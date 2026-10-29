"""AEGIS IDENTITY: authenticated, tenant-isolated identity continuity prototype.
Use only synthetic data. Integrate production identity provider, HSM and WebAuthn before deployment.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="AEGIS IDENTITY", version="0.3.0")
LOCK = threading.RLock()
DB_PATH = os.getenv("AEGIS_DB_PATH", "aegis.db")
MODEL_VERSION = "baseline-rules-3"
POLICY_VERSION = "continuity-policy-3"

def now():
    return datetime.now(timezone.utc).isoformat()

@contextmanager
def database():
    with LOCK:
        connection = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA foreign_keys=ON")
            yield connection
        finally:
            connection.close()

def init_db():
    with database() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS keys (
            tenant TEXT NOT NULL, subject TEXT NOT NULL, credential_id TEXT NOT NULL,
            public_key TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL, PRIMARY KEY (tenant, credential_id)
        );
        CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY, tenant TEXT NOT NULL, subject TEXT NOT NULL,
            intent_digest TEXT NOT NULL, expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS decisions (
            id TEXT PRIMARY KEY, tenant TEXT NOT NULL, subject_ref TEXT NOT NULL,
            action TEXT NOT NULL, decision TEXT NOT NULL, score INTEGER NOT NULL,
            reasons TEXT NOT NULL, policy_version TEXT NOT NULL, model_version TEXT NOT NULL,
            occurred_at TEXT NOT NULL, evidence TEXT NOT NULL, prev_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS decisions_tenant_idx ON decisions(tenant, occurred_at);
        CREATE TABLE IF NOT EXISTS requests (
            tenant TEXT NOT NULL, request_id TEXT NOT NULL, request_hash TEXT NOT NULL,
            decision_id TEXT NOT NULL, PRIMARY KEY (tenant, request_id)
        );
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY, tenant TEXT NOT NULL, decision_id TEXT NOT NULL,
            status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            analyst_note TEXT NOT NULL DEFAULT ''
        );
        """)

@app.on_event("startup")
def on_startup():
    init_db()

def principals():
    # Format: {"demo-admin":{"tenant":"demo","role":"admin"},...}
    # Never put secrets in source control; use an identity provider outside prototype.
    raw = os.environ.get("AEGIS_API_KEYS", "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}

def principal(x_api_key: str | None = Header(default=None)):
    if not x_api_key:
        raise HTTPException(401, "API key required")
    for key, entry in principals().items():
        if hmac.compare_digest(x_api_key, key) and isinstance(entry, dict):
            if entry.get("tenant") and entry.get("role") in ("admin", "analyst", "service"):
                return entry
    raise HTTPException(401, "Invalid API key")

def require_admin(p=Depends(principal)):
    if p["role"] != "admin":
        raise HTTPException(403, "Administrator role required")
    return p

def require_analyst(p=Depends(principal)):
    if p["role"] not in ("admin", "analyst"):
        raise HTTPException(403, "Analyst role required")
    return p

def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def b64_decode(value):
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        raise HTTPException(422, "Invalid base64")

class Register(BaseModel):
    subject_id: str = Field(min_length=1, max_length=128)
    credential_id: str = Field(min_length=1, max_length=128)
    ed25519_public_key_b64: str

@app.post("/v1/credentials")
def register(item: Register, p=Depends(require_admin)):
    key = b64_decode(item.ed25519_public_key_b64)
    if len(key) != 32:
        raise HTTPException(422, "Expected Ed25519 public key (32 bytes)")
    try:
        Ed25519PublicKey.from_public_bytes(key)
    except ValueError:
        raise HTTPException(422, "Invalid public key")
    with database() as c:
        try:
            c.execute("INSERT INTO keys VALUES(?,?,?,?,0,?)",
                      (p["tenant"], item.subject_id, item.credential_id, item.ed25519_public_key_b64, now()))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Credential already registered")
    return {"credential_id": item.credential_id, "registered": True}

@app.delete("/v1/credentials/{credential_id}")
def revoke(credential_id: str, p=Depends(require_admin)):
    with database() as c:
        cur = c.execute("UPDATE keys SET revoked=1 WHERE tenant=? AND credential_id=?",
                        (p["tenant"], credential_id))
    if not cur.rowcount:
        raise HTTPException(404, "Credential not found")
    return {"revoked": True}

class Intent(BaseModel):
    subject_id: str = Field(min_length=1, max_length=128)
    action: Literal["login", "transfer", "profile_change", "recovery", "enrollment"]
    amount_minor: int = Field(default=0, ge=0, le=10**12)
    currency: str = Field(default="USD", pattern="^[A-Z]{3}$")
    beneficiary_id: str = Field(default="", max_length=128)

def intent_payload(i: Intent):
    return i.model_dump()

@app.post("/v1/challenges")
def challenge(i: Intent, p=Depends(principal)):
    nonce = str(uuid.uuid4())
    expires = (datetime.now(timezone.utc) + timedelta(minutes=3)).isoformat()
    tenant = p["tenant"]
    message = digest({"challenge_id": nonce, "tenant": tenant, "intent": intent_payload(i)})
    with database() as c:
        c.execute("INSERT INTO challenges VALUES(?,?,?,?,?,0)",
                  (nonce, tenant, i.subject_id, message, expires))
    return {"challenge_id": nonce, "message_to_sign": message, "expires_at": expires,
            "algorithm": "Ed25519", "encoding": "utf-8"}

class Evaluation(Intent):
    request_id: str = Field(min_length=8, max_length=128)
    credential_id: str | None = None
    challenge_id: str | None = None
    signature_b64: str | None = None
    new_device: bool = False
    known_device: bool = False
    recent_failed_attempts: int = Field(default=0, ge=0, le=10000)
    velocity_1h: int = Field(default=0, ge=0, le=10000)
    newly_added_beneficiary: bool = False

def verify_signature(c, item, tenant):
    if not all([item.credential_id, item.challenge_id, item.signature_b64]):
        return False
    row = c.execute("SELECT public_key FROM keys WHERE tenant=? AND subject=? AND credential_id=? AND revoked=0",
                    (tenant, item.subject_id, item.credential_id)).fetchone()
    ch = c.execute("SELECT * FROM challenges WHERE id=? AND tenant=? AND subject=?",
                   (item.challenge_id, tenant, item.subject_id)).fetchone()
    if not row or not ch or ch["used"] or datetime.fromisoformat(ch["expires_at"]) <= datetime.now(timezone.utc):
        return False
    expected = digest({"challenge_id": item.challenge_id, "tenant": tenant,
                       "intent": intent_payload(Intent(**item.model_dump()))})
    if not hmac.compare_digest(ch["intent_digest"], expected):
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(b64_decode(row["public_key"]))
        key.verify(b64_decode(item.signature_b64), expected.encode())
    except (InvalidSignature, ValueError, HTTPException):
        return False
    # Atomic nonce consumption; rejecting replay. Transaction protected by DB lock.
    consumed = c.execute("UPDATE challenges SET used=1 WHERE id=? AND used=0", (item.challenge_id,))
    return consumed.rowcount == 1

def score(item):
    signals = [
        (item.new_device, 24, "NEW_DEVICE"),
        (not item.known_device, 10, "UNRECOGNIZED_DEVICE"),
        (item.amount_minor >= 1_000_000, 22, "HIGH_VALUE"),
        (item.newly_added_beneficiary, 18, "NEW_BENEFICIARY"),
        (item.recent_failed_attempts > 0, min(item.recent_failed_attempts * 5, 20), "FAILED_AUTH"),
        (item.velocity_1h >= 3, min(item.velocity_1h * 4, 24), "HIGH_VELOCITY"),
    ]
    reasons = [code for enabled, _, code in signals if enabled]
    return min(100, sum(weight for enabled, weight, _ in signals if enabled)), reasons

@app.post("/v1/evaluate")
def evaluate(item: Evaluation, p=Depends(principal)):
    tenant = p["tenant"]
    incoming = item.model_dump()
    input_hash = digest(incoming)
    with database() as c:
        c.execute("BEGIN IMMEDIATE")
        existing = c.execute("SELECT request_hash,decision_id FROM requests WHERE tenant=? AND request_id=?",
                             (tenant, item.request_id)).fetchone()
        if existing:
            if existing["request_hash"] != input_hash:
                c.execute("ROLLBACK")
                raise HTTPException(409, "Idempotency key reused for different request")
            record = c.execute("SELECT * FROM decisions WHERE id=? AND tenant=?",
                               (existing["decision_id"], tenant)).fetchone()
            c.execute("COMMIT")
            return format_decision(record)
        signed = verify_signature(c, item, tenant)
        risk, reasons = score(item)
        sensitive = item.action in ("transfer", "profile_change", "recovery")
        if sensitive and not signed:
            decision = "hold"
            reasons.append("SIGNED_ACTION_REQUIRED")
        elif item.action == "enrollment":
            decision = "challenge"
            reasons.append("IDENTITY_PROOFING_REQUIRED")
        elif risk >= 75:
            decision = "hold"
        elif risk >= 40:
            decision = "challenge"
        else:
            decision = "allow"
        event_id = str(uuid.uuid4())
        date = now()
        subject_ref = hashlib.sha256((tenant + ":" + item.subject_id).encode()).hexdigest()[:20]
        previous = c.execute("SELECT event_hash FROM decisions WHERE tenant=? ORDER BY rowid DESC LIMIT 1",
                             (tenant,)).fetchone()
        previous_hash = previous["event_hash"] if previous else "GENESIS"
        evidence = {"signature_verified": signed, "credential_id": item.credential_id if signed else None,
                    "intent_digest": digest(intent_payload(Intent(**incoming))),
                    "risk_signals": reasons}
        canonical = {"id": event_id, "tenant": tenant, "subject_ref": subject_ref,
                     "decision": decision, "risk": risk, "timestamp": date, "evidence": evidence}
        event_hash = digest({"previous_hash": previous_hash, "record": canonical})
        c.execute("INSERT INTO decisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (event_id, tenant, subject_ref, item.action, decision, risk, json.dumps(reasons),
                   POLICY_VERSION, MODEL_VERSION, date, json.dumps(evidence), previous_hash, event_hash))
        c.execute("INSERT INTO requests VALUES(?,?,?,?)", (tenant, item.request_id, input_hash, event_id))
        if decision in ("hold", "challenge"):
            c.execute("INSERT INTO cases VALUES(?,?,?,?,?,?,?)",
                      (str(uuid.uuid4()), tenant, event_id, "open", date, date, ""))
        c.execute("COMMIT")
        record = c.execute("SELECT * FROM decisions WHERE id=?", (event_id,)).fetchone()
    return format_decision(record)

def format_decision(r):
    return {"id": r["id"], "timestamp": r["occurred_at"], "subject_ref": r["subject_ref"],
            "action": r["action"], "decision": r["decision"], "risk_score": r["score"],
            "reason_codes": json.loads(r["reasons"]), "policy_version": r["policy_version"],
            "model_version": r["model_version"], "evidence": json.loads(r["evidence"]),
            "event_hash": r["event_hash"], "prev_hash": r["prev_hash"]}

@app.get("/health")
def health():
    return {"status": "ok", "service": "aegis-identity", "version": "0.3.0"}

@app.get("/v1/events")
def events(limit: int = 50, p=Depends(require_analyst)):
    limit = max(1, min(limit, 100))
    with database() as c:
        rows = c.execute("SELECT * FROM decisions WHERE tenant=? ORDER BY rowid DESC LIMIT ?",
                         (p["tenant"], limit)).fetchall()
    return {"events": [format_decision(row) for row in rows]}

@app.get("/v1/cases")
def cases(p=Depends(require_analyst)):
    with database() as c:
        rows = c.execute("SELECT * FROM cases WHERE tenant=? ORDER BY created_at DESC LIMIT 100",
                         (p["tenant"],)).fetchall()
    return {"cases": [dict(row) for row in rows]}

class CaseUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved", "escalated"]
    analyst_note: str = Field(default="", max_length=2000)

@app.patch("/v1/cases/{case_id}")
def update_case(case_id: str, item: CaseUpdate, p=Depends(require_analyst)):
    with database() as c:
        cur = c.execute("UPDATE cases SET status=?, analyst_note=?, updated_at=? WHERE id=? AND tenant=?",
                        (item.status, item.analyst_note, now(), case_id, p["tenant"]))
    if not cur.rowcount:
        raise HTTPException(404, "Case not found")
    return {"updated": True, "case_id": case_id, "status": item.status}
