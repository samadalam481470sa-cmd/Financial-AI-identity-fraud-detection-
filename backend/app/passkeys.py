"""WebAuthn relying-party routes for the AEGIS engineering environment.

Real browser WebAuthn ceremonies are verified server-side: RP ID, origin,
challenge, authenticator signature and UV flag. Identity proofing is
separate. The sandbox proofing grant is not legal/issuer-backed verification.
"""
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

def utcnow():
    return datetime.now(timezone.utc)

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def rp_settings():
    rp_id = os.getenv("AEGIS_RP_ID", "localhost")
    origin = os.getenv("AEGIS_ORIGIN", "http://localhost:8080")
    if not rp_id or "/" in rp_id or ":" in rp_id:
        raise RuntimeError("AEGIS_RP_ID must be a host name without scheme or path")
    if not (origin.startswith("https://") or
            (rp_id == "localhost" and origin.startswith("http://localhost:"))):
        raise RuntimeError("WebAuthn requires HTTPS, except loopback localhost development")
    if os.getenv("AEGIS_MODE", "development") != "development" and not origin.startswith("https://"):
        raise RuntimeError("WebAuthn staging origin requires HTTPS")
    return rp_id, origin

def init_passkey_db(c):
    c.executescript("""
        CREATE TABLE IF NOT EXISTS proofing_grants (
            tenant TEXT NOT NULL, subject TEXT NOT NULL, reference TEXT NOT NULL,
            grant_type TEXT NOT NULL, granted_at TEXT NOT NULL,
            PRIMARY KEY(tenant, subject)
        );
        CREATE TABLE IF NOT EXISTS passkey_credentials (
            tenant TEXT NOT NULL, subject TEXT NOT NULL,
            credential_id TEXT NOT NULL, public_key TEXT NOT NULL,
            sign_count INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL, backup_state INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(tenant, credential_id)
        );
        CREATE INDEX IF NOT EXISTS passkey_subject_idx
          ON passkey_credentials(tenant, subject, revoked);
        CREATE TABLE IF NOT EXISTS passkey_challenges (
            id TEXT PRIMARY KEY, tenant TEXT NOT NULL, subject TEXT NOT NULL,
            kind TEXT NOT NULL, challenge_b64 TEXT NOT NULL,
            intent_hash TEXT NOT NULL, expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );
    """)

class SyntheticProofing(BaseModel):
    subject_id: str = Field(min_length=1, max_length=128)
    reference: str = Field(min_length=8, max_length=128)

class SubjectRequest(BaseModel):
    subject_id: str = Field(min_length=1, max_length=128)

class BrowserResponse(BaseModel):
    subject_id: str = Field(min_length=1, max_length=128)
    challenge_id: str = Field(min_length=8, max_length=128)
    credential: dict

class PasskeyIntent(SubjectRequest):
    action: str
    amount_minor: int = Field(default=0, ge=0, le=10**12)
    currency: str = Field(default="USD", pattern="^[A-Z]{3}$")
    beneficiary_id: str = Field(default="", max_length=128)

def credential_id_from_response(payload):
    cid = payload.get("id")
    if not isinstance(cid, str) or not 8 <= len(cid) <= 1024:
        raise HTTPException(422, "Invalid WebAuthn credential identifier")
    try:
        decoded = base64url_to_bytes(cid)
        if not decoded:
            raise ValueError("empty")
        return b64url(decoded)
    except Exception:
        raise HTTPException(422, "Malformed WebAuthn credential identifier")

def verify_passkey_assertion(c, item, tenant, digest):
    """Verify bound browser assertion atomically during evaluation transaction.

    False means mandatory passkey proof was missing/invalid. Calling code MUST
    fail closed instead of accepting untrusted risk data.
    """
    payload = getattr(item, "passkey_credential", None)
    challenge_id = getattr(item, "passkey_challenge_id", None)
    if not isinstance(payload, dict) or not challenge_id:
        return False
    try:
        credential_id = credential_id_from_response(payload)
    except HTTPException:
        return False
    stored = c.execute(
        "SELECT * FROM passkey_credentials WHERE tenant=? AND subject=? AND credential_id=? AND revoked=0",
        (tenant, item.subject_id, credential_id)
    ).fetchone()
    challenge = c.execute(
        "SELECT * FROM passkey_challenges WHERE id=? AND tenant=? AND subject=? AND kind='authentication'",
        (challenge_id, tenant, item.subject_id)
    ).fetchone()
    if not stored or not challenge or challenge["used"]:
        return False
    if datetime.fromisoformat(challenge["expires_at"]) <= utcnow():
        return False
    # Make assertions transaction specific; a passkey signature on a login
    # cannot authorize a transfer or a different beneficiary/amount.
    canonical_intent = {
        "subject_id": item.subject_id, "action": item.action, "amount_minor": item.amount_minor,
        "currency": item.currency, "beneficiary_id": item.beneficiary_id,
    }
    if challenge["intent_hash"] != digest(canonical_intent):
        return False
    rp_id, origin = rp_settings()
    try:
        result = verify_authentication_response(
            credential=payload,
            expected_challenge=base64url_to_bytes(challenge["challenge_b64"]),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(stored["public_key"]),
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=True,
        )
    except (WebAuthnException, ValueError, TypeError, KeyError):
        return False
    if not result.user_verified:
        return False
    consumed = c.execute(
        "UPDATE passkey_challenges SET used=1 WHERE id=? AND used=0",
        (challenge_id,)
    )
    if not consumed.rowcount:
        return False
    c.execute(
        "UPDATE passkey_credentials SET sign_count=?, backup_state=? WHERE tenant=? AND credential_id=?",
        (result.new_sign_count, int(result.credential_backed_up), tenant, credential_id)
    )
    return True

def register_passkey_routes(app, database, principal, require_admin, digest, now):
    @app.post("/v1/passkeys/sandbox-proofing")
    def mark_synthetic_proofing(item: SyntheticProofing, p=Depends(require_admin)):
        if os.getenv("AEGIS_MODE", "development") != "development":
            raise HTTPException(403, "Sandbox identity proofing cannot authorize staging or production")
        with database() as c:
            c.execute(
                """INSERT INTO proofing_grants(tenant,subject,reference,grant_type,granted_at)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(tenant,subject) DO UPDATE SET reference=excluded.reference,
                   grant_type=excluded.grant_type,granted_at=excluded.granted_at""",
                (p["tenant"], item.subject_id, item.reference, "synthetic-only", now())
            )
        return {"subject_id": item.subject_id, "assurance": "synthetic-only",
                "verified_real_identity": False}

    @app.post("/v1/passkeys/registration/options")
    def registration_options(item: SubjectRequest, p=Depends(require_admin)):
        if os.getenv("AEGIS_MODE", "development") != "development":
            raise HTTPException(403, "Real issuer-backed enrollment provider not configured")
        rp_id, _ = rp_settings()
        with database() as c:
            grant = c.execute(
                "SELECT reference FROM proofing_grants WHERE tenant=? AND subject=? AND grant_type='synthetic-only'",
                (p["tenant"], item.subject_id)
            ).fetchone()
            if not grant:
                raise HTTPException(403, "Synthetic identity enrollment grant required")
            existing = c.execute(
                "SELECT credential_id FROM passkey_credentials WHERE tenant=? AND subject=? AND revoked=0",
                (p["tenant"], item.subject_id)
            ).fetchall()
            challenge = secrets.token_bytes(32)
            challenge_id = str(uuid.uuid4())
            expires_at = (utcnow() + timedelta(minutes=3)).isoformat()
            opts = generate_registration_options(
                rp_id=rp_id, rp_name="AEGIS IDENTITY",
                user_name=item.subject_id,
                user_id=hashlib.sha256((p["tenant"] + ":" + item.subject_id).encode()).digest(),
                challenge=challenge,
                exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(x["credential_id"])) for x in existing],
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.PREFERRED,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
            )
            c.execute(
                "INSERT INTO passkey_challenges VALUES(?,?,?,?,?,?,?,0)",
                (challenge_id, p["tenant"], item.subject_id, "registration",
                 b64url(challenge), "", expires_at)
            )
        return {"challenge_id": challenge_id, "publicKey": json.loads(options_to_json(opts)),
                "expires_at": expires_at, "proofing_level": "synthetic-only"}

    @app.post("/v1/passkeys/registration/verify")
    def registration_verify(item: BrowserResponse, p=Depends(require_admin)):
        if os.getenv("AEGIS_MODE", "development") != "development":
            raise HTTPException(403, "Real issuer-backed enrollment provider not configured")
        rp_id, origin = rp_settings()
        with database() as c:
            c.execute("BEGIN IMMEDIATE")
            stored = c.execute(
                "SELECT * FROM passkey_challenges WHERE id=? AND tenant=? AND subject=? AND kind='registration'",
                (item.challenge_id, p["tenant"], item.subject_id)
            ).fetchone()
            if not stored or stored["used"] or datetime.fromisoformat(stored["expires_at"]) <= utcnow():
                raise HTTPException(403, "Registration challenge invalid or expired")
            grant = c.execute(
                "SELECT 1 FROM proofing_grants WHERE tenant=? AND subject=? AND grant_type='synthetic-only'",
                (p["tenant"], item.subject_id)
            ).fetchone()
            if not grant:
                raise HTTPException(403, "Enrollment proofing grant missing")
            try:
                result = verify_registration_response(
                    credential=item.credential,
                    expected_challenge=base64url_to_bytes(stored["challenge_b64"]),
                    expected_rp_id=rp_id,
                    expected_origin=origin,
                    require_user_verification=True,
                )
            except (WebAuthnException, ValueError, TypeError, KeyError):
                raise HTTPException(403, "WebAuthn registration verification failed")
            credential_id = b64url(result.credential_id)
            c.execute("UPDATE passkey_challenges SET used=1 WHERE id=? AND used=0", (item.challenge_id,))
            try:
                c.execute(
                    "INSERT INTO passkey_credentials VALUES(?,?,?,?,?,0,?,?)",
                    (p["tenant"], item.subject_id, credential_id,
                     b64url(result.credential_public_key), result.sign_count,
                     now(), int(result.credential_backed_up))
                )
            except sqlite3.IntegrityError:
                raise HTTPException(409, "Authenticator already registered")
            c.execute("COMMIT")
        return {"registered": True, "credential_id": credential_id,
                "user_verified": True, "identity_proofing": "synthetic-only"}

    @app.post("/v1/passkeys/authentication/options")
    def authentication_options(item: PasskeyIntent, p=Depends(principal)):
        if p["role"] not in ("admin", "service"):
            raise HTTPException(403, "Service or sandbox administrator role required")
        rp_id, _ = rp_settings()
        with database() as c:
            entries = c.execute(
                "SELECT credential_id FROM passkey_credentials WHERE tenant=? AND subject=? AND revoked=0",
                (p["tenant"], item.subject_id)
            ).fetchall()
            if not entries:
                raise HTTPException(404, "No registered passkeys for this account")
            challenge_bytes = secrets.token_bytes(32)
            challenge_id = str(uuid.uuid4())
            expires_at = (utcnow() + timedelta(minutes=3)).isoformat()
            options = generate_authentication_options(
                rp_id=rp_id,
                challenge=challenge_bytes,
                user_verification=UserVerificationRequirement.REQUIRED,
                allow_credentials=[
                    PublicKeyCredentialDescriptor(id=base64url_to_bytes(e["credential_id"]))
                    for e in entries
                ],
            )
            c.execute(
                "INSERT INTO passkey_challenges VALUES(?,?,?,?,?,?,?,0)",
                (challenge_id, p["tenant"], item.subject_id, "authentication",
                 b64url(challenge_bytes), digest(item.model_dump()), expires_at)
            )
        return {"challenge_id": challenge_id, "publicKey": json.loads(options_to_json(options)),
                "expires_at": expires_at}

    @app.delete("/v1/passkeys/{credential_id}")
    def revoke_passkey(credential_id: str, p=Depends(require_admin)):
        with database() as c:
            result = c.execute(
                "UPDATE passkey_credentials SET revoked=1 WHERE tenant=? AND credential_id=?",
                (p["tenant"], credential_id)
            )
        if result.rowcount == 0:
            raise HTTPException(404, "Passkey not found")
        return {"revoked": True}
