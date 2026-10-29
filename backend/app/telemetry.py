"""Signed telemetry ingestion and provenance-aware fraud signals.

Requires an authenticated service principal AND independent pinned Ed25519
source signature. No web scraping, IP profiling or user-provided telemetry
is accepted as an authoritative signal.
"""
import base64
import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field, field_validator


class TelemetryEvent(BaseModel):
    event_id: UUID
    subject_id: str = Field(min_length=1, max_length=128)
    event_type: Literal["login_failed", "beneficiary_added", "device_seen", "transfer_submitted"]
    occurred_at: datetime
    device_id: str | None = Field(default=None, min_length=1, max_length=128)
    beneficiary_id: str | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("occurred_at")
    @classmethod
    def must_be_aware(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Telemetry timestamp must contain an explicit UTC offset")
        return value


class TelemetryEnvelope(BaseModel):
    source_id: str = Field(min_length=1, max_length=80)
    event: TelemetryEvent
    signature_b64: str = Field(min_length=20, max_length=256)


def canonical_message(event):
    encoded = json.dumps(event.model_dump(mode="json"),
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
    return b"AEGIS-TELEMETRY-V1\n" + encoded


def ref(tenant, identifier):
    return hashlib.sha256((tenant + ":" + identifier).encode()).hexdigest()[:20]


def source_config():
    try:
        raw = json.loads(os.getenv("AEGIS_TELEMETRY_SIGNERS", "{}"))
        return raw if isinstance(raw, dict) else {}
    except (ValueError, TypeError):
        return {}


def init_telemetry_db(c):
    c.executescript("""
       CREATE TABLE IF NOT EXISTS telemetry_events (
         tenant TEXT NOT NULL, event_id TEXT NOT NULL,
         subject_ref TEXT NOT NULL, event_type TEXT NOT NULL,
         occurred_at TEXT NOT NULL, source_id TEXT NOT NULL,
         device_ref TEXT, beneficiary_ref TEXT, signature_hash TEXT NOT NULL,
         PRIMARY KEY(tenant,event_id)
       );
       CREATE INDEX IF NOT EXISTS telemetry_account_window
         ON telemetry_events(tenant,subject_ref,event_type,occurred_at);
    """)


def trusted_features(c, tenant, subject_id, beneficiary_id="", device_id=None):
    subject = ref(tenant, subject_id)
    hour = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    week = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    counts = {r["event_type"]: r["n"] for r in c.execute(
        """SELECT event_type,COUNT(*) as n FROM telemetry_events
           WHERE tenant=? AND subject_ref=? AND occurred_at>=? GROUP BY event_type""",
        (tenant, subject, hour)
    ).fetchall()}
    failed = counts.get("login_failed", 0)
    transfers = counts.get("transfer_submitted", 0)
    reason_codes = []
    extra_risk = 0
    if failed >= 2:
        extra_risk += min(32, failed * 8)
        reason_codes.append("SIGNED_FAILED_AUTH_BURST")
    if transfers >= 3:
        extra_risk += min(24, transfers * 5)
        reason_codes.append("SIGNED_TRANSFER_VELOCITY")
    if beneficiary_id:
        beneficiary = ref(tenant, beneficiary_id)
        hit = c.execute(
            """SELECT 1 FROM telemetry_events WHERE tenant=? AND subject_ref=?
               AND event_type='beneficiary_added' AND beneficiary_ref=?
               AND occurred_at>=? LIMIT 1""",
            (tenant, subject, beneficiary, week)
        ).fetchone()
        if hit:
            extra_risk += 18
            reason_codes.append("SIGNED_RECENT_BENEFICIARY")
    if device_id:
        current = ref(tenant, device_id)
        any_devices = c.execute(
            """SELECT 1 FROM telemetry_events WHERE tenant=? AND subject_ref=?
               AND event_type='device_seen' LIMIT 1""",
            (tenant, subject)
        ).fetchone()
        matched = c.execute(
            """SELECT 1 FROM telemetry_events WHERE tenant=? AND subject_ref=?
               AND event_type='device_seen' AND device_ref=? LIMIT 1""",
            (tenant, subject, current)
        ).fetchone()
        if any_devices and not matched:
            extra_risk += 15
            reason_codes.append("SIGNED_DEVICE_CHANGE")
    return extra_risk, reason_codes, {
        "trusted_events_1h": counts,
        "beneficiary_reference_present": bool(beneficiary_id),
        "device_reference_present": bool(device_id),
        "signature_verified_source": True if reason_codes else False,
    }


def register_telemetry_routes(app, database, principal, now):
    @app.post("/v1/telemetry/events", status_code=201)
    def ingest(item: TelemetryEnvelope, p=Depends(principal)):
        if p["role"] != "service":
            raise HTTPException(403, "Authenticated service principal required")
        source = source_config().get(item.source_id)
        if not isinstance(source, dict) or source.get("tenant") != p["tenant"]:
            raise HTTPException(403, "Source not registered to authenticated tenant")
        raw_public = source.get("ed25519_public_key_b64")
        if not isinstance(raw_public, str):
            raise HTTPException(503, "Trusted event source key not configured")
        event = item.event
        instant = datetime.now(timezone.utc)
        if abs((instant - event.occurred_at.astimezone(timezone.utc)).total_seconds()) > 300:
            raise HTTPException(422, "Telemetry event timestamp outside accepted 5-minute window")
        try:
            public_key = base64.b64decode(raw_public, validate=True)
            signature = base64.b64decode(item.signature_b64, validate=True)
            if len(public_key) != 32 or len(signature) != 64:
                raise ValueError("Unexpected signing key or signature size")
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, canonical_message(event)
            )
        except (InvalidSignature, ValueError, TypeError):
            raise HTTPException(403, "Invalid trusted-source signature")
        with database() as c:
            try:
                c.execute(
                    """INSERT INTO telemetry_events VALUES(?,?,?,?,?,?,?,?,?)""",
                    (p["tenant"], str(event.event_id), ref(p["tenant"], event.subject_id),
                     event.event_type, event.occurred_at.astimezone(timezone.utc).isoformat(),
                     item.source_id,
                     ref(p["tenant"], event.device_id) if event.device_id else None,
                     ref(p["tenant"], event.beneficiary_id) if event.beneficiary_id else None,
                     hashlib.sha256(signature).hexdigest())
                )
            except sqlite3.IntegrityError:
                raise HTTPException(409, "Duplicate signed telemetry event")
        return {"accepted": True, "event_id": str(event.event_id), "source_id": item.source_id,
                "provenance": "verified Ed25519 signature", "tenant": p["tenant"]}
