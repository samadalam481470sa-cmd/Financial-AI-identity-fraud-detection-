"""Source-authenticated fraud telemetry: signature, tenancy, replay, and risk provenance."""
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.main import app, init_db
from app.telemetry import TelemetryEvent, canonical_message


@pytest.fixture
def environment(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    monkeypatch.setenv("AEGIS_DB_PATH", str(tmp_path / "telemetry.sqlite"))
    monkeypatch.setenv("AEGIS_MODE", "development")
    monkeypatch.setenv("AEGIS_API_KEYS", json.dumps({
        "service": {"tenant": "alpha", "role": "service"},
        "admin": {"tenant": "alpha", "role": "admin"},
        "other": {"tenant": "beta", "role": "service"},
    }))
    monkeypatch.setenv("AEGIS_TELEMETRY_SIGNERS", json.dumps({
        "issuer-01": {
            "tenant": "alpha",
            "ed25519_public_key_b64": base64.b64encode(public).decode()
        }
    }))
    init_db()
    return TestClient(app), key


def envelope(key, **kwargs):
    event = TelemetryEvent(
        event_id=kwargs.pop("event_id", uuid.uuid4()),
        subject_id=kwargs.pop("subject_id", "alice"),
        event_type=kwargs.pop("event_type", "login_failed"),
        occurred_at=kwargs.pop("occurred_at", datetime.now(timezone.utc)),
        **kwargs,
    )
    signature = base64.b64encode(key.sign(canonical_message(event))).decode()
    return {"source_id": "issuer-01", "event": event.model_dump(mode="json"),
            "signature_b64": signature}


def emit(client, key, **kwargs):
    return client.post("/v1/telemetry/events", headers={"X-API-Key": "service"},
                       json=envelope(key, **kwargs))


def test_signed_source_and_replay(environment):
    client, key = environment
    original = envelope(key, event_type="beneficiary_added", beneficiary_id="new-payee")
    accepted = client.post("/v1/telemetry/events",
                           headers={"X-API-Key": "service"}, json=original)
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["provenance"] == "verified Ed25519 signature"
    assert client.post("/v1/telemetry/events",
                       headers={"X-API-Key": "service"}, json=original).status_code == 409
    altered = json.loads(json.dumps(original))
    altered["event"]["beneficiary_id"] = "different-payee"
    assert client.post("/v1/telemetry/events",
                       headers={"X-API-Key": "service"}, json=altered).status_code == 403


def test_cross_tenant_and_unprivileged_source_blocked(environment):
    client, key = environment
    data = envelope(key)
    assert client.post("/v1/telemetry/events",
                       headers={"X-API-Key": "other"}, json=data).status_code == 403
    assert client.post("/v1/telemetry/events",
                       headers={"X-API-Key": "admin"}, json=data).status_code == 403
    assert client.post("/v1/telemetry/events", json=data).status_code == 401


def test_expiry_is_enforced(environment):
    client, key = environment
    old_event = envelope(key, occurred_at=datetime.now(timezone.utc) - timedelta(minutes=10))
    assert client.post("/v1/telemetry/events",
                       headers={"X-API-Key": "service"}, json=old_event).status_code == 422


def test_server_derived_events_affect_fraud_risk(environment):
    client, key = environment
    for _ in range(3):
        assert emit(client, key).status_code == 201
    assert emit(client, key, event_type="beneficiary_added", beneficiary_id="bob").status_code == 201
    decision = client.post("/v1/evaluate", headers={"X-API-Key": "service"}, json={
        "request_id": str(uuid.uuid4()), "subject_id": "alice", "action": "transfer",
        "amount_minor": 2000, "beneficiary_id": "bob", "known_device": True
    })
    assert decision.status_code == 200, decision.text
    event = decision.json()
    assert "SIGNED_FAILED_AUTH_BURST" in event["reason_codes"]
    assert "SIGNED_RECENT_BENEFICIARY" in event["reason_codes"]
    assert event["risk_score"] >= 42
    assert event["evidence"]["verified_telemetry"]["trusted_events_1h"]["login_failed"] == 3
    assert event["decision"] == "hold"  # cryptographic authorization still required


def test_device_change_from_signed_history(environment):
    client, key = environment
    assert emit(client, key, event_type="device_seen", device_id="familiar-device").status_code == 201
    response = client.post("/v1/evaluate", headers={"X-API-Key": "service"}, json={
        "request_id": str(uuid.uuid4()), "subject_id": "alice", "action": "login",
        "device_id": "brand-new-device", "known_device": True
    })
    assert response.status_code == 200
    assert "SIGNED_DEVICE_CHANGE" in response.json()["reason_codes"]
