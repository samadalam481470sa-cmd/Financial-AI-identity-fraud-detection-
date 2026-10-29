import base64
import os
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("AEGIS_API_KEYS", '{"admin":{"tenant":"t1","role":"admin"},"analyst":{"tenant":"t1","role":"analyst"},"other":{"tenant":"t2","role":"admin"}}')
    from app.main import app, init_db
    init_db()
    return TestClient(app)

def headers(key="admin"):
    return {"X-API-Key": key}

def evaluate(client, **kwargs):
    data = {"request_id": str(uuid.uuid4()), "subject_id": "alice", "action": "transfer", "amount_minor": 1500000}
    data.update(kwargs)
    return client.post("/v1/evaluate", json=data, headers=headers())

def test_health(client):
    assert client.get("/health").status_code == 200

def test_auth_required(client):
    assert client.get("/v1/events").status_code == 401
    assert client.post("/v1/evaluate", json={}).status_code == 401

def test_unsigned_transfer_held(client):
    r = evaluate(client)
    assert r.status_code == 200
    assert r.json()["decision"] == "hold"
    assert "SIGNED_ACTION_REQUIRED" in r.json()["reason_codes"]
    assert len(client.get("/v1/cases", headers=headers()).json()["cases"]) == 1

def test_login_low_risk(client):
    r = client.post("/v1/evaluate", headers=headers(), json={
        "request_id": str(uuid.uuid4()), "subject_id": "alice", "action": "login", "known_device": True
    })
    assert r.json()["decision"] == "challenge"
    assert "SIGNED_ACTION_REQUIRED" in r.json()["reason_codes"]

def test_signature_and_replay(client):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    assert client.post("/v1/credentials", headers=headers(), json={
        "subject_id": "alice", "credential_id": "device1",
        "ed25519_public_key_b64": base64.b64encode(public).decode()
    }).status_code == 200
    intent = {"subject_id": "alice", "action": "transfer", "amount_minor": 2000, "currency": "USD", "beneficiary_id": "bob"}
    challenge = client.post("/v1/challenges", headers=headers(), json=intent).json()
    signature = base64.b64encode(private.sign(challenge["message_to_sign"].encode())).decode()
    request = dict(intent, request_id=str(uuid.uuid4()), credential_id="device1",
                   challenge_id=challenge["challenge_id"], signature_b64=signature, known_device=True)
    success = client.post("/v1/evaluate", headers=headers(), json=request)
    assert success.status_code == 200
    assert success.json()["decision"] == "allow"
    assert success.json()["evidence"]["signature_verified"]
    same = client.post("/v1/evaluate", headers=headers(), json=request)
    assert same.json()["id"] == success.json()["id"]
    request["request_id"] = str(uuid.uuid4())
    replay = client.post("/v1/evaluate", headers=headers(), json=request)
    assert replay.json()["decision"] == "hold"
    request["amount_minor"] = 8000
    tamper = client.post("/v1/evaluate", headers=headers(), json=request)
    assert tamper.json()["decision"] == "hold"

def test_idempotency_conflict(client):
    data = {"request_id": "same-request-123", "subject_id": "alice", "action": "login"}
    assert client.post("/v1/evaluate", headers=headers(), json=data).status_code == 200
    data["subject_id"] = "bob"
    assert client.post("/v1/evaluate", headers=headers(), json=data).status_code == 409

def test_tenant_isolation(client):
    evaluate(client)
    assert len(client.get("/v1/events", headers=headers("other")).json()["events"]) == 0
    assert client.get("/v1/events", headers=headers("analyst")).status_code == 200
    assert client.post("/v1/credentials", headers=headers("analyst"), json={}).status_code == 403
