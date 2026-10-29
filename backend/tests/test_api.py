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
    request["request_id"] = str(uuid.uuid4())
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

def test_server_measured_velocity_and_metrics(client):
    for _ in range(4):
        response = client.post("/v1/evaluate", headers=headers(), json={
            "request_id": str(uuid.uuid4()), "subject_id": "velocity-user", "action": "login",
            "known_device": True, "velocity_1h": 0
        })
        assert response.status_code == 200
    last = client.post("/v1/evaluate", headers=headers(), json={
        "request_id": str(uuid.uuid4()), "subject_id": "velocity-user", "action": "login",
        "known_device": True, "velocity_1h": 0
    })
    assert "SERVER_OBSERVED_VELOCITY" in last.json()["reason_codes"]
    assert last.json()["evidence"]["server_observed_events_1h"] == 4
    metrics = client.get("/v1/metrics", headers=headers())
    assert metrics.status_code == 200
    assert metrics.json()["counts"]["challenge"] >= 5
    assert client.get("/v1/metrics").status_code == 401

def test_audit_chain_detects_tampering(client):
    evaluate(client)
    evaluate(client, amount_minor=100)
    verified = client.get("/v1/audit/verify", headers=headers())
    assert verified.status_code == 200
    assert verified.json()["valid"]
    assert verified.json()["checked"] == 2
    from app.main import database
    with database() as connection:
        connection.execute("UPDATE decisions SET score=0 WHERE tenant='t1' AND rowid=(SELECT MIN(rowid) FROM decisions)")
    broken = client.get("/v1/audit/verify", headers=headers())
    assert broken.json()["valid"] is False
    assert broken.json()["checked"] == 0

def test_tenant_specific_audit(client):
    evaluate(client)
    assert client.get("/v1/audit/verify", headers=headers("other")).json()["checked"] == 0
    assert client.get("/v1/metrics", headers=headers("other")).json()["open_cases"] == 0
    assert client.get("/v1/audit/verify", headers=headers("analyst")).status_code == 200

def test_security_headers_and_large_body(client):
    response = client.get("/health")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    response = client.post("/v1/evaluate", headers={"X-API-Key": "admin", "Content-Length": "200000"}, content=b"{}")
    assert response.status_code == 413

def test_recovery_closed_without_verified_identity_proof(client):
    data = {"request_id": str(uuid.uuid4()), "subject_id": "alice", "action": "recovery"}
    response = client.post("/v1/evaluate", headers=headers(), json=data)
    assert response.status_code == 403
    assert "re-proofing" in response.json()["detail"]

def test_analyst_cannot_evaluate_or_start_challenge(client):
    data = {"request_id": str(uuid.uuid4()), "subject_id": "alice", "action": "login"}
    response = client.post("/v1/evaluate", headers=headers("analyst"), json=data)
    assert response.status_code == 403
    response = client.post("/v1/challenges", headers=headers("analyst"), json={"subject_id": "alice", "action": "login"})
    assert response.status_code == 403

def test_development_keys_disabled_outside_development(client, monkeypatch):
    monkeypatch.setenv("AEGIS_MODE", "production")
    assert client.get("/v1/events", headers=headers()).status_code == 503

def test_staging_requires_valid_oidc_config(monkeypatch):
    from app.auth import validate_mode
    monkeypatch.setenv("AEGIS_MODE", "staging")
    monkeypatch.delenv("AEGIS_OIDC_ISSUER", raising=False)
    with pytest.raises(RuntimeError, match="OIDC"):
        validate_mode()

def test_staging_rejects_development_keys(client, monkeypatch):
    from app.auth import validate_mode
    monkeypatch.setenv("AEGIS_MODE", "staging")
    monkeypatch.setenv("AEGIS_REFERENCE_HMAC_KEY", "test-only-identity-hmac-key-32bytes-minimum-abc123")
    monkeypatch.setenv("AEGIS_OIDC_ISSUER", "https://identity.example.org/")
    monkeypatch.setenv("AEGIS_OIDC_AUDIENCE", "aegis-api")
    monkeypatch.setenv("AEGIS_OIDC_JWKS_URL", "https://identity.example.org/keys")
    with pytest.raises(RuntimeError, match="Demo API keys"):
        validate_mode()
    monkeypatch.delenv("AEGIS_API_KEYS")
    validate_mode()
    assert client.get("/v1/events", headers=headers()).status_code == 401

def test_staging_jwt_signature_and_audience(client, monkeypatch):
    import jwt
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
    from datetime import datetime, timezone, timedelta
    from app import auth
    monkeypatch.setenv("AEGIS_MODE", "staging")
    monkeypatch.setenv("AEGIS_REFERENCE_HMAC_KEY", "test-only-identity-hmac-key-32bytes-minimum-abc123")
    monkeypatch.setenv("AEGIS_OIDC_ISSUER", "https://issuer.example.org/")
    monkeypatch.setenv("AEGIS_OIDC_AUDIENCE", "aegis-api")
    monkeypatch.setenv("AEGIS_OIDC_JWKS_URL", "https://issuer.example.org/jwks")
    secret = generate_private_key(public_exponent=65537, key_size=2048)
    class LocalJWKS:
        def get_signing_key_from_jwt(self, _):
            class Key: pass
            key = Key()
            key.key = secret.public_key()
            return key
    monkeypatch.setattr(auth, "jwks_client", lambda: LocalJWKS())
    now = datetime.now(timezone.utc)
    claims = {"sub": "analyst1", "iss": "https://issuer.example.org/",
              "aud": "aegis-api", "exp": now + timedelta(minutes=5),
              "iat": now, "aegis_tenant": "t1", "aegis_role": "analyst"}
    valid = jwt.encode(claims, secret, algorithm="RS256")
    response = client.get("/v1/events", headers={"Authorization": "Bearer " + valid})
    assert response.status_code == 200
    invalid = jwt.encode({**claims, "aud": "another-api"}, secret, algorithm="RS256")
    assert client.get("/v1/events", headers={"Authorization": "Bearer " + invalid}).status_code == 401
    signed_but_wrong_role = jwt.encode({**claims, "aegis_role": "superuser"}, secret, algorithm="RS256")
    assert client.get("/v1/events", headers={"Authorization": "Bearer " + signed_but_wrong_role}).status_code == 403

def test_sensitive_api_rate_limit(client, monkeypatch):
    monkeypatch.setenv("AEGIS_RATE_LIMIT_PER_MINUTE", "2")
    request = {"subject_id": "demo", "action": "login"}
    assert client.post("/v1/challenges", json=request, headers=headers()).status_code == 200
    assert client.post("/v1/challenges", json=request, headers=headers()).status_code == 200
    blocked = client.post("/v1/challenges", json=request, headers=headers())
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers

def test_staging_never_allows_action_without_proofing(client, monkeypatch):
    import jwt
    from datetime import datetime, timedelta, timezone
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
    from app import auth
    ed_key = Ed25519PrivateKey.generate()
    public = ed_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    client.post("/v1/credentials", headers=headers(), json={
        "subject_id": "alice", "credential_id": "staging-credential",
        "ed25519_public_key_b64": base64.b64encode(public).decode()})
    intent = {"subject_id": "alice", "action": "transfer", "amount_minor": 100,
              "currency": "USD", "beneficiary_id": "bob"}
    signed_challenge = client.post("/v1/challenges", json=intent, headers=headers()).json()
    signature = base64.b64encode(ed_key.sign(signed_challenge["message_to_sign"].encode())).decode()
    monkeypatch.setenv("AEGIS_MODE", "staging")
    monkeypatch.setenv("AEGIS_REFERENCE_HMAC_KEY", "test-staging-reference-hmac-key-with-at-least-32bytes")
    monkeypatch.setenv("AEGIS_OIDC_ISSUER", "https://issuer.example.org/")
    monkeypatch.setenv("AEGIS_OIDC_AUDIENCE", "aegis-api")
    monkeypatch.setenv("AEGIS_OIDC_JWKS_URL", "https://issuer.example.org/jwks")
    rsa_key = generate_private_key(public_exponent=65537, key_size=2048)
    class StaticJwks:
        def get_signing_key_from_jwt(self, token):
            class SigningKey: pass
            k = SigningKey()
            k.key = rsa_key.public_key()
            return k
    monkeypatch.setattr(auth, "jwks_client", lambda: StaticJwks())
    now = datetime.now(timezone.utc)
    token = jwt.encode({
        "sub": "test-service", "iss": "https://issuer.example.org/", "aud": "aegis-api",
        "exp": now + timedelta(minutes=5), "iat": now,
        "aegis_tenant": "t1", "aegis_role": "service"
    }, rsa_key, algorithm="RS256")
    result = client.post("/v1/evaluate", headers={"Authorization": "Bearer " + token},
                         json={**intent, "request_id": str(uuid.uuid4()),
                               "credential_id": "staging-credential",
                               "challenge_id": signed_challenge["challenge_id"],
                               "signature_b64": signature, "known_device": True})
    assert result.status_code == 200
    assert result.json()["decision"] == "hold"
    assert result.json()["evidence"]["signature_verified"]
    assert "VERIFIED_IDENTITY_PROOFING_REQUIRED" in result.json()["reason_codes"]
