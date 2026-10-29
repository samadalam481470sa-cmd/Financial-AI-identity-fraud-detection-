"""Security regression coverage for passkey origin, RP-ID, replay and intent binding.
Cryptographic response parsing itself is provided by the audited py_webauthn library;
mocked verification is used only for state-transition and policy integration tests.
"""
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.main import app, init_db
from app import passkeys


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_MODE", "development")
    monkeypatch.setenv("AEGIS_DB_PATH", str(tmp_path / "webauthn-test.sqlite3"))
    monkeypatch.setenv("AEGIS_API_KEYS", '{"admin":{"tenant":"alpha","role":"admin"},"service":{"tenant":"alpha","role":"service"},"other":{"tenant":"beta","role":"admin"},"analyst":{"tenant":"alpha","role":"analyst"}}')
    monkeypatch.setenv("AEGIS_RP_ID", "localhost")
    monkeypatch.setenv("AEGIS_ORIGIN", "http://localhost:8080")
    init_db()
    return TestClient(app)


def hdr(key="admin"):
    return {"X-API-Key": key}


def create_enrolled(client, monkeypatch):
    proof = client.post("/v1/passkeys/sandbox-proofing", headers=hdr(),
                        json={"subject_id": "alice", "reference": "synthetic-fixture-1234"})
    assert proof.status_code == 200
    assert proof.json()["verified_real_identity"] is False
    options = client.post("/v1/passkeys/registration/options", headers=hdr(),
                          json={"subject_id": "alice"})
    assert options.status_code == 200, options.text
    assert options.json()["publicKey"]["authenticatorSelection"]["userVerification"] == "required"
    assert options.json()["publicKey"]["rp"]["id"] == "localhost"
    fake_id = b"fake-valid-credential-id"
    fake_key = b"fake-cose-public-key"
    def pretend_registration(**kwargs):
        assert kwargs["expected_rp_id"] == "localhost"
        assert kwargs["expected_origin"] == "http://localhost:8080"
        assert kwargs["require_user_verification"] is True
        return SimpleNamespace(credential_id=fake_id, credential_public_key=fake_key,
                               sign_count=0, credential_backed_up=False)
    monkeypatch.setattr(passkeys, "verify_registration_response", pretend_registration)
    payload = {"subject_id": "alice", "challenge_id": options.json()["challenge_id"],
               "credential": {"id": passkeys.b64url(fake_id), "response": {}}}
    result = client.post("/v1/passkeys/registration/verify", headers=hdr(), json=payload)
    assert result.status_code == 200, result.text
    assert result.json()["user_verified"] is True
    replay = client.post("/v1/passkeys/registration/verify", headers=hdr(), json=payload)
    assert replay.status_code == 403
    return passkeys.b64url(fake_id)


def test_enrollment_requires_grant_and_role(client, monkeypatch):
    missing = client.post("/v1/passkeys/registration/options", headers=hdr(),
                          json={"subject_id": "unknown"})
    assert missing.status_code == 403
    analyst = client.post("/v1/passkeys/sandbox-proofing", headers=hdr("analyst"),
                          json={"subject_id": "alice", "reference": "synthetic-reference"})
    assert analyst.status_code == 403
    other = client.post("/v1/passkeys/registration/options", headers=hdr("other"),
                        json={"subject_id": "alice"})
    assert other.status_code == 403
    create_enrolled(client, monkeypatch)


def test_passkey_intent_binding_replay_and_tenant(client, monkeypatch):
    cid = create_enrolled(client, monkeypatch)
    intent = {"subject_id": "alice", "action": "transfer", "amount_minor": 2000,
              "currency": "USD", "beneficiary_id": "bob"}
    options = client.post("/v1/passkeys/authentication/options", headers=hdr("service"), json=intent)
    assert options.status_code == 200
    assert options.json()["publicKey"]["userVerification"] == "required"
    calls = []
    def pretend_authentication(**kwargs):
        assert kwargs["expected_rp_id"] == "localhost"
        assert kwargs["expected_origin"] == "http://localhost:8080"
        assert kwargs["require_user_verification"] is True
        calls.append(kwargs)
        return SimpleNamespace(new_sign_count=1, user_verified=True, credential_backed_up=False)
    monkeypatch.setattr(passkeys, "verify_authentication_response", pretend_authentication)
    payload = {**intent, "request_id": str(uuid.uuid4()), "known_device": True,
               "passkey_challenge_id": options.json()["challenge_id"],
               "passkey_credential": {"id": cid}}
    changed = client.post("/v1/evaluate", headers=hdr("service"), json={**payload,
                            "amount_minor": 3000})
    assert changed.status_code == 200
    assert changed.json()["decision"] == "hold"
    assert not changed.json()["evidence"]["passkey_verified"]
    payload["request_id"] = str(uuid.uuid4())
    successful = client.post("/v1/evaluate", headers=hdr("service"), json=payload)
    assert successful.status_code == 200, successful.text
    assert successful.json()["decision"] == "allow"
    assert successful.json()["evidence"]["passkey_verified"] is True
    assert len(calls) == 1
    replay = client.post("/v1/evaluate", headers=hdr("service"),
                         json={**payload, "request_id": str(uuid.uuid4())})
    assert replay.status_code == 200
    assert replay.json()["decision"] == "hold"
    assert len(calls) == 1
    cross = client.post("/v1/evaluate", headers=hdr("other"),
                        json={**payload, "request_id": str(uuid.uuid4())})
    assert cross.status_code == 200
    assert not cross.json()["evidence"]["passkey_verified"]


def test_bogus_signature_never_authorizes(client, monkeypatch):
    create_enrolled(client, monkeypatch)
    intent = {"subject_id": "alice", "action": "transfer", "amount_minor": 100}
    challenge = client.post("/v1/passkeys/authentication/options", headers=hdr(), json=intent)
    assert challenge.status_code == 200
    response = client.post("/v1/evaluate", headers=hdr(), json={**intent,
       "request_id": str(uuid.uuid4()), "passkey_challenge_id": challenge.json()["challenge_id"],
       "passkey_credential": {"id": passkeys.b64url(b"fake-valid-credential-id")}})
    assert response.status_code == 200
    assert response.json()["decision"] == "hold"
    assert not response.json()["evidence"]["passkey_verified"]


def test_staging_enrollment_disabled(client, monkeypatch):
    monkeypatch.setenv("AEGIS_MODE", "staging")
    response = client.post("/v1/passkeys/sandbox-proofing", headers=hdr(),
                           json={"subject_id": "alice", "reference": "synthetic-proof-123"})
    assert response.status_code in (401, 403)


def test_rp_configuration_restrictions(monkeypatch):
    monkeypatch.setenv("AEGIS_MODE", "staging")
    monkeypatch.setenv("AEGIS_RP_ID", "localhost")
    monkeypatch.setenv("AEGIS_ORIGIN", "http://localhost:8080")
    with pytest.raises(RuntimeError, match="HTTPS"):
        passkeys.rp_settings()
    monkeypatch.setenv("AEGIS_ORIGIN", "https://example.com")
    monkeypatch.setenv("AEGIS_RP_ID", "https://example.com")
    with pytest.raises(RuntimeError, match="host name"):
        passkeys.rp_settings()
