# WebAuthn and Signed Fraud Telemetry — Implementation Guide

This document explains **actually implemented controls** and what remains outside the current release. The project is suitable for isolated synthetic-data demonstrations, not real customer identity verification or payments.

## 1. Real browser WebAuthn credential ceremonies

The API uses the `webauthn` (py_webauthn) Python relying-party library and the browser's native `navigator.credentials` API.

- `POST /v1/passkeys/sandbox-proofing`: development-only admin marking a **synthetic** user as test-enrolled. It is NOT a verified legal identity.
- `POST /v1/passkeys/registration/options`: admin-initiated WebAuthn registration with server-generated 32-byte challenge, per-subject ID, anti-duplicate credentials, and **required user verification**.
- `POST /v1/passkeys/registration/verify`: validates authenticator-generated attestation data, the expected RP ID, exact origin, user verification and challenge. Stores COSE credential public key and signature counter only after verification.
- `POST /v1/passkeys/authentication/options`: generates an authenticator assertion challenge tied to **tenant, subject, action, amount, currency, beneficiary**.
- `POST /v1/evaluate`: accepts `passkey_challenge_id` and `passkey_credential` from the browser; verifies origin, RP ID, signed authenticator data, signature count, UV, challenge expiry, exact transaction and atomic replay consumption before satisfying mandatory signed-action policy.
- `DELETE /v1/passkeys/{credential_id}`: admin revocation scoped to tenant.

Current development configuration:

```dotenv
AEGIS_MODE=development
AEGIS_RP_ID=localhost
AEGIS_ORIGIN=http://localhost:8080
```

If running the Vite development server at http://localhost:5173, set `AEGIS_ORIGIN=http://localhost:5173` **on the backend**. Browser WebAuthn requires a secure context: HTTPS in staging or localhost for development. The browser must access the same origin configured server-side.

**Sandbox browser flow:** Open the dashboard as a demo administrator, click "1. Synthetic proofing grant," then "2. Register WebAuthn passkey," and run "Evaluate with passkey" for a synthetic low-risk transfer. An unsigned transfer must still be held, while a passkey-signed one may be allowed in local mode. This integration is verified using a Chromium virtual authenticator in `.github/workflows/webauthn-e2e.yml`.

### Identity assurance limit

The proofing grant is explicitly synthetic and available only in development. Passkeys establish continuity of possession of a browser authenticator, NOT the human's legal identity. In staging, the sandbox enrollment endpoint refuses to run; trusted issuer-backed enrollment has not yet been built. All would-be staging ALLOW decisions are force-held until external identity proofing is present. A real account recovery process is also blocked.

To add proofing properly, integrate a contracted third-party issuer/document provider and verify its signed webhooks, timestamp, session binding, document authenticity, anti-injection checks and repeat-use controls. Define assurance levels and review NIST SP 800-63A-4 requirements; include operator escalation and accessibility.

## 2. Independent signed telemetry ingestion

`POST /v1/telemetry/events` accepts **only** a `service` role and a separately configured Ed25519 source signature. The signing key must belong to the same tenant as the service principal. Signals do not become trusted simply because a browser or API caller sets a Boolean.

Configure source public keys, never private keys, in the backend environment:

```dotenv
AEGIS_TELEMETRY_SIGNERS={"issuer-01":{"tenant":"sandbox","ed25519_public_key_b64":"PUBLIC_KEY_BASE64_HERE"}}
```

Event envelope:

```json
{
  "source_id": "issuer-01",
  "event": {
    "event_id": "6e265fb3-c60d-40d0-bf04-dc166340c3a1",
    "subject_id": "synthetic-user",
    "event_type": "login_failed",
    "occurred_at": "2026-10-29T15:00:00Z",
    "device_id": null,
    "beneficiary_id": null
  },
  "signature_b64": "SOURCE_SIGNATURE_BASE64"
}
```

**Signing contract:** Construct `TelemetryEvent` with the event fields and sign the bytes returned by `backend/app/telemetry.py::canonical_message(event)` using the source's Ed25519 private key. The signed bytes are `b"AEGIS-TELEMETRY-V1\\n" + json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode("utf-8")`. Signatures and event IDs are checked server-side; events outside a five-minute window and duplicate event IDs are rejected.

Only hashed subject/device/beneficiary references, event type, event time, source ID and signature hash enter the telemetry table. The system derives failed-login bursts, transfer velocity, recently added beneficiaries and device changes from verified signed history. In staging, **untrusted client-supplied fraud flags are not included** in the rule-score calculation.

**Limit:** A signed event only proves the signer submitted the data. It does not establish that the signer measured it accurately, nor replace evidence governance, partner due diligence, secure event issuance, network security or real investigation labels.

## 3. Regression verification

```bash
PYTHONPATH=backend python -m pytest backend/tests -q
```

Dedicated suites: `test_passkeys.py` checks registration policy, intent binding, replay, origin and tenant isolation; `test_telemetry.py` checks source signatures, wrong-tenant blocks, replay, staleness and verified risk features.

`scripts/verify-passkeys.mjs` uses Chromium's virtual WebAuthn authenticator to exercise **real** browser credential creation and an authenticator-signed authorization against the running backend. See the GitHub Actions "WebAuthn browser integration" workflow.

## 4. Future production requirements

- An independently validated identity-proofing provider, retention/consent policies and accessible recovery.
- Enterprise OIDC/OAuth integration with fine-grained service identities and safe delegated user binding.
- PostgreSQL with tenant row-level security, migration/rollback, encrypted backups and restore drills.
- Real trusted bank/identity-event issuer integrations, event-bus semantics, resilient rate controls and a secure data lake.
- HSM/KMS-backed secrets, immutable externally anchored audit trail, alerts, observability, incident management, disaster recovery.
- Representative, permissioned fraud outcomes with calibration, drift, privacy and fairness testing.
- Formal security review, threat-model and independent penetration test before processing customer records.

**The server deliberately rejects `AEGIS_MODE=production`** until these release gates have been satisfied.
