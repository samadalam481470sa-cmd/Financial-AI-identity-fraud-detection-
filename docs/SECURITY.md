# AEGIS IDENTITY Security Architecture and Limitations

## System invariants

1. Personal information is **never** a standalone authenticator.
2. Login and sensitive actions require a successfully verified, unrevoked cryptographic credential.
3. Signatures cover a one-time server-issued challenge bound to subject, tenant, amount, action, beneficiary and currency.
4. A challenge expires after three minutes and is consumed once. A second request with the same request ID is idempotent; reusing that ID for different inputs is rejected.
5. All events and case queries are scoped to the authenticated tenant.
6. Fraud scores cannot override mandatory signed-action requirements.
7. Every decision stores its policy version, model version, anonymized subject reference, reasons, signed-evidence state, and chained event digest.
8. High-risk and challenged decisions open an investigation case; the case may be resolved by an authorized analyst.
9. The demo does not store SSNs, biometric images, or government ID documents.
10. The application must not be exposed publicly or used for live identity verification.

## Verified WebAuthn and signed event provenance

Browser passkey registration and authentication now verify real WebAuthn authenticator responses, including origin, relying-party ID, user verification, signature, one-time challenge, intent binding and replay resistance. Browser integration tests exercise virtual authenticator registration and signed authorization. The sandbox grant is synthetic and is **not evidence of a person's legal identity**.

Fraud telemetry requires both an authenticated service identity and a separately pinned Ed25519 event-source signature. Signed events are deduplicated and stored with HMAC-derived tenant-specific subject/device/beneficiary references. The deterministic graph feature extractor identifies fan-out, shared beneficiaries, reciprocal transfers and short cycles within 24 hours. These indicators require human interpretation, never automatic criminal accusations.

Staging requires an external `AEGIS_REFERENCE_HMAC_KEY` (32+ bytes), issuer-validated OIDC and TLS for remote origins. Proper key custody and historical-reference rotation remain release gates.

## Attacker scenarios and expected controls

| Scenario | Expected control |
| --- | --- |
| Compromised SSN and date of birth | Knowledge of PII does not authorize anything |
| Forged `credential_verified=true` JSON | No such trusted field; verifier checks Ed25519 signature itself |
| Tampering with transfer amount after signing | Intent digest mismatch; signed action is not verified |
| Reusing a challenge | Atomic nonce consumption; replay denied |
| Reusing request ID for another transaction | 409 conflict |
| Repeated fraud events in another tenant | Database-scoped filtering |
| Revoked signing credential | Verification fails |
| Unfamiliar device and new beneficiary | Elevated contextual risk; potentially hold/challenge |

## Limits and required production work

This is an **engineering prototype**, not a production identity provider, an audited financial service, or a model validated for real fraud. This implementation uses server-configured API keys for its sandbox, not OIDC, service-to-service mTLS, or fine-grained identity assurance. Demo Ed25519 browser signing is **not WebAuthn** or an attested hardware-backed passkey. Credential enrollment is administrator-operated and is not backed by in-person or issuer-proven identity proofing. The console supplies contextual signals, so untrusted sources could misrepresent new-device or velocity fields; in production signals must come from server-controlled telemetry with provenance checks.

SQLite is intended for local development, not multi-replica high-throughput production. The chained event hash detects some modifications only if anchored externally; it is **not** an independently tamper-proof ledger. A synthetic-only trainable fraud ML experiment, local authenticated temporal graph feature extractor, and a SQLite-backed rate limiter are implemented. No independently validated real-data fraud classifier, production graph database, bank integration, document verification, biometric liveness pipeline, HSM/KMS custody, distributed rate-limiting system, or audited cloud deployment is included.

Before any sensitive deployment: integrate NIST SP 800-63-4-aligned proofing, robust WebAuthn RP verification, origin/RP-ID binding and attestation policy, OIDC authorization, tenant-aware Postgres row-level security, KMS-backed integrity checks, strict event provenance, data protection controls, user appeals, account recovery safeguards, logging, incident response, independent security review and formal ML model validation.

## Data and privacy safeguards

Demo decisions store hashed subject references, never plaintext subject IDs. The credential registry and nonce challenges store subject identifiers for sandbox verification. Keep synthetic data only, use isolated development keys, and erase demo databases after tests. Do not submit real SSNs, ID scans, bank details or biometric data.

## Responsible demonstration

When describing the app to recruiters, say: "AEGIS IDENTITY implements a tenant-aware signed-intent transaction decision prototype and fraud investigations; fraud scoring is presently a deterministic baseline and browser Ed25519 is a demonstrator, not verified WebAuthn."
