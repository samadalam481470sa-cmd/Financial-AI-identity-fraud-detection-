# Production release gates — AEGIS IDENTITY

**Production is intentionally disabled.** This release supports an isolated development demonstration and a staging JWT authentication mode only. A successful CI build is not security accreditation, legal authorization, a privacy impact assessment or validation against real fraud.

## Delivered hardening

- Automatic failure of production startup until high-assurance controls have been implemented and independently approved.
- Development API keys disabled in staging; staging uses issuer-verified RS256 JWT access tokens from a fixed HTTPS JWKS address.
- Expected audience and issuer enforced; required expiry/issued-at and tenant/role claims; analyst role cannot evaluate transactions.
- Recovery API denied until independently verified recovery/re-proofing is implemented.
- Exact-transaction Ed25519 signing in the research prototype, single-use challenge, revocation and idempotency.
- Request size cap, security response headers, atomic per-credential request throttling (SQLite-backed), event-chain integrity verification, tenant-scoped audit and investigation data.
- Containerized backend and web, synthetic ML research and tested UI screenshot capture automation.

## Blocking release gates

| Gate | Status | Evidence needed before enabling |
| --- | --- | --- |
| Real identity proofing and issuer checks | NOT IMPLEMENTED | Document verification vendor integration, assurance mapping, consent, adversarial test results |
| WebAuthn passkeys, origins, RP ID, attestation | NOT IMPLEMENTED | End-to-end WebAuthn RP verification and negative tests |
| Secure account recovery | BLOCKED BY DESIGN | Independent recovery process, notification, escalation, appeals, red-team tests |
| Authenticated telemetry provenance | NOT IMPLEMENTED | Device/velocity/beneficiary signals from trusted systems, not caller supplied |
| PostgreSQL row-level security | NOT IMPLEMENTED | Enforced RLS, tenant isolation tests, migration and rollback plan |
| Production IAM / service identity | PARTIAL (staging JWT) | Tested IdP, service-to-service authn, scoped permissions, break-glass and rotation |
| Multi-instance rate limiting / abuse prevention | PARTIAL | Distributed durable limits, bot controls and DDoS resistance |
| Production key custody and tamper evidence | NOT IMPLEMENTED | HSM/KMS, anchored immutable logs, verified retention and deletion |
| Production cloud architecture | NOT IMPLEMENTED | Terraform, segregated AWS accounts/VPC, policy enforcement, WAF, TLS, observability |
| Real fraud model | NOT VALIDATED | Approved labels, prospective shadow evaluation, calibrated cost policies and fairness checks |
| Disaster recovery | NOT IMPLEMENTED | RTO/RPO, restore drills, verified backup encryption and key recovery |
| Legal/privacy governance | NOT VERIFIED | Applicable jurisdiction mapping, privacy impact assessment, human review, contracts and retention |
| Independent security signoff | NOT DONE | Threat model, pentest, SAST/DAST/SCA, incident response exercise, signed approval |

## Staging identity provider configuration (internal testing only)

```text
AEGIS_MODE=staging
AEGIS_OIDC_ISSUER=https://YOUR-IDP.example.com/
AEGIS_OIDC_AUDIENCE=aegis-api
AEGIS_OIDC_JWKS_URL=https://YOUR-IDP.example.com/.well-known/jwks.json
```

The issuer and JWKS must be HTTPS and preconfigured by the server administrator. JWTs must be signed with RS256, contain the exact expected issuer/audience, and carry `aegis_tenant` and `aegis_role` claims administered by the identity provider. The caller cannot supply its own key location. Never copy the development `AEGIS_API_KEYS` configuration into staging.

The current database and demo credential registration logic should only be used with synthetic staging identities on an isolated network, not for customer banking data.

## Verification commands

```bash
PYTHONPATH=backend python -m pytest backend/tests -q
cd frontend && npm install && npm run build
cd ..
docker compose build
```

These checks alone do not meet production gate criteria. The security owner must record acceptance evidence for each required gate before changing the fail-closed production behavior.

## Release definition

- **Development demonstration:** permitted with synthetic data and local-only network bindings.
- **Staging integration:** limited to isolated synthetic/authorized test data with a configured trusted IdP.
- **Production customer identity processing:** **NOT APPROVED**. The server refuses production mode rather than falling back to insecure authentication.
