# Deployment Guide — Development / Internal Evaluation

## One command local full-stack stack

```bash
cp .env.example .env
# Edit .env and set a unique local-only AEGIS_API_KEYS mapping.
docker compose up --build
```

Open **http://localhost:8080**. The dashboard, API and API docs are proxied to the same origin. The SQLite database is stored in a Docker volume.

API alone is also available on `http://127.0.0.1:8000`. The backend and frontend ports bind to loopback only; no public deployment or TLS is configured.

## Example environment

```dotenv
AEGIS_API_KEYS={"change-this-to-a-long-random-secret":{"tenant":"sandbox","role":"admin"}}
```

An administrator key is necessary for demonstration credential enrollment. Rotate keys and remove the example after local testing. Never put keys or other sensitive data in git.

## Security boundaries and deployment blockers

This Docker deployment is **for local development only**. It has no TLS termination and API credentials are shared with browser JavaScript. Do not expose it on the Internet. Production requires OIDC-based identity with secure sessions, fine-grained authorization, independent proofing, WebAuthn relying party implementation, rate limits, legitimate client/server event provenance, database row-level isolation, device posture, secret management, active monitoring, incident runbooks, backup validation and independent security review.

## Persistence

SQLite persists in the named volume `aegis-data`. To erase demonstration data: `docker compose down -v` (destructive; backup first). No production backup automation is provided.

## Diagnostics

- `docker compose ps`
- `docker compose logs -f api`
- `docker compose logs -f web`
- `curl -s http://localhost:8080/health`
- `curl -s -H "X-API-Key: YOUR_LOCAL_KEY" http://localhost:8080/v1/metrics`
- `curl -s -H "X-API-Key: YOUR_LOCAL_KEY" http://localhost:8080/v1/audit/verify`

Metrics describe synthetic risk decisions. The hash-chain check identifies changes to covered decision fields but is not externally anchored or independently tamper-proof.

## Validation before demonstration

Verify backend tests and frontend build pass in GitHub Actions. Perform the signed-demo walkthrough in the repository README. Test in a local browser. Docker build/test success alone does not establish production readiness.
