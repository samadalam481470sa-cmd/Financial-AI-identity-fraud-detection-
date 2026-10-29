# AEGIS IDENTITY
### Adaptive Evidence-Grounded Identity Security

A runnable full-stack fraud prevention and identity continuity research prototype. **Stolen personal information alone must not authorize access or sensitive actions.**

**Status:** local testable demo. Not certified, independently audited, production-ready, a live bank integration, a real identity-proofing system or a trained fraud ML model. Use synthetic data only.

## What is implemented

- FastAPI service with environment-configured API-key authentication, tenant separation and admin/analyst roles
- Server-side Ed25519 verification of registered credentials for signed login, transfer, profile change and recovery intent
- One-time three-minute challenges bound to tenant, user, action, amount, currency and beneficiary, with replay prevention
- Revocation, idempotent request handling, authenticated case management, persistent SQLite records
- Baseline deterministic fraud risk rules, hard policy gates, decision reasons, event hash chaining and model/policy versions
- Responsive React/Vite dashboard: unsigned vs signed evaluation, browser cryptographic demo, cases and audit events
- GitHub Actions automated tests and build, Docker Compose full-stack web + API with same-origin Nginx proxy
- Independent one-hour observed transaction velocity, tenant-scoped aggregate metrics and verifiable local audit hash chains
- [Engineering blueprint](docs/BLUEPRINT.md) and [security limits and attacker tests](docs/SECURITY.md)

## One-command full-stack Docker demo

```bash
git clone https://github.com/samadalam481470sa-cmd/Financial-AI-identity-fraud-detection-.git
cd Financial-AI-identity-fraud-detection-
cp .env.example .env
# Replace example API keys with unique local-only keys in .env
docker compose up --build
```

Open **http://localhost:8080** and enter the configured admin key. This setup runs both the React dashboard and FastAPI server behind a same-origin Nginx proxy; ports bind to localhost only. See [local deployment guide](docs/DEPLOYMENT.md).

## Run locally

Requires Python 3.12+, Node.js 22+, and a modern browser.

**Terminal 1 — backend (macOS/Linux):**

```bash
git clone https://github.com/samadalam481470sa-cmd/Financial-AI-identity-fraud-detection-.git
cd Financial-AI-identity-fraud-detection-
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
export AEGIS_API_KEYS='{"local-dev-only-key":{"tenant":"sandbox","role":"admin"}}'
export AEGIS_DB_PATH=./aegis.db
PYTHONPATH=backend uvicorn app.main:app --reload --port 8000
```

**Windows PowerShell**, after installing dependencies:

```powershell
$env:AEGIS_API_KEYS='{"local-dev-only-key":{"tenant":"sandbox","role":"admin"}}'
$env:AEGIS_DB_PATH='./aegis.db'
$env:PYTHONPATH='backend'
python -m uvicorn app.main:app --reload --port 8000
```

**Terminal 2 — dashboard:**

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 and enter the development API key `local-dev-only-key`. Open http://localhost:8000/docs for interactive API documentation.

## Demo walkthrough

1. Evaluate an **unsigned $15,000 transfer**, new device, new beneficiary: expect **HOLD**, because cryptographic proof is mandatory.
2. Click **Register demo credential**. Browser creates an ephemeral Ed25519 key and registers its public half with the admin API.
3. Click **Evaluate signed**. The browser signs a server-issued intent digest. The server verifies key, expiry, exact action fields, tenant and nonce. High risk can still cause a **HOLD**.
4. Lower the amount, disable anomalous flags and velocity, sign again to demonstrate **ALLOW**.
5. View **Audit events** and **Investigation cases**, and update case status.

The demo browser Ed25519 ceremony is **not** WebAuthn or proof that a person has been verified. Device and velocity fields are synthetic caller-supplied demonstration signals, not independently sourced production telemetry.

## API

| Method | Endpoint | Access |
|---|---|---|
| GET | `/health` | Public |
| POST | `/v1/credentials` | Admin |
| DELETE | `/v1/credentials/{credential_id}` | Admin |
| POST | `/v1/challenges` | Authenticated |
| POST | `/v1/evaluate` | Authenticated |
| GET | `/v1/events` | Analyst/Admin |
| GET | `/v1/cases` | Analyst/Admin |
| PATCH | `/v1/cases/{case_id}` | Analyst/Admin |

Additional analyst endpoints: `GET /v1/metrics` and `GET /v1/audit/verify`. The audit chain is not externally anchored and does not guarantee independent immutability.

Requests use `X-API-Key` from the `AEGIS_API_KEYS` JSON environment variable, e.g. `{"your-key":{"tenant":"demo","role":"admin"}}`. Never commit or publish real keys.

## Test and container

```bash
PYTHONPATH=backend python -m pytest backend/tests -q
cd frontend && npm install && npm run build
```

```bash
AEGIS_API_KEYS='{"your-local-secret":{"tenant":"sandbox","role":"admin"}}' docker compose up --build
```

Docker exposes the API on localhost:8000 and the built React dashboard on localhost:8080. Both bind to loopback only.

## Architecture

```text
React fraud investigation console
               |
Authenticated FastAPI boundary
               |
Credential registry / one-time challenge verifier
               |
Signed-intent gate + deterministic risk policy
               |
SQLite transactional storage
  |            |              |
Decisions    Cases       Audit / integrity hashes
```

## Reproducible ML research (not in authorization path)

See [ml/README.md](ml/README.md). A separate trainable gradient-boosted classification experiment creates **only synthetic labeled data**, performs train/calibration/test splits and exports held-out precision, recall, average precision, ROC-AUC and Brier score. This is a research sandbox, **not a validated real-world fraud detection model**.

```bash
pip install -r ml/requirements.txt
python ml/train.py --rows 6000 --output ml/artifacts
```

The API never executes this prototype model in sensitive decisions. Real financial deployment would require approved non-synthetic datasets, independently verified features, calibrated risk thresholds and a safe shadow validation rollout.

## Next enterprise milestones

- WebAuthn relying-party implementation and phishing-resistant authentication instead of demo signing
- Real third-party document/issuer proofing, verified telemetry, trusted evidence custody and accessible secure recovery
- PostgreSQL RLS, Kafka events, Redis aggregation, graph stores, OIDC IAM, AWS/Kubernetes/Terraform and KMS/HSM
- Validated calibrated fraud models using representative data, temporal graph analytics, fairness tests, red teaming
- Independent penetration test, audit and compliance review before any public or sensitive deployment

## Source blueprint

The owner-provided **User Fraud Detection AI — 100 Pages** PDF is the design reference. Its recommendations include signed identity continuity, transaction monitoring, privacy-aware behavioral intelligence, replay resistance, event schemas, and independent verification. Its proposed components are roadmap items unless identified above as actually implemented. See [docs/BLUEPRINT.md](docs/BLUEPRINT.md).

This repository is MIT licensed. 
