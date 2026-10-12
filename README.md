# CPR – JengaBank APP04 Payment Processing Service

JengaSec 2026, Application Blue track. Python 3.12 · FastAPI · SQLAlchemy 2 · Alembic · PostgreSQL 16.

> **Private repository.** Never make this repo or its container image public: Red teams would study it before the event, and public images are rejected.

## Key dates (EAT)

| When | What |
|---|---|
| Mon 12 Oct, 23:59 | Every member: profile, ID, Code of Conduct complete |
| **Tue 13 Oct, 12:00** | **Proposal due** (also registration closes) |
| Tue 13 Oct, 14:00 | Build freeze: last Healthy image is locked (check the team page for our exact time) |
| 14–16 Oct | Live event at Strathmore |

## What is already here

The platform plumbing only. The ledger, transfer, fraud and maker-checker design is ours to write.

| Requirement | Where |
|---|---|
| linux/amd64, non-root, one port (8080) | `Dockerfile` |
| `/healthz`, `/readyz` (DB check), `/openapi.json` | `app/main.py` |
| One JSON log line per request (`ts, src_ip, method, path, status, user, action`) | `app/observability.py` |
| All other logs are JSON too | `app/observability.py` (`LOGGING`) |
| Tables and seed data created on startup | Alembic, run by `app/run.py` before the server starts |
| No internet at runtime | All packages installed in the image |
| No docs UI, no server header, no input echoed in 422 errors, security headers | `app/main.py`, `app/run.py` |

### Logging security events

Every request is logged automatically. Name the outcome wherever it is decided:

```python
from app import observability as audit

audit.user(user_id)               # once authentication succeeds
audit.action("transfer.denied")
```

Without an explicit action, the filter falls back to `http.request`, `authz.denied`, `input.rejected` and similar, based on the status code. Never log passwords, tokens or full secrets.

### Database changes

Add a new revision in `migrations/versions/` (`0002_...py`, `0003_...py`, each with `down_revision` pointing at the previous one). **Never edit a migration that has already been pushed.** Seed data (made-up only) goes in migrations too.

Money paths use the synchronous `get_db` session (`app/db.py`): one request, one thread, one transaction.

## Run locally

Tests (no database needed):

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt
.venv/Scripts/python -m pytest
```

Full stack (needs Docker Desktop running):

```bash
docker compose up --build
```

Then check `http://localhost:8080/healthz`, `/readyz` and `/openapi.json`.

## Build and submit

```bash
docker buildx build --platform linux/amd64 -t ghcr.io/<owner>/cpr-jengasec-2026:v1 --push .
```

- New tag every time (`v1`, `v2`, …), never `latest`.
- GHCR package visibility: **Private**.
- Token for the form: classic GitHub token with **`read:packages` only**.
- Team page → Submit application: image, username, token, port `8080`, health path `/healthz`, database **yes**.
- Wait for Pulled → Scanned → Deployed → **Healthy**.

### Open questions for the organisers

- Exact environment variable names for the PostgreSQL connection (`app/config.py` accepts `DATABASE_URL` or `PG*`).
- Does the database count toward our 3 GB?
- How are proposals and the 14:00 build freeze sequenced?

## Team

| Role | Owner | Area |
|---|---|---|
| A – Captain, Ops | | Pipeline, submission, freeze |
| B – Identity and access | | Auth, roles, authorisation checks |
| C – Payments core | | Ledger, transfers, fraud, maker-checker |
| D – Security lead | | Proposal, threat model, review, testing |

Rule: no security-critical change merges without D's review.

The proposal's threat model, architecture and security design are written by the team, not AI tools (competition rule). See `docs/JengaSec-2026-Team-Game-Plan.pdf`.
