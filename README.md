# CPR – JengaBank APP04 Payment Processing Service

JengaSec 2026, Application Blue track. Python 3.12 · FastAPI · SQLAlchemy 2 · Alembic · PostgreSQL 16.

> **Private repository.** Never make this repo or its container image public: Red teams would study it before the event, and public images are rejected.

## Key dates (EAT)

| When | What |
|---|---|
| Mon 12 Oct, 23:59 | Every member: profile, ID, Code of Conduct complete |
| **Tue 13 Oct, 12:00** | **Proposal due** (also registration closes) |
| **Tue 13 Oct, 13:00** | **Build freeze: last Healthy image is locked** (confirmed on our team page) |
| Tue 13 Oct, 14:00 | Other documents close (Blue Team Documentation, Report, Supporting Evidence) |
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
- Which of Blue Team Documentation, Report and Supporting Evidence are required, and can a filing be replaced?
- Do Red teams or judges get credentials from us? If yes, customer accounts only: which ones?
- Does the platform database persist across image submissions, or start fresh each time?
- Can we reset the platform database before the freeze if test data gets in by accident?

## Team

| Member | Role | Owns |
|---|---|---|
| **Moses** | Captain + builder: ledger core | Double-entry ledger, atomic transfers, seed data, maker-checker (with Kathy), pipeline and submission, freeze |
| **Kathy** | Builder: access and approval | Authentication, roles, ownership checks, lockout and rate limits, maker-checker (with Moses) |
| **Adam** | Builder: controls | Idempotency, limits, reversals, fraud allow/review/block, end-of-day reconciliation |
| **Ethan** | Security specialist | Proposal lead, threat model, append-only log, code review, testing our own service |

Tasks are GitHub issues, one owner each. Design decisions live in [`docs/DECISIONS.md`](docs/DECISIONS.md).

### How we work

- Branch per task: `moses/ledger`, `kathy/auth`, `adam/fraud`, ... Open a pull request into `main`; never push straight to `main`.
- **Ethan reviews every security-critical pull request before it merges.**
- `main` must always build and pass `pytest`. Moses ships images from `main` only.
- Check in every 4–6 hours: done, blocked, next.
- Moses owns the freeze: when he says stop, everyone stops.


