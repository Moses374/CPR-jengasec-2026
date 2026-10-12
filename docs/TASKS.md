# Task guide

What each task involves, how to approach it, what can go wrong, and what "done" means.

**How to use this:** where a task needs a design choice, this guide lists the options and trade-offs. The owner picks one, writes the choice and the reason in [`DECISIONS.md`](DECISIONS.md), and the proposal describes it. Competition rule: our threat model, architecture and security design are written by us, not AI tools.

## Shared conventions

**Code layout.** One file per owner keeps merge conflicts rare:

| File | Owner |
|---|---|
| `app/models.py` | Moses creates; others add their own tables at the bottom |
| `app/ledger.py` | Moses: posting entries, balances, transfers. Adam adds reversals |
| `app/auth.py` | Kathy: login, tokens, current user, role checks |
| `app/approvals.py` | Kathy with Moses: maker-checker |
| `app/fraud.py`, `app/recon.py` | Adam |
| `app/audit_log.py` | Ethan |
| `app/routes/*.py` | Each owner adds their own router; Moses wires them into `app/main.py` |
| `migrations/versions/` | One new revision per change, numbered in order. Announce in chat before creating one, so two people don't both make `0003`. |

**Every endpoint:**
- Requires a logged-in user except `/healthz`, `/readyz`, `/openapi.json` and login.
- Validates input with a Pydantic model using `extra="forbid"`, so unknown fields (`"balance"`, `"role"`) are rejected and mass assignment is impossible.
- Calls `audit.action("...")` with the specific outcome.
- Never returns stack traces, SQL errors or internal IDs it does not need to.

**Every pull request:** small, with tests, `pytest` green, Ethan reviews anything touching money, auth or the log.

**Two production facts that shape several tasks:**
1. The app runs **2 worker processes** (`WEB_CONCURRENCY=2`). Anything kept in Python memory (a secret generated at startup, an in-memory rate limiter, a cache) is **different in each worker**. Shared state must live in PostgreSQL, or we deliberately set one worker.
2. The database is **snapshotted at freeze and restored before each event day**. Seed data and any generated secrets must live in the database (created by migrations or on first start), not in files.

---

## #1 All: design decisions session (tonight)

**Goal:** every question in `DECISIONS.md` answered and agreed, plus the API table filled in.

**Run it like this (90 minutes):**
1. 10 min: read the APP04 brief together, out loud.
2. 15 min each: Moses, Kathy, Adam, Ethan present their answers; others challenge them. Use this guide's options as the menu.
3. 20 min: fill the API table together (method, path, role, purpose).
4. 5 min: confirm who starts what tonight.

**Done when:** every question is marked `agreed`, and the API table lists every endpoint. Push it to `main`.

---

## Moses

### #2 Team admin and registration (tonight 23:59)

- Each member: verify email, fill **My Profile**, upload ID, accept the **Code of Conduct**. Check each person's status on the team page yourself; do not take "done" on trust.
- **My Team:** mark Ethan as security specialist, pick a deputy captain.
- **Registration form:** Application Blue first, AI Defence Blue second, enterprise no preference, skills declaration (drafted already; each person confirms their line is true). It locks on submit.
- Confirm all three accepted their GitHub invites (Settings → Collaborators shows "pending" otherwise).

**Done when:** the team checklist on the website is fully green and registration is submitted.

### #3 Prove the submission pipeline (tonight)

The point is to hit token, platform and port problems now, with a trivial app, not on Tuesday with the real one.

1. **Push token:** GitHub → Settings → Developer settings → Tokens (classic) → scope `write:packages`. Personal; never share or commit it.
2. Log in and push:
   ```bash
   echo <PUSH_TOKEN> | docker login ghcr.io -u Moses374 --password-stdin
   docker buildx build --platform linux/amd64 -t ghcr.io/moses374/cpr-jengasec-2026:v1 --push .
   ```
3. **Visibility:** GitHub → your profile → Packages → `cpr-jengasec-2026` → Package settings → confirm **Private**. Link it to the repo (same page) so teammates can see it.
4. **Form token:** a second classic token with **only `read:packages`**. This one goes into the submission form.
5. **Team page → Submit application:** image `ghcr.io/moses374/cpr-jengasec-2026:v1`, username `Moses374`, the read-only token, port `8080`, health path `/healthz`, database **yes**.
6. Watch it go Pulled → Scanned → Deployed → **Healthy**. Read the scan report and the app logs on the page.
7. **Find the database settings.** The logs show whether migrations ran. If they failed, the platform is using different variable names than `DATABASE_URL` / `PG*`; the Image Submission Guide should list them. Update `app/config.py` (small PR).

**If it fails:** see the troubleshooting table in `docs/JengaSec-2026-Team-Game-Plan.pdf` (unauthorized → token; exec format error → platform flag; stuck at Deployed → port/path or crash in logs).

**Done when:** a screenshot of **Healthy** is posted on the issue and the DB variable names are confirmed.

### #8 Double-entry ledger and atomic transfers (Tue ~06:00)

**Double entry in one paragraph:** money is never created or destroyed. Every movement is a *transaction* made of two or more *entries*: a debit on one account and an equal credit on another. The entries of each transaction sum to zero. An account's balance is not stored anywhere; it is the **sum of its entries**.

**Tables to design** (decide columns and constraints): accounts, transactions, entries. Things worth enforcing in the database, not just Python: amounts non-zero, entries reference real accounts and transactions, transaction entries balance (check in the posting function, verified by reconciliation).

**Deriving the balance.** `SELECT COALESCE(SUM(amount), 0) FROM entries WHERE account_id = :id` with an index on `account_id`. Fast enough for this event. Avoid a stored balance column: the brief explicitly forbids a mutable balance.

**Concurrency: pick one mechanism and prove it.**

| Option | How | Trade-off |
|---|---|---|
| **Row locks** | In one transaction: `SELECT ... FROM accounts WHERE id IN (:a, :b) ORDER BY id FOR UPDATE`, then compute balance, check, insert entries, commit | Simple and standard. **Always lock in the same order** (by id) or two opposite transfers deadlock. |
| **SERIALIZABLE isolation** | Run the transfer at `SERIALIZABLE`; retry on serialization failure | Correct by construction; needs a retry loop and can fail under heavy contention |
| **Advisory locks** | `pg_advisory_xact_lock(account_id)` | Works, but easier to get subtly wrong |

**Amounts.** Choose integer minor units (`BIGINT` cents) or `NUMERIC(18,2)` with Python `Decimal`. Never floats. In the request model, reject zero, negatives, too many decimal places, non-numbers, and absurd values, and reject transfers to the same account or to accounts that do not exist.

**Transfer flow** (one database transaction, in this order): validate → authorise (Kathy's ownership check) → idempotency check → lock accounts → compute balance → limits → fraud (Adam) → maker-checker threshold (Kathy and Moses) → insert transaction + entries → audit log record (Ethan) → commit.

**Seed data:** a migration with made-up customers, accounts and opening balances (an opening balance is itself a transaction from a bank "equity" or "funding" account, so the books still balance).

**Logging:** `transfer.created`, `transfer.denied`, `transfer.insufficient_funds`, `input.rejected`.

**Tests:** the key one: **50 parallel transfers from one account never overspend and the ledger still sums to zero.** A test with threads and real PostgreSQL (via `docker compose up db`) is enough.

**Hand-off:** push the models and the posting function early; Kathy, Adam and Ethan plug into it. Adam's idempotency, limits and reversals (#9) build directly on this, so agree the function signatures with him tonight.

### #5 Final freeze submission (Tue 11:00)

- **09:00 feature freeze:** announce it. After that only fixes for Ethan's findings merge.
- On `main`: `pytest` green; `docker compose up --build` works from a clean state (`docker compose down -v` first).
- **Scan:** `docker run --rm -v //var/run/docker.sock:/var/run/docker.sock aquasec/trivy image ghcr.io/moses374/cpr-jengasec-2026:vN`. Fix criticals (usually a newer base image or package version).
- **Load check:** run Ethan's parallel-transfer script while watching `docker stats`; memory must stay well under the limit.
- Push the final tag (`vN`, never `latest`), submit, confirm **Healthy** by 11:00. Leave 11:00–14:00 as buffer.
- Before 14 Oct: all four download their WireGuard profiles and test the connection.

---

## Kathy (Moses pairs on #7)

### #6 Authentication and roles (Tue ~06:00)

**What to build:** login, logout, "who is calling" for every request, and role checks.

**Passwords.** Hash with `argon2-cffi` (preferred) or `bcrypt`; add the package to `requirements.txt`. Never store or log plain passwords. Compare in constant time (the libraries do).

**Tokens: pick one.**

| Option | Pros | Cons / traps |
|---|---|---|
| **Opaque session token** stored hashed in a `sessions` table | Works across both workers; real logout (delete the row); easy expiry | One DB lookup per request (fine) |
| **JWT** (`PyJWT`) | No lookup per request | The signing secret must be shared by both workers **and** survive restarts: store it in the database, not generated per process. Logout needs a denylist. Pin the algorithm (`algorithms=["HS256"]`) so `none` and algorithm confusion fail. |

Either way: short expiry, tokens in the `Authorization: Bearer` header, never in URLs.

**Roles.** Decide the list (for example customer, teller/operator, approver, auditor, admin) and write one FastAPI dependency per check (`require_role("approver")`). Checks happen on the server for every route.

**Ownership checks.** The number one bank bug (IDOR). Every query for an account or transfer is scoped to the caller: `WHERE id = :id AND owner_id = :current_user`. If it is not theirs, return **404**, not 403, so attackers cannot learn which IDs exist. Use random UUIDs, not sequential numbers.

**Lockout and rate limiting.**
- In-memory limiters do not work with 2 workers; keep counters in PostgreSQL (`failed_attempts`, `locked_until` on the user, or a small attempts table).
- A hard lockout lets an attacker lock real customers out on purpose. Safer: temporary lockout with backoff, plus throttling per source IP.
- Error messages are identical for "no such user" and "wrong password", and take similar time.

**Logging:** `audit.user(user_id)` on every authenticated request; actions `login.ok`, `login.failed`, `login.locked`, `token.invalid`, `authz.denied`.

**Seed users:** made-up names, strong random passwords, documented in a seed file only the team sees. No `admin/admin`.

**Tests:** login ok/fail, lockout triggers and expires, expired token rejected, customer A cannot read customer B's account (404), role checks deny.

**Hand-off:** Moses and Adam depend on `current_user` and `require_role`. Push those first (even before lockout) so they can build on them.

### #7 Maker-checker approvals (Tue ~09:00)

**What it means:** above a threshold, the person who creates a transfer (maker) cannot make it happen alone; a different authorised person (checker) must approve it.

**State machine** (Moses and Kathy build this together: it is part of the transfer flow):
`pending_approval → approved → posted`, or `pending_approval → rejected`, or `pending_approval → expired`.

**Rules to decide and enforce:**
- Threshold amount (and whether it applies per transfer or per day).
- Which role can approve.
- **Checker ≠ maker**, enforced in code *and* as a database check constraint.
- Expiry time for requests nobody handles.

**Traps:**
- **Double approval race:** two checkers approving at once. Do the transition with `UPDATE ... SET status='approved' WHERE id=:id AND status='pending_approval'` and check that exactly one row changed.
- **Stale funds:** the balance may have changed since the request. Re-check funds and limits *at posting time*, inside the locked transfer transaction.
- **Splitting:** someone sends many transfers just under the threshold. Adam's velocity rule or a daily threshold can catch it; decide which.

**Logging:** `approval.requested`, `approval.granted`, `approval.rejected`, `approval.expired`, `approval.self_denied`.

**Tests:** below threshold posts directly; above waits; maker cannot approve own; wrong role cannot approve; double approval only posts once; expiry works.

---

## Adam

### #4 Fraud allow/review/block and end-of-day reconciliation (Tue ~09:00)

**Fraud check.** A function the transfer flow calls *before* money moves:
`assess(transfer, sender_history) -> (decision, reasons)` where decision is `allow`, `review` or `block`.

Signals to choose from (pick 3–5, set thresholds as named constants):

| Signal | Example rule |
|---|---|
| Amount vs history | more than N times the sender's typical transfer |
| Velocity | more than N transfers, or more than X total, in the last M minutes |
| New payee | first-ever transfer to this recipient *and* above an amount |
| Account age | newly created account sending large amounts |
| Rapid drain | transfer would empty most of the balance |
| Odd hours | large transfer at unusual times (careful: false positives) |

Decisions to make: which signals give **review** versus **block**; what a held transfer looks like (status `held`, no ledger entries yet); who resolves a review (a staff role) and through which endpoint; what happens if nobody does.

Guidance: prefer **review** for ambiguous cases. Blocking a real customer counts as damage, and AI Red teams will try to trigger false positives on purpose. Always record the reasons, and log `transfer.review` / `transfer.blocked` so judges and AI defenders can see the control working.

**End-of-day reconciliation.** A check that proves the books are correct. Candidate checks:
- Every transaction's entries sum to zero (double-entry holds).
- The sum of all entries across the ledger is zero.
- No account below its allowed minimum.
- Every ledger transaction for the day has a matching audit-log record, and the audit log's hash chain verifies (with Ethan).
- Counts and totals for the day match between ledger and log.

Decisions: how it is triggered (a staff/admin-only endpoint is simplest and testable; a background scheduler is harder with 2 workers), where results are stored (a `recon_runs` table), what happens on a mismatch (log `recon.mismatch` with details, raise an alert state).

**Tests:** one per fraud outcome; reconciliation passes on clean data and detects a deliberately broken entry.

### #9 Idempotency, limits and reversals (Tue ~09:00)

**Idempotency.** Networks retry; an attacker replays. The same request must never move money twice.
- The client sends an `Idempotency-Key` header (required on transfer creation).
- Table: key, user, a hash of the request body, the stored response, created time. **Unique on (user, key).**
- Insert it inside the same transaction as the transfer. Same key + same body → return the stored response. Same key + different body → reject (409 or 422). Decide how long keys are kept (24 hours is common).
- Log `transfer.duplicate`.

**Limits.** Decide per-transfer maximum and per-day total (and per account type if you want). Compute "today's total" from the entries **inside the locked transaction**, otherwise parallel requests slip past it. Log `limit.exceeded`.

**Reversals.** Never edit or delete a posted entry. A reversal is a **new transaction with the opposite entries**, pointing to the original. Decide: who may reverse (a staff role, maybe through maker-checker), and prevent reversing twice (unique constraint on "reverses transaction id"). Log `transfer.reversed`.

**Tests:** replay returns same result and moves money once; reused key with different body rejected; limit enforced under parallel requests; double reversal rejected; ledger still sums to zero.

---

## Ethan

### #10 Proposal: lead and submit (Tue 12:00 hard; aim 10:30)

Check the website for required sections and length first; follow them exactly. A structure that usually works:

1. **Overview:** which app, what it does, the team and roles.
2. **Architecture:** components, data flow, a diagram (diagrams may be drawn with tools if declared).
3. **Data model:** the ledger tables and why the balance is derived.
4. **How we meet each brief requirement:** one short section per bullet in the APP04 brief, naming the exact mechanism. Judges compare proposals; precision wins.
5. **Threat model:** STRIDE applied to each step of the transfer flow, as a table: step, threat, impact, control, how we detect it in logs.
6. **Security objectives:** measurable statements (for example "no transfer can overdraw an account under concurrent requests").
7. **Logging and detection:** the contract fields and our action names.
8. **Testing plan:** how we attack our own service before the freeze.
9. **Declarations:** mentor (if any), AI use (editing only).

Process: each owner writes their part from `DECISIONS.md` tonight; you merge, make it consistent, and write the threat model. **Every claim must be true of the frozen app**, since judges check the running service against it.

### #11 Append-only audit log (Tue ~09:00)

**Goal:** a record of every money-relevant event that the app can add to but nobody can quietly change.

**Layers to choose from (combine two):**

| Layer | How | Note |
|---|---|---|
| **Trigger** | A PostgreSQL trigger that raises an error on `UPDATE`, `DELETE` and `TRUNCATE` of the log table | Works even if the app user owns the table |
| **Permissions** | Grant the app only `INSERT, SELECT` on the table | Only works if the app's DB user is not the table owner; check what the platform gives us |
| **Hash chain** | Each row stores `hash = sha256(previous_hash + this row's content)` | Makes tampering *detectable*: changing any row breaks every hash after it. Adam's reconciliation verifies it. |

**Decide:** which events are recorded (transfer created, held, approved, rejected, reversed, recon run ...), which fields, and how concurrent inserts get the right previous hash (take a lock on insert, or chain per day).

**Tests:** insert works; update, delete and truncate fail; altering a row is detected by verification.

### #12 Review and attack our own service (Tue 06:00–11:00)

**Reviews (all night):** for each PR touching money, auth or the log, check: ownership scoping on every query, input models with `extra="forbid"`, locks on money paths, no secrets or tokens logged, specific `audit.action` names, tests present.

**Attack list (Tuesday morning, against `docker compose up`):**

| Attack | What to try | Expected |
|---|---|---|
| IDOR | Log in as customer A, request B's account and transfer IDs | 404 |
| Race | 50 parallel transfers draining one account | Never negative; ledger sums to zero |
| Amounts | `0`, `-100`, `1e20`, `"abc"`, `0.001`, same-account transfer | Rejected |
| Replay | Same `Idempotency-Key` twice; same key with a new body | Once only; second rejected |
| Maker-checker | Maker approves own; customer approves; two approvals at once | Denied; posts once |
| Auth | Expired token, tampered token, `alg: none`, brute-force login | Rejected; lockout and logs |
| Mass assignment | Extra fields like `"balance"`, `"role"`, `"status"` | Rejected |
| Injection | SQL meta-characters in every field | No errors leak; parameterised queries hold |
| Log tampering | Try to update or delete audit rows | Fails; chain detects |

Tools: Burp Suite or ZAP for manual testing, `sqlmap` and `ffuf` for automation, and a short Python script with threads for the race test.

**File every finding** as an issue assigned to the owner, label `security`, and re-test the fix.

**Event prep:** an incident report template (time, source IP, technique and MITRE ATT&CK ID, endpoint, evidence log lines, response) and ready-made log queries (failed logins by IP, denied transfers by user, review/block spikes).
