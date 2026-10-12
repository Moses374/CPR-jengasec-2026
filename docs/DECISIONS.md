# Design decisions (APP04 Payment Processing)

The team writes the answers here. Each owner answers their section, the whole team agrees, and then the answers feed straight into the proposal and the code.

Status per question: `open` → `agreed`.

## Brief (security focus)

- Double-entry ledger; balance derived, never a mutable field
- Atomic transfers, provably safe under concurrent requests
- Idempotency, server-side limits, and a fraud allow/review/block
- Maker-checker above a threshold; reversals as new entries
- Append-only log that reconciles at end of day

---

## Moses: ledger core

1. What tables hold accounts, transactions and entries? What columns, and which constraints?
2. How is a balance calculated without a stored balance field? How do we keep it fast enough?
3. How does a transfer stay atomic when two requests hit the same account at once? (Name the exact mechanism.)
4. How are amounts stored (type, currency, rounding)?
5. What seed data (made-up) do we ship: accounts, users, opening balances?
6. Platform: which database settings does JengaSec inject? Exact freeze time on our team page?

## Kathy (with Moses on maker-checker): access and approval

1. What roles exist and what can each one do?
2. How do users log in: password storage, token type, expiry, logout?
3. How is ownership checked so a customer can only touch their own accounts and transfers?
4. Lockout and rate limiting: thresholds, duration, and how we avoid locking out real customers?
5. Maker-checker: above what amount? Who can approve? Can the maker approve their own request? What happens to requests nobody approves, and when?

## Adam: controls

1. How do idempotency keys work: who sends them, what scope, how long kept, what happens on a repeat with a different body?
2. What are the limits (per transfer, per day, per account type), and where are they enforced?
3. How does a reversal work as a new entry? Who can trigger it? Can a reversal be reversed?
4. Fraud: which signals do we check (amount, velocity, new payee, time, ...)?
5. What sends a transfer to **allow**, **review** or **block**? What happens to a transfer under review?
6. End-of-day reconciliation: what is compared with what? Who or what triggers it? What happens on a mismatch?

## Ethan: security and the log

1. What does the append-only log record, and how do we make it impossible to edit or delete rows (database permissions, triggers, hash chain, ...)?
2. Threat model: for each step of a transfer, what are the threats (STRIDE) and which control above stops each one?
3. Which `action` names do we log for every security event (`transfer.denied`, `transfer.review`, `approval.granted`, ...)?
4. Which attacks will we try on our own service on Tuesday morning?

### Answers

Drafted by Ethan on 12 Oct, grounded in the code and in Moses's decisions. Everything is `open` until the team agrees. Where an answer relies on another owner, it says who, so a change in their section shows up here. Code: `app/audit_log.py`, `migrations/versions/0003_audit_log.py`, `tests/test_audit_*.py`, `tests/attack/`, `scripts/race_transfers.py`.

**Q1 Append-only log: `open`**

Two append-only tables and one copy outside the database
- `entries` (Moses, migration 0002) is the money. A mistake is fixed by a reversal, never by an UPDATE.
- `audit_log` (Ethan, migration 0003) is who did what, when, from where, and with what outcome.
- The JSON request line on stdout (`app/observability.py`) is the third record and the only one outside the database.
- Workflow tables such as `transfer_requests` may change status, but every change is mirrored by an `audit_log` row, so history survives.

What a row holds

| Column | Notes |
|---|---|
| `seq` | Gapless. Assigned as head + 1 under the chain lock, not from a sequence (sequences skip numbers on rollback). A gap can only mean a deleted row. |
| `ts` | Database clock, read under the lock. A trigger rejects any value more than 30 s in the past or 5 s ahead, so nobody can backdate an event. |
| `user_id`, `role`, `src_ip` | Who. Plain text, not foreign keys: a failed login has no user, and a change to `users` must never block or alter the log. `src_ip` is `request.client.host`; `X-Forwarded-For` is not trusted (question O3). |
| `action`, `outcome` | Action from the vocabulary in Q3. Outcome is `ok`, `denied` or `error`. |
| `object_type`, `object_id` | What it was about: `transfer_request`, `account`, `approval`, ... |
| `details` | JSONB with allowlisted keys only (`DETAIL_KEYS`): reason code, amounts in cents, ids, rule ids. Unknown keys are dropped and listed as `dropped_keys`. No floats. |
| `prev_hash`, `row_hash` | The SHA-256 chain (layer 3). |

Never logged, in any log: passwords, password hashes, tokens, request bodies, full idempotency keys (store `key_hash`), the username of a failed login for an unknown user (store `username_hash`, because people paste passwords into the username field).

How it is written
- Money and approvals: `audit_log.append(db, ...)` inside the request's transaction, as step 7 of Moses's lock order ("audit log row, always last, held briefly"), then commit. If it raises, the transfer rolls back. So there is **no ledger change without an audit row**.
- Denials, and any event where the money transaction is gone: `audit_log.record(...)`, its own short transaction, best effort. If it fails it logs `auditlog.write_failed` (error type only, never the SQL or its parameters) and the request carries on; the stdout line still holds the action.
- Both calls also set the action on the request log line, so the two records cannot disagree.
- The seed migration (Moses) can write through the same function with the migration's connection: `append(op.get_bind(), action="seed.loaded", ...)`.

Five layers, each with a test that makes it fire on its own

| # | Layer | Mechanism | Stops | Test |
|---|---|---|---|---|
| 1 | Privileges | `UPDATE, DELETE, TRUNCATE` revoked from `PUBLIC` and from the connecting user. | Plain DML from SQL injection or a bug. | Runs as a non-superuser owner, the likely platform case. |
| 2 | Triggers | `reject_modification()` (Moses's function, `LG002`) on UPDATE, DELETE and TRUNCATE. Still holds after the owner grants itself the privilege back. | The same, from an owner who undid layer 1. | `test_layer_2_...` |
| 3 | Chain | A `BEFORE INSERT` trigger takes the advisory lock and accepts only `seq = head + 1`, `prev_hash = head hash` and a database-clock `ts` (`AU001`, `AU002`). `verify_chain()` recomputes every hash **in Python**, outside the database's own logic. | Forks, gaps and backdating are refused. Edits, deletes and reordering are detected, even by an owner who switched the triggers off. | `test_the_chain_trigger_...`, `test_an_edited_row_is_found` |
| 4 | Anchor | `anchor()` writes `auditlog.anchor seq=... row_hash=...` to the platform logs after a commit. Call sites to wire: every reconciliation run (Adam), startup in `app/run.py` (Moses), and the verify endpoint. `verify_chain(expected_head=...)` compares. | Rows removed from the end, and a full rewrite with recomputed hashes. No chain can show either by itself. | `test_rows_cut_from_the_end_...`, `test_a_full_rewrite_...` |
| 5 | Controls check | `check_controls()` reports missing or disabled triggers and re-granted privileges. Reconciliation logs `auditlog.controls_disabled`. Code rules: no string-built SQL (Moses's `test_sql_safety.py`), no `UPDATE` or `DELETE` on `audit_log` anywhere in `app/`. | An attacker who quietly switches protections off. | `test_the_controls_...` |

Limits, stated plainly (for the proposal)
- A database owner or superuser can still change data. We cannot prevent that; we detect it (layers 3 to 5) and prove it from anchors held outside the database. This is the same residual risk Moses states for the ledger.
- The chain is a plain SHA-256 chain, not keyed. A key would have to live in the database (it is snapshotted and both workers must share it), so it would not stop anyone who can write the database. The anchor outside the database does that job, and it depends on the platform keeping stdout (question O2).
- Removing the tail or rewriting the whole chain is only provable if the anchors survive. Reconciliation must read the last anchor from the logs, not from the database.

What reconciliation (Adam) calls: `verify_chain(db, expected_head=last_anchor)`, `check_controls(db)`, `anchor()` after the commit. And one cross-check: every posted `transfer_requests` row has an audit row whose `object_id` is its id and whose `details.amount_cents` equals the entries (Moses: "reconciliation checks posted entries against it").

**Q2 Threat model: `open`**

Assumptions. The attacker is a Red team with network access to port 8080 and the public `/openapi.json`, possibly holding one or more customer logins. They cannot see the repo, the image, the database or the container. A staff account that misuses its power is also in scope, because that is what maker-checker is for. Assets, in order: money in the ledger, integrity of the record, customer data, availability. Platform facts that shape the controls: two worker processes (nothing kept in Python memory is shared), and the database is snapshotted at freeze.

```
client -> [1 request in] -> [2 authenticate] -> [3 authorize + ownership] -> [4 validate]
       -> [5 idempotency] -> [6 limits] -> [7 fraud] -> [8 maker-checker routing]
       -> [9 lock debited accounts, check, post entries] -> [10 audit row, commit] -> response
later: [11 reversal]   [12 end-of-day reconciliation]
```

S spoofing, T tampering, R repudiation, I information disclosure, D denial of service, E elevation of privilege. "Test" refers to the attacks in Q4. Controls marked (decided) are in Moses's section or already in his code; the rest are proposals for the owner named.

| ID | Step | STRIDE | Threat | Control | Owner | Test |
|---|---|---|---|---|---|---|
| T1 | 1 Request | D | Huge body, huge page size or slow requests exhaust the container. | Body limit (proposal 16 KB, 413 over it), page size max 100, `lock_timeout` 3 s, `statement_timeout` 10 s, pool timeout 5 s (decided). | Moses, Kathy | A15 |
| T2 | 1 Request | I | Errors leak stack traces, SQL or versions. | Platform plumbing (no server header, 422 without input echo) plus a catch-all 500 that returns a generic body and logs `app.error`. | Moses | A14 |
| T3 | 2 Auth | S | Brute force and credential stuffing on login. | Slow password hash (argon2), lockout counters in PostgreSQL (not memory: two workers), per-IP throttle. | Kathy | A6 |
| T4 | 2 Auth | S | Forged, tampered, expired or post-logout token. | Opaque token whose hash is stored in a `sessions` table (shared by both workers, real logout, role read from the DB on every request). If JWT: secret stored in the DB, algorithm pinned, denylist for logout. | Kathy | A5 |
| T5 | 2 Auth | I | Account enumeration by error text or response time. | One generic 401 for unknown user and wrong password. Verify a dummy hash for unknown users so timing matches. | Kathy | A6 |
| T6 | 2 Auth | D | An attacker locks real customers out on purpose. | Temporary lockout with backoff, keyed on username and IP first. Never permanent. | Kathy | A6 |
| T7 | 3 Authz | E | A customer calls a staff endpoint, or a new route ships without a check. | A role dependency on every route, default deny. `tests/attack` walks `/openapi.json` and fails if any route answers a caller with no token with anything but 401. | Kathy | A18 |
| T8 | 3 Authz | E, I | IDOR: one customer reads or spends from another's account, request or approval. | Every query is scoped to the caller. Foreign ids return 404, not 403. UUID ids (decided). | Kathy | A3 |
| T9 | 3 Authz | E | Mass assignment: `owner_id`, `role`, `status`, `balance` in a body. | Pydantic models with `extra="forbid"`; input models separate from DB models (TASKS convention). | All | A8 |
| T10 | 4 Validate | T | Zero, negative, fractional, `1e30`, `NaN`, unicode-digit or overflowing amounts. | Amount is a string matching `^(0\|[1-9][0-9]{0,9})\.[0-9]{2}$`, stored as BIGINT cents, minimum 1.00 KES, DB `CHECK`s (decided). | Moses | A7 |
| T11 | 4 Validate | T | Self-transfer, frozen or closed account, system account, wrong currency. | `CHECK (from <> to)` and the insert trigger: customer accounts only, source active, destination not closed (decided). | Moses | A7 |
| T12 | 4 Validate | T | SQL injection and log injection through free text, query or path parameters. | Bound parameters only, enforced by `test_sql_safety.py` (decided). UUID-typed path params, memo max 140 chars. Action names are literals from a fixed list, enforced by `test_audit_actions.py`, so no attacker text reaches the action field. | All; Ethan reviews | A13 |
| T13 | 5 Idempotency | T, R | A retry, or a replay by an attacker, pays twice. | Required `Idempotency-Key`, unique on (user, key), stored response returned on repeat. | Adam | A2 |
| T14 | 5 Idempotency | T | Same key, different body (swap amount or recipient). | Store a hash of the body; mismatch is rejected (409 or 422) and logged `idempotency.conflict`. | Adam | A2 |
| T15 | 5 Idempotency | T | 50 parallel requests with one key all pass "not seen yet". | `INSERT ... ON CONFLICT` first in Moses's lock order; the others wait or fail until the first commits. | Adam, Moses | A2 |
| T16 | 5 Idempotency | D | Key spam fills the table. | Key max 64 chars, only for logged-in users, pruned after 24 h, rate limited. | Adam | A15 |
| T17 | 6 Limits | T | Daily limit beaten by parallel requests (check, then act). | Daily total read after the account locks, in the same transaction (lock order step 4). Limits come from the DB, not the request. | Adam, Moses | A9 |
| T18 | 6 Limits | T | Splitting into many transfers just under a limit or the approval threshold. | Rolling-window sum and count feed the limit and a fraud velocity rule. | Adam | A9 |
| T19 | 7 Fraud | I | The attacker learns the rules by probing. | Review and block answer with a generic code. Rule ids go only into `audit_log.details`. | Adam | A9 |
| T20 | 7 Fraud | E | A customer releases their own held transfer. | Only an approver releases; the checker is never the maker. | Kathy, Adam | A4 |
| T21 | 8 Maker-checker | E | The maker approves their own request. | `CHECK (checker_id <> maker_id)` and a trigger that needs a checker to post a pending approval (decided), plus the role check in code. | Moses, Kathy | A4 |
| T22 | 8 Maker-checker | T | Approve one thing, execute another. | Amount, accounts and maker are immutable by trigger. The approval body carries `request_id` and `expected_amount`; a mismatch is 409 `approval.mismatch`. Funds and limits are re-checked at posting under lock (decided). | Moses, Kathy | A11 |
| T23 | 8 Maker-checker | T | Two checkers approve at once and it posts twice. | Conditional `UPDATE` that must change exactly one row; terminal states are final by trigger (decided). | Moses, Kathy | A11 |
| T24 | 8 Maker-checker | D | Requests nobody decides pile up. | `expires_at` is part of the balance calculation (no scheduler, works with two workers); expired requests cannot be approved; max 5 open per account (decided). | Moses | A11 |
| T25 | 9 Posting | T | Double spend: concurrent transfers each see enough balance. | Lock debited accounts sorted by id with `FOR NO KEY UPDATE`, READ COMMITTED pinned, checks after the locks; overdraft backstop trigger `LG004` (decided). | Moses | A1 |
| T26 | 9 Posting | T | A half-written or unbalanced transaction. | One transaction; deferred triggers `LG001` and `LG003`; `SET CONSTRAINTS ALL IMMEDIATE` before the audit row (decided). | Moses | A16, A20 |
| T27 | 9 Posting | T | Entries edited or deleted to hide theft. | Moses's append-only triggers on `entries`, plus the layers in Q1. | Moses, Ethan | A12 |
| T28 | 9 Posting | D | A hot account's lock queue stalls the service. | Credits take no lock, so a flood into a victim's account cannot stall it. `lock_timeout` 3 s gives 503 `ledger.lock_timeout`; one retry on deadlock (decided). | Moses | A15 |
| T29 | 9 Posting | D | Thousands of tiny entries slow one balance. | Minimum 1.00 KES, rate limits, daily caps, covering index (decided). | Moses, Adam | A15 |
| T30 | 9 Posting | I | Errors or listings expose other balances or the system account. | Errors mention only the caller's own source account. System balances hidden from customers (decided). | Moses | A7 |
| T31 | 10 Audit | R | A user denies making a transfer. | Audit row in the same transaction: user, role, IP, time, chained. | Ethan | A12 |
| T32 | 10 Audit | T | The audit log is edited or deleted. | The five layers in Q1. | Ethan | A12 |
| T33 | 10 Audit | I | Secrets end up in logs. | Allowlisted `details` keys, a never-log list, `test_audit_actions.py` flags unknown keys, and a sweep of logs and responses after the attack run. | Ethan | A19 |
| T34 | 11 Reversal | T | The same transfer is reversed twice. | `reverses_id UNIQUE` (decided). Reversal of a reversal rejected and the amount taken from the original (Adam's validation). | Adam | A10 |
| T35 | 11 Reversal | E | A customer claws money back. | Staff only; proposal: a teller requests and an approver approves. | Adam, Kathy | A10 |
| T36 | 12 Reconciliation | T | An imbalance or deleted row stays hidden. | Compare ledger, requests and audit log; verify the chain against the last anchor from the logs; run `check_controls()`. A mismatch alerts and never self-heals. | Adam, Ethan | A16 |
| T37 | 12 Reconciliation | D | Heavy runs triggered on purpose. | Staff only, one run at a time, `verify_chain` capped at 10,000 rows per call and rate limited. | Adam | A15 |
| T38 | any | T | An attacker with injection or owner rights switches off triggers. | No string-built SQL (test), `check_controls()` at startup and in reconciliation, anchors in the logs. | Moses, Ethan | A12, A13 |

In one line each, for the proposal
- **S**: slow hashing, lockout in the database, opaque server-side tokens.
- **T**: row locks, one transaction, deferred constraint triggers, idempotency, append-only entries and log.
- **R**: a hash-chained audit row written in the same transaction as the money.
- **I**: 404 for foreign objects, generic errors, generic fraud answers, no secrets in logs.
- **D**: body, page and time limits, derived expiry, no lock on credits, one reconciliation at a time.
- **E**: default-deny roles, owner-scoped queries, maker is never checker.

**Q3 Action names: `open`**

Rules
1. Format is `area.event`, optionally `area.event.qualifier`; lowercase.
2. One action per request, set where the decision is made, as a **string literal**. Every deny path sets one; no silent 4xx.
3. ★ means the event is also written to `audit_log`. Reason codes (`insufficient_funds`, `self_approval`, ...) go in `audit_log.details`; the stdout line carries only the action.
4. The vocabulary is `ACTIONS` in `app/audit_log.py`. `tests/test_audit_actions.py` fails the build on an unknown or computed name, and on an unknown `details` key. To add a name, add it there and here.
5. Names the owners already chose in `TASKS.md` are kept. When a handler sets none, the request-log filter falls back to `http.request`, `auth.unauthenticated` (401), `authz.denied` (403), `http.not_found`, `input.rejected` (422), `ratelimit.hit` (429), `http.error` (5xx).

| Area | Action | When | Level |
|---|---|---|---|
| auth | `login.ok` ★ | Login succeeded (then `audit.user(id)`) | info |
| auth | `login.failed` ★ | Wrong password or unknown user, same name for both | warn |
| auth | `login.locked` ★ | Lockout starts, or an attempt while locked | warn |
| auth | `login.logout` ★ | Token revoked | info |
| auth | `token.invalid` | Token present but expired, unknown or revoked | warn |
| access | `authz.denied` ★ | Role not allowed on the route | warn |
| access | `authz.ownership_denied` ★ | Object exists but is not the caller's (client sees 404) | warn |
| access | `account.read_privileged` ★ | Staff reads an account they do not own | info |
| access | `auditlog.read` ★ | Someone reads the audit log or runs verify | info |
| input | `input.rejected` | Validation failed | info |
| input | `ratelimit.hit` ★ | Too many requests | warn |
| transfer | `transfer.created` ★ | Money posted | info |
| transfer | `transfer.denied` ★ | Business refusal: frozen or closed account, not a customer account, ... | warn |
| transfer | `transfer.insufficient_funds` ★ | Not enough available funds | warn |
| transfer | `limit.exceeded` ★ | Per-transfer or daily limit | warn |
| transfer | `transfer.duplicate` ★ | Same key and body, stored response returned | info |
| transfer | `idempotency.conflict` ★ | Same key, different body | warn |
| transfer | `transfer.review` ★ | Fraud says review; held | warn |
| transfer | `transfer.blocked` ★ | Fraud says block | alert |
| transfer | `transfer.pending_approval` ★ | Above threshold, waiting for a checker | info |
| transfer | `transfer.reversed` ★ | Reversal posted | info |
| transfer | `transfer.failed` ★ | System error at posting; hold released | error |
| approval | `approval.requested` ★ | A request enters the queue | info |
| approval | `approval.granted` ★ | Checker approves and it posts | info |
| approval | `approval.rejected` ★ | Checker rejects | info |
| approval | `approval.expired` ★ | Request expired unapproved | info |
| approval | `approval.self_denied` ★ | Maker tried to approve their own request | alert |
| approval | `approval.denied` ★ | Wrong role, already decided, or expired | warn |
| approval | `approval.mismatch` ★ | `expected_amount` differs from the request | warn |
| ledger | `ledger.invariant_violation` ★ | A database trigger refused a posting | alert |
| ledger | `ledger.controls_disabled` ★ | Startup or reconciliation found a ledger trigger missing or off | alert |
| ledger | `ledger.imbalance` ★ | Reconciliation found debits and credits differ | alert |
| ledger | `ledger.lock_timeout`, `ledger.deadlock` | 503 from a lock wait or deadlock | warn |
| recon | `recon.started`, `recon.passed` ★ | Run begins, run is clean | info |
| recon | `recon.mismatch` ★ | Any check failed | alert |
| audit log | `auditlog.chain_ok` ★ | Verify passed | info |
| audit log | `auditlog.chain_broken` ★ | Verify failed (first bad `seq` in details) | alert |
| audit log | `auditlog.controls_disabled` ★ | Audit trigger missing, off, or privilege re-granted | alert |
| audit log | `auditlog.anchor` | Head hash written to the logs | info |
| audit log | `auditlog.write_failed` | An audit row could not be written (stdout only) | error |
| system | `seed.loaded` ★, `app.error` | Seed migration wrote history; unhandled exception | info, error |

**Q4 Attacks on Tuesday morning: `open`**

When and where
- Tonight: the harness exists for everything that does not depend on unwritten features (marked "ready" below).
- Tue 06:00 to 09:00: attack each feature as it lands, P1 first. Moses's feature freeze is 09:00; after that only fixes for these findings merge.
- Fix pull requests merged by about 10:30 so Moses can push the final tag and see **Healthy** by 11:00 (his plan in `TASKS.md`). 11:00 to 13:00 is buffer; the freeze is 13:00.
- Always against our own `docker compose up --build`, never against the platform deployment before the freeze (the database is snapshotted at freeze; test data would be in it).
- Run: `docker compose up --build -d`, then `ATTACK_BASE_URL=http://localhost:8080 python -m pytest tests/attack -q`, and `python scripts/race_transfers.py --help`. Database tests: `REQUIRE_DB=1 python -m pytest`.
- Every finding becomes a GitHub issue assigned to the owner with the label `security`, with the request, the response and the fix commit. That is also our Supporting Evidence.

| # | Pri | Attack | How | Pass means | Where |
|---|---|---|---|---|---|
| A1 | P1 | Double spend | Account with funds for 1; 50 parallel transfers, different keys. | Exactly 1 posts; balance never negative; ledger sums to zero. | `scripts/race_transfers.py` (ready); Moses's DB proof tests |
| A2 | P1 | Idempotency abuse | 50 parallel POSTs with one key; same key with a different body; user B reuses user A's key. | One transfer; identical replies; mismatch rejected; keys are per user. | `race_transfers.py --same-key` (ready) |
| A3 | P1 | IDOR | As customer A, read and spend with B's account, request and approval ids. | 404 every time, no data. | Write when Kathy's auth lands |
| A4 | P1 | Self-approval | Maker approves own request; two approvers at once; customer calls approve. | Denied; posts once. | Moses's trigger tests (done); HTTP test to write |
| A12 | P1 | Log tamper | UPDATE, DELETE, TRUNCATE on `audit_log`; edit, delete, rewrite a row as owner; verify. | Refused, or found by `verify_chain`; anchor catches tail and rewrite. | `tests/test_audit_log_db.py` (ready) |
| A18 | P1 | Default deny | Walk `/openapi.json`; call every route with no token and with garbage tokens. | 401 everywhere, nothing leaks. | `tests/attack/test_attack_surface.py` (ready) |
| A5 | P2 | Token attacks | Garbage, truncated, expired, post-logout, tampered tokens. | 401 always. | Garbage part ready; rest when auth lands |
| A6 | P2 | Login abuse | 20 wrong passwords; compare errors and timing for unknown versus real user; check unlock. | Lockout, generic error, similar timing, lock ends. | Write with Kathy |
| A7 | P2 | Amount abuse | `0`, `-1`, `0.001`, `1e3`, `NaN`, `1e30`, `"１００"`, self-transfer, closed destination. | 422 each time, no ledger change. | Write with Moses's endpoint |
| A8 | P2 | Mass assignment | Extra fields `owner_id`, `role`, `status`, `balance` on every POST. | 422, nothing stored. | Write with endpoints |
| A9 | P2 | Limit evasion | Daily limit by parallel requests; many transfers just under the limit; probe fraud rules. | Limit holds; velocity rule fires; replies reveal no rule names. | `race_transfers.py` plus Adam's rules |
| A10 | P2 | Reversal abuse | Reverse twice in parallel; reverse a reversal; customer reverses; bigger amount in the body. | One reversal; amount from the original. | Write with Adam |
| A11 | P2 | Approval races | Approve twice at once; approve after expiry; approve when funds are gone. | One posting; clean failures. | Moses's DB tests (done); HTTP test to write |
| A13 | P2 | Injection | `' OR 1=1--`, `;DROP TABLE`, CRLF and unicode in memo, username, filters, path ids. | No 500, no split log line, no stored payload used as SQL. | `test_sql_safety.py` (static, done); live part when endpoints exist |
| A14 | P2 | Error leakage | Malformed JSON, wrong types, invalid UUID, wrong method. | No trace, no server header, no echoed input. | `tests/attack` (ready) |
| A15 | P2 | Resource abuse | 2 MB body, `limit=1000000`, 200 parallel requests on one account, spam verify. | 413 or 422, capped page, no deadlock, verify rate limited. | Body part ready; rest with endpoints |
| A16 | P2 | Reconciliation | In a test DB break things (unbalanced entry, deleted audit row, edited entry); run it; then run it clean. | Each break flagged with detail; clean run passes. | Write with Adam |
| A17 | P3 | Rate-limit bypass | Spoof `X-Forwarded-For`; `Admin` versus `admin`; trailing spaces; look-alike unicode. | Limit still applies per account. | Write with Kathy |
| A19 | P3 | Secrets sweep | After all attacks, grep container logs and responses for test passwords and tokens. | Zero hits. | To write |
| A20 | P3 | Crash consistency | `docker kill` the app during the A1 load; restart; reconcile. | Passes; no half transfers. | Manual |

Triage: a failed P1 blocks the merge; a failed P2 gets an issue for the owner; P3 is best effort.

**What the threat model needs from the other sections: `open`**

| From | Must be true |
|---|---|
| Moses | The audit row is written last, before commit, by `audit_log.append(db, ...)` (agreed in his lock order). The seed migration writes its history through `append(op.get_bind(), ...)`. A request body size limit. Migration number: `0003` is the audit log; Kathy's auth revision takes the next free number, and whoever merges second changes `down_revision`. |
| Kathy | A role dependency on every route, default deny. Owner-scoped queries, 404 for foreign ids. Sessions or the token secret in the database (two workers, snapshot at freeze). Role read from the DB. Lockout and rate counters in the DB. Seed users have random passwords, no `admin/admin`. |
| Adam | `UNIQUE (user, key)` plus a stored body hash. Limits read after the account lock. A rolling window, not only per transfer. No reversal of a reversal; amount taken from the original. Generic answers for review and block. Reconciliation uses `verify_chain`, `check_controls` and `anchor` as in Q1. |
| Everyone | Parameterised SQL only. `extra="forbid"` on input models. Log through `audit_log.append` or `record`, or `audit.action`, with a literal name from Q3. Never log a secret. |

Reviewer checklist for Ethan, every security-critical pull request
1. Does every new route have a role dependency and an owner filter?
2. Any SQL built from strings, or `text()` with formatting? (`test_sql_safety.py` also checks.)
3. Does every deny path set an action from Q3, and does a money path write its audit row last?
4. Is money logic in one transaction, locks before checks, in Moses's lock order?
5. Any `UPDATE` or `DELETE` on `entries` or `audit_log`?
6. Do new input models forbid extra fields? Are amounts integers in cents, never floats?
7. Anything secret in logs, errors or test fixtures?
8. Does a migration edit an old revision (not allowed) instead of adding a new one, and does the revision chain still have a single head?

**Security questions for the organisers: `open`** (add to the README list; the credentials, persistence and reset questions are already there)
- **O1.** Which database user do we get? Is it a superuser or the table owner, and can it `CREATEROLE`? (Decides whether layer 1 and Moses's `NOLOGIN` owner idea are possible; we test as a plain owner either way.)
- **O2.** Is stdout collected and kept outside our container, and for how long? (The anchors in layer 4 depend on it.)
- **O3.** Behind the platform's proxy, which `src_ip` do we see? Is `X-Forwarded-For` set, and can a client forge it? (Kathy's per-IP throttle and the audit `src_ip` depend on it.)

## API (all, agreed together)

List every endpoint: method, path, who can call it, request, response.

Status: `open`. **Draft by Ethan** for the team to edit; the first merged edit wins and the others rebase. Prefix `/api/v1` matches `tests/test_platform.py`. Roles are proposals from the `TASKS.md` examples and Moses's seed (customer, teller, approver, auditor, admin); Kathy owns the final list. "Staff" means teller, approver, auditor or admin.

Conventions
- JSON only, UUID ids. `amount` is a string with exactly 2 decimals (`"100.00"`), never a number (Moses, Q4).
- Money-moving POSTs need an `Idempotency-Key` header (max 64 chars).
- Errors are `{"error": "<code>"}`; 422 adds `details` of where and why, never the input. A caller who may not see an object gets 404.
- Lists take `limit` (max 100) and `cursor`.
- There is no registration, password reset or user-management endpoint. Users come from the seed migration: less attack surface, less to build.

| Method | Path | Role | Purpose | Request, response |
|---|---|---|---|---|
| GET | `/healthz`, `/readyz`, `/openapi.json` | public | Platform checks and schema | 200; `/readyz` 503 if the DB is down |
| POST | `/api/v1/auth/login` | public | Log in | `{username, password}` gives 200 `{access_token, token_type, expires_in}`; 401 generic; 429 locked or throttled |
| POST | `/api/v1/auth/logout` | any logged in | Revoke the current token | 204 |
| GET | `/api/v1/me` | any logged in | Who am I | 200 `{user_id, username, role}` |
| GET | `/api/v1/accounts` | customer (own); staff (all, system accounts for auditor and admin only) | List accounts with derived balance | `limit`, `cursor` give 200 `{items:[{id, name, status, posted, available}], next_cursor}` |
| GET | `/api/v1/accounts/{account_id}` | owner; staff | One account | 200; 404 |
| GET | `/api/v1/accounts/{account_id}/entries` | owner; staff | Statement (posted entries and open holds) | `limit`, `cursor`, `from`, `to` give 200 `{items, next_cursor}` |
| POST | `/api/v1/transfers` | customer, from own account | Create a transfer request; it posts, waits for approval, is held for review, or is blocked | `Idempotency-Key`; `{from_account_id, to_account_id, amount, memo?}` gives 201 `{id, status:"posted"}`; 202 `{id, status:"pending_approval"}` or `"held_review"`; 200 replay; 403 `declined`; 404; 409 key in flight; 422 invalid, insufficient funds, limit; 429 |
| GET | `/api/v1/transfers` | customer (own); staff (all) | List transfer requests | `status`, `limit`, `cursor` give 200 `{items, next_cursor}` |
| GET | `/api/v1/transfers/{request_id}` | maker; staff | One request with its status | 200; 404 |
| GET | `/api/v1/approvals` | approver | Queue of requests waiting for a checker or a review, never your own | `limit`, `cursor` give 200 `{items, next_cursor}` |
| POST | `/api/v1/approvals/{request_id}/approve` | approver, not the maker | Approve; it posts in the same transaction | `Idempotency-Key`; `{expected_amount}` gives 200 `{status}`; 403 own request; 404; 409 mismatch, decided or expired; 422 funds gone |
| POST | `/api/v1/approvals/{request_id}/reject` | approver, not the maker | Reject | `{reason}` gives 200 `{status}`; 403; 404; 409 |
| POST | `/api/v1/transfers/{request_id}/reversals` | teller (request); approver (approves) | Reverse a posted transfer with new opposite entries; Adam decides whether this goes through maker-checker | `Idempotency-Key`; `{reason}` gives 202 `{approval_id}`; 404; 409 already reversed, or is itself a reversal |
| POST | `/api/v1/reconciliation/runs` | admin | Start a run (the end-of-day trigger is Adam's decision) | `{business_date}` gives 202 `{run_id}`; 409 already running |
| GET | `/api/v1/reconciliation/runs`, `/api/v1/reconciliation/runs/{run_id}` | auditor, admin | Runs and the result of one | 200 `{status:"passed" or "mismatch", checks, mismatches}`; 404 |
| GET | `/api/v1/audit-log` | auditor | Read the audit log (read-only) | `before_seq`, `action`, `user_id`, `limit` give 200 `{items}`; wraps `audit_log.list_events` |
| GET | `/api/v1/audit-log/verify` | auditor | Recompute the hash chain and compare with the last anchor | `from_seq`, `limit` (max 10,000) give 200 `{ok, checked, first_bad_seq?, reason?}`; wraps `audit_log.verify_chain` |
