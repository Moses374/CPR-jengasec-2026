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

### Answers

**Q4 Amounts: `agreed`**
- Stored as `BIGINT` minor units (KES cents). Never floats, never `NUMERIC` (Postgres silently rounds extra decimals on insert).
- API takes and returns amounts as JSON strings with exactly 2 decimals: `^(0|[1-9][0-9]{0,9})\.[0-9]{2}$`. Anything else is rejected with 422; we reject, we never round.
- One `to_cents()` / `from_cents()` pair in `app/ledger.py`. Inside the app every amount, limit and threshold is an `int` in cents (e.g. `APPROVAL_THRESHOLD_CENTS`). Kathy and Adam use the same unit, so no threshold can be bypassed by a unit mismatch.
- Single currency: `currency CHAR(3) CHECK (currency = 'KES')` on accounts. DB backstop on entries: `amount <> 0 AND abs(amount) <= 1000000000000`.

**Q1 Tables: `agreed`** (shared columns of `transfer_requests` still to confirm with Kathy and Adam)
- `accounts` (UUID ids, `owner_id` NULL only for system accounts, `min_balance`, `status`; **no balance column**), `ledger_transactions` (kind, `reverses_id UNIQUE`), `entries` (signed `BIGINT amount`, `UNIQUE (transaction_id, account_id)`).
- Ledger holds only posted money and is immutable: triggers reject `UPDATE`, `DELETE`, `TRUNCATE` (same trigger function as the audit log, with Ethan).
- Every transfer creates a row in a separate `transfer_requests` table (workflow state). The ledger only ever holds posted money.
- No API endpoint can debit a system account; only seed migrations and reversals post to them.
- Moses creates a minimal `users(id, username, created_at)` in `0002`; Kathy extends it with auth columns in her own revision.

**Pending transfers reserve funds (derived holds, no stored field)**
- `available = SUM(entries) − SUM(open requests from the account)`, where open = `status IN ('pending_approval','held_review') AND expires_at > now()`.
- Request creation locks the source account and checks `available`. Posting re-checks funds and limits under lock.
- Expiry is automatic in the calculation (no scheduler, works with 2 workers); every transition out of a pending state also requires `expires_at > now()`. DB clock only.
- Max 5 open requests per source account.
- View `account_activity` = posted entries UNION open holds, for history.

**Request and ledger can never disagree (DB-enforced)**
- `ledger_transaction_id UNIQUE` and `CHECK ((status='posted') = (ledger_transaction_id IS NOT NULL))`.
- Deferred trigger: every `kind='transfer'` ledger transaction has exactly one posted request (no money moves without passing maker-checker and fraud).
- Deferred trigger: a posted request's ledger transaction has exactly two entries, `−amount` on `from_account_id` and `+amount` on `to_account_id`.
- At the end of the seed migration, a trigger is created that rejects any new `kind='opening'` transaction. Reversals (Adam) follow the same match-a-record pattern.

**An approval covers exactly what the checker saw**
1. Trigger: `id, maker_id, from_account_id, to_account_id, amount, memo, created_at` are immutable; no DELETE or TRUNCATE.
2. Trigger enforces the state machine: `held_review → pending_approval | posted | blocked | expired`; `pending_approval → posted | rejected | expired | failed`; terminal states final; `posted` from `pending_approval` requires `checker_id`.
3. Approval and posting are one DB transaction (no "approved, not yet posted" state). Failure at that point → `failed` with a reason, hold released.
4. Posting reads the amount only from the locked request row. The approval body is `request_id` + `expected_amount`; a mismatch returns 409 (`approval.mismatch`).
5. `CHECK (checker_id <> maker_id)`; checker role verified in code and by trigger; double approval closed by a conditional `UPDATE` that must change exactly 1 row.
6. The audit log records amount and accounts at creation and approval; reconciliation checks posted entries against it.

**Double entry: DB trigger prevents, reconciliation detects**
- Deferred constraint triggers: each transaction's entries sum to zero, and each transaction has at least 2 entries.
- The posting function runs `SET CONSTRAINTS ALL IMMEDIATE` after inserting, so violations surface there; caught, rolled back, logged `ledger.invariant_violation`, client gets a generic 500.
- Every trigger has a test that proves it fires. DB tests run in GitHub Actions with a Postgres service and are required on every PR (they must not silently skip).
- Indexes: `entries(transaction_id)`, `entries(account_id) INCLUDE (amount)`, partial index on open requests by `from_account_id`.
- Owner/superuser bypass: (1) if the platform allows `CREATEROLE`, money tables are owned by a `NOLOGIN` role and the app user gets only the grants it needs; (2) no string-built SQL anywhere (unparameterised `text()` allows stacked statements), enforced by a test and review; (3) startup and reconciliation verify all triggers exist and are enabled (`ledger.controls_disabled`); (4) reconciliation logs ledger totals and the audit chain head to platform logs, an anchor outside the DB.
- Known residual risk (stated in the proposal): a superuser can change data; we cannot prevent that, but we detect it at the next reconciliation and prove it from the logs held outside the DB.

**Q3 Concurrency: `agreed`**
- Mechanism: row locks. Not SERIALIZABLE (contention causes abort storms an attacker can trigger on purpose) and not advisory locks (not tied to rows, easy to get wrong).
- Isolation pinned to READ COMMITTED on the engine (each statement sees what the previous lock holder committed), with a test that asserts it.
- `SELECT … FOR NO KEY UPDATE`, not `FOR UPDATE`: does not conflict with the foreign-key checks Postgres runs on insert, so crossed transfers cannot deadlock through them.
- Lock only accounts being **debited**, sorted by id, via one helper `ledger.lock_accounts(db, ids)`. Credits only raise a balance, so this stays correct, and nobody can stall a victim's account by flooding transfers into it.
- One lock order for every money path:
  1. idempotency key row (Adam, `INSERT … ON CONFLICT`)
  2. the `transfer_requests` row, `FOR UPDATE`, when acting on an existing request (approve, reject, expire)
  3. debited accounts (`lock_accounts`)
  4. checks: balance, holds, limits, fraud, all after the locks
  5. inserts
  6. `SET CONSTRAINTS ALL IMMEDIATE`
  7. audit log row (Ethan): always last, held briefly
  8. commit
- DB overdraft backstop: deferred constraint trigger on each debit entry locks the account and checks `SUM(entries) >= min_balance`, so even a path that forgot to lock cannot overdraw. App locks protect holds and give clean errors (`422`, `transfer.insufficient_funds`).
- Fail fast: `lock_timeout` 3s → 503 + `Retry-After` (`ledger.lock_timeout`); `statement_timeout` 10s; pool timeout 5s; deadlock retried once after full rollback, then 503 (`ledger.deadlock`).
- Proof tests (real Postgres, threads released together): 50 parallel transfers with funds for 10 → exactly 10 succeed; crossed A→B / B→A without deadlock; 20 parallel approvals → one posts; approve vs reject → one wins; parallel holds never exceed available funds; the backstop trigger alone prevents overdraft; isolation level asserted.

**Q2 Balances: `agreed`**
- `posted = SUM(entries.amount)`; `held = SUM(open transfer_requests.amount)` (open = `pending_approval` / `held_review` and `expires_at > now()`); `available = posted − held`.
- Plain derived `SUM` with a covering index `entries(account_id) INCLUDE (amount)` (index-only scans; Postgres 16 autovacuums insert-only tables). Considered and rejected: balance checkpoints (sequence ids are assigned at insert, not commit, so a late commit can be missed forever), materialized views (stale), and a running `balance_after` column (a stored balance in disguise, and it forces locking receivers).
- One definition: Postgres functions `ledger_posted_balance(uuid)` and `ledger_available_balance(uuid)` in `0002`, called by both the overdraft trigger and `app/ledger.py`. They return `bigint` and fail closed on overflow.
- Display reads take no lock; decisions use only balances read inside the locked transaction. Balances are never cached in Python (2 workers).
- Flooding an account with tiny entries to slow its balance down is limited by: minimum transfer 1.00 KES (request model + `CHECK (amount >= 100)` on `transfer_requests`, to confirm with Adam), rate limits (Kathy) and daily caps (Adam), and the 3s lock timeout. A test seeds 200,000 entries on one account and asserts an Index Only Scan under 50 ms.
- Balance and history endpoints are scoped to the owner (404 otherwise). System account balances are hidden from customers; only an auditor/admin role sees them.
- Whole-ledger `SUM(entries) = 0` is checked by reconciliation and logged as part of the anchor outside the DB.

**Q5 Seed data: `agreed`**
- Migration order: `0002` ledger schema (Moses) → auth (Kathy) → audit log (Ethan) → idempotency/fraud/recon (Adam) → **seed last** (Moses). The seed needs Kathy's hash format and roles and Ethan's audit records, so it runs after everyone's schema.
- One system account, `JengaBank Funding`, source of every opening balance; hidden from customers.
- Customers (fictional names only), each there to exercise a control: Amina Wekesa (current 2,500,000.00 + savings 800,000.00: maker-checker, own-account transfers); Brian Otieno (150,000.00: ordinary recipient); Cynthia Mwangi (5,000.00: insufficient funds, rapid drain); David Kiprop (new account, 0.00: new-account fraud signal); Esther Njeri (frozen, 20,000.00: frozen accounts cannot send).
- Staff: 1 teller/operator, 2 approvers (checker ≠ maker, double-approval race), 1 auditor, 1 admin. Role names from Kathy.
- About 30 posted transfers spread over the 14 days before the migration runs, so fraud has a baseline. Every seeded transfer goes through the full path (request, ledger transaction, 2 entries, audit record), so our own triggers check the seed. No pending requests (they would expire before the event days).
- Credentials: random 20+ character password per seed user, generated once locally; only argon2 hashes (Kathy's parameters) go in the migration; plaintext lives in the team password manager, never in the repo or logs; staff credentials are never shared outside the team.
- Fixed UUID literals generated once with `uuid4()`; never patterned ids. Names only, no real personal data. Tests create their own data and never depend on seed balances.
- No transfers against the platform deployment before the freeze (the DB is snapshotted at freeze and restored each event day); test locally with `docker compose`.

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

## API (all, agreed together)

List every endpoint: method, path, who can call it, request, response.

| Method | Path | Role | Purpose |
|---|---|---|---|
| | | | |
