# Design decisions (APP04 Payment Processing)

The team writes the answers here. Each owner answers their section, the whole team agrees, and then the answers feed straight into the proposal and the code. Competition rule: the threat model, architecture and security design are written by us, not AI tools.

Status per question: `open` → `agreed`.

## Brief (security focus)

- Double-entry ledger; balance derived, never a mutable field
- Atomic transfers, provably safe under concurrent requests
- Idempotency, server-side limits, and a fraud allow/review/block
- Maker-checker above a threshold; reversals as new entries
- Append-only log that reconciles at end of day

---

## Adam: ledger core

1. What tables hold accounts, transactions and entries? What columns, and which constraints?
2. How is a balance calculated without a stored balance field? How do we keep it fast enough?
3. How does a transfer stay atomic when two requests hit the same account at once? (Name the exact mechanism.)
4. How are amounts stored (type, currency, rounding)?
5. How do idempotency keys work: who sends them, what scope, how long kept, what happens on a repeat with a different body?
6. What are the limits (per transfer, per day, per account type), and where are they enforced?
7. How does a reversal work as a new entry? Who can trigger it? Can a reversal be reversed?
8. What seed data (made-up) do we ship: accounts, users, balances?

## Kathy: access and approval

1. What roles exist and what can each one do?
2. How do users log in: password storage, token type, expiry, logout?
3. How is ownership checked so a customer can only touch their own accounts and transfers?
4. Lockout and rate limiting: thresholds, duration, and how we avoid locking out real customers?
5. Maker-checker: above what amount? Who can approve? Can the maker approve their own request? What happens to requests nobody approves, and when?

## Moses: controls and operations

1. Fraud: which signals do we check (amount, velocity, new payee, time, ...)?
2. What sends a transfer to **allow**, **review** or **block**? What happens to a transfer under review?
3. End-of-day reconciliation: what is compared with what? Who or what triggers it? What happens on a mismatch?
4. Platform: which database settings does JengaSec inject? Exact freeze time on our team page?

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
