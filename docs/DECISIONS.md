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

### Adam's proposal (pending team agreement)

1. Transfer clients must send an opaque `Idempotency-Key` of 1–128 visible ASCII characters. Scope it to the authenticated user; retain its SHA-256 request fingerprint and exact response for 24 hours. Reserve the key in the same database transaction as the transfer. A matching key and body returns the saved response; a matching key with a different body returns `409` and does not run the transfer. Fingerprint canonical JSON (sorted keys, compact separators, UTF-8; reject non-JSON values).
2. Use Kenyan shillings (**KES / KSh**) throughout. Store amounts as integer cents (100 cents = KSh 1). Cap a single transfer at **250,000 cents (KSh 2,500)** and posted plus pending/held daily outgoing transfers at **1,000,000 cents (KSh 10,000) per account, UTC day**. Do not vary by account type initially. Check both in the account-row-locked posting transaction; pending transfers reserve daily capacity so concurrent or held requests cannot bypass the cap.
3. Only `approver` and `admin` may request a reversal. In one ledger transaction, create a new transaction referencing the original and copy every original entry with its amount negated. A unique constraint on the reversed transaction ID allows only one reversal; reject reversals of reversal transactions. Reversal requests use the normal maker-checker flow when they exceed its agreed threshold. The ledger remains append-only.
4. Fraud inputs are: amount versus the sender's typical amount, prior transfer count and value in the last 10 minutes, first-time payee, account age, proportion of available funds drained, and UTC hour. All thresholds live as named policy constants. Review signals: at least 5 prior transfers in 10 minutes or KSh 5,000 outgoing in that window including the proposed transfer; at least 5× the sender's typical transfer and at least KSh 500; a new payee and at least KSh 1,000; an account younger than 24 hours and at least KSh 500; draining at least 90% of available funds with a transfer of at least KSh 1,000; or a transfer of at least KSh 1,000 between 00:00 and 04:59 UTC. Block at 10 or more prior transfers in 10 minutes. These are initial event thresholds and should be tuned against tests, not silently changed in code.
5. No signal means `allow`; any review signal means `review` unless the hard velocity block applies; the hard velocity signal means `block`. A review is stored as `held` with its reasons and no ledger entries. An `approver` or `admin` other than the maker can approve or reject it within 24 hours; approval re-runs funds, limit, and fraud checks in the locked posting transaction. Unresolved reviews expire without posting.
6. An `auditor` or `admin` triggers reconciliation through a staff-only endpoint once per UTC business day (and may rerun it). Compare per-transaction entry sums, the global ledger sum, derived balances against each account's minimum, the set of ledger transaction IDs against audit-log transaction IDs, and Ethan's audit hash-chain verification. Persist each result in `recon_runs`. On any mismatch, persist mismatch codes, emit `recon.mismatch`, and leave the run in an alert state; reconciliation never edits ledger entries.

These choices rely on Moses exposing integer-cent ledger entries and account locks, Kathy providing the named staff roles and approval flow, and Ethan exposing audit transaction references plus a hash-chain verifier. Keep this section pending until the team agrees those interfaces and thresholds.

## Ethan: security and the log

1. What does the append-only log record, and how do we make it impossible to edit or delete rows (database permissions, triggers, hash chain, ...)?
2. Threat model: for each step of a transfer, what are the threats (STRIDE) and which control above stops each one?
3. Which `action` names do we log for every security event (`transfer.denied`, `transfer.review`, `approval.granted`, ...)?
4. Which attacks will we try on our own service on Tuesday morning?

## API (all, agreed together)

List every endpoint: method, path, who can call it, request, response.

| Method | Path | Role | Purpose |
| ------ | ---- | ---- | ------- |
|        |      |      |         |
