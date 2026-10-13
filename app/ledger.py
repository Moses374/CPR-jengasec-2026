"""Ledger core: amounts, balances, transfers, approvals (docs/DECISIONS.md, Moses section).

Every money function here runs one database transaction in the agreed lock order and commits it:

  1. idempotency key row               INSERT ... ON CONFLICT: a parallel duplicate waits here
  2. the request row                   FOR UPDATE, when acting on an existing request
  3. debited accounts                  lock_accounts(): FOR NO KEY UPDATE, sorted by id
  4. checks: balance, holds, limits, fraud, all after the locks
  5. inserts
  6. SET CONSTRAINTS ALL IMMEDIATE     database invariants fire here, inside our error handling
  7. audit_log.append()                always last, held briefly (global chain lock)
  8. commit

The database (migrations 0002 and 0004) enforces the same rules again, so a bug here cannot move money
that does not exist; these checks exist to give callers clean errors.

Amounts: strings with exactly 2 decimals at the edge, int cents everywhere inside.
"""

import json
import logging
import re
import uuid
from dataclasses import dataclass
from decimal import Decimal

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app import audit_log, controls, fraud, observability

log = logging.getLogger("app.ledger")

AMOUNT_RE = r"^(0|[1-9][0-9]{0,9})\.[0-9]{2}$"
_AMOUNT = re.compile(AMOUNT_RE)
MIN_TRANSFER_CENTS = controls.MIN_TRANSFER_CENTS  # KSh 1.00, same as the CHECK on transfer_requests.amount
OPEN_STATES = ("pending_approval", "held_review")

FRAUD_DECISIONS = ("allow", "review", "block")


# ------------------------------------------------------------------ errors

class LedgerError(Exception):
    """A refusal the caller can show: HTTP status, a stable error code, and the log action."""

    status = 422
    code = "invalid_request"
    action = "transfer.denied"

    def __init__(self, code: str | None = None):
        super().__init__(code or self.code)
        if code:
            self.code = code


class InvalidAmount(LedgerError):
    code, action = "invalid_amount", "input.rejected"


class NotFound(LedgerError):
    # Also used for objects that exist but are not the caller's: never reveal which.
    status, code, action = 404, "not_found", "authz.ownership_denied"


class TransferDenied(LedgerError):
    code, action = "transfer_denied", "transfer.denied"


class InsufficientFunds(LedgerError):
    code, action = "insufficient_funds", "transfer.insufficient_funds"


class ApprovalConflict(LedgerError):
    status, code, action = 409, "conflict", "approval.denied"


class AmountMismatch(ApprovalConflict):
    code, action = "amount_mismatch", "approval.mismatch"


class SelfApproval(LedgerError):
    status, code, action = 403, "self_approval", "approval.self_denied"


class LimitRefused(LedgerError):
    # The code says which limit (per_transfer_limit, daily_limit): limits are not secret.
    code, action = "limit_exceeded", "limit.exceeded"


class IdempotencyConflict(LedgerError):
    status, code, action = 409, "idempotency_conflict", "idempotency.conflict"


class Busy(LedgerError):
    status, code, action = 503, "busy", "ledger.lock_timeout"


class InvariantViolation(LedgerError):
    status, code, action = 500, "internal_error", "ledger.invariant_violation"


# ------------------------------------------------------------------ amounts

def to_cents(amount: str) -> int:
    """'1500.00' -> 150000. Rejects anything that is not exactly 2 decimals; never rounds."""
    if not isinstance(amount, str) or not _AMOUNT.fullmatch(amount):
        raise InvalidAmount()
    cents = int(Decimal(amount) * 100)  # exact: the pattern allows only 2 decimal places
    if cents < MIN_TRANSFER_CENTS:
        raise InvalidAmount("amount_too_small")
    return cents


def from_cents(cents: int) -> str:
    """150000 -> '1500.00'; -150 -> '-1.50'."""
    sign = "-" if cents < 0 else ""
    whole, part = divmod(abs(int(cents)), 100)
    return f"{sign}{whole}.{part:02d}"


# ------------------------------------------------------------------ reading

def posted_balance(db: Session, account_id) -> int:
    return db.execute(text("SELECT ledger_posted_balance(:a)"), {"a": account_id}).scalar_one()


def available_balance(db: Session, account_id) -> int:
    return db.execute(text("SELECT ledger_available_balance(:a)"), {"a": account_id}).scalar_one()


def list_accounts(db: Session, owner_id) -> list[dict]:
    """The caller's own accounts with derived balances (for display only: never feed into a decision)."""
    rows = db.execute(text(
        "SELECT id, name, status, ledger_posted_balance(id) AS posted, ledger_available_balance(id) AS available "
        "FROM accounts WHERE owner_id = :o AND kind = 'customer' ORDER BY created_at, id"
    ), {"o": owner_id}).all()
    return [{"id": str(r.id), "name": r.name, "status": r.status,
             "posted": from_cents(r.posted), "available": from_cents(r.available)} for r in rows]


def get_request(db: Session, request_id, viewer_id) -> dict:
    """One transfer request, visible to its maker only (staff views come with Kathy's roles)."""
    r = db.execute(text(
        "SELECT id, from_account_id, to_account_id, amount, status, created_at, decided_at, expires_at "
        "FROM transfer_requests WHERE id = :r AND maker_id = :u"
    ), {"r": request_id, "u": viewer_id}).first()
    if r is None:
        raise NotFound()
    return {"id": str(r.id), "from_account_id": str(r.from_account_id), "to_account_id": str(r.to_account_id),
            "amount": from_cents(r.amount), "status": r.status, "created_at": r.created_at.isoformat(),
            "decided_at": r.decided_at.isoformat() if r.decided_at else None,
            "expires_at": r.expires_at.isoformat()}


# ------------------------------------------------------------------ writing

@dataclass(frozen=True)
class Actor:
    """Who is acting, for the audit row. role and src_ip come from Kathy's auth and the request."""

    user_id: uuid.UUID
    role: str | None = None
    src_ip: str | None = None


@dataclass(frozen=True)
class Idempotency:
    """A client's Idempotency-Key, stored only as hashes (the raw key never reaches the database)."""

    key_hash: str
    fingerprint: str

    @classmethod
    def from_request(cls, key: str, validated_body: dict) -> "Idempotency":
        # Fingerprint the validated model, not the raw JSON: it describes what will actually run.
        return cls(controls.idempotency_key_hash(key), controls.request_fingerprint(validated_body))


@dataclass(frozen=True)
class TransferResult:
    id: str
    status: str
    replayed: bool = False


def _begin(db: Session) -> None:
    # Fail fast instead of piling up behind a hot account (DECISIONS Q3).
    db.execute(text("SET LOCAL lock_timeout = '3s'"))
    db.execute(text("SET LOCAL statement_timeout = '10s'"))


def lock_accounts(db: Session, account_ids) -> dict:
    """Lock the accounts being debited, always in id order (the only order anyone may use)."""
    ids = sorted({str(a) for a in account_ids})
    rows = db.execute(text(
        "SELECT id, owner_id, kind, status, min_balance, created_at FROM accounts "
        "WHERE id = ANY(CAST(:ids AS uuid[])) ORDER BY id FOR NO KEY UPDATE"
    ), {"ids": ids}).all()
    return {str(r.id): r for r in rows}


def _post_entries(db: Session, actor: Actor, src, dst, cents: int) -> str:
    txn = db.execute(text(
        "INSERT INTO ledger_transactions (kind, created_by) VALUES ('transfer', :u) RETURNING id"
    ), {"u": actor.user_id}).scalar_one()
    db.execute(text(
        "INSERT INTO entries (transaction_id, account_id, amount) VALUES (:t, :s, :neg), (:t, :d, :pos)"
    ), {"t": txn, "s": src, "d": dst, "neg": -cents, "pos": cents})
    return txn


def _ctx(actor: Actor, object_id, object_type: str = "transfer_request") -> dict:
    return {"user_id": actor.user_id, "role": actor.role, "src_ip": actor.src_ip,
            "object_type": object_type, "object_id": object_id}


# Refusals log one of a fixed set of names. Each name is a literal at its call site, so no text from a
# request can ever become an action (tests/test_audit_actions.py enforces it).
_RECORD_REFUSAL = {
    "input.rejected": lambda **kw: audit_log.record(action="input.rejected", **kw),
    "authz.ownership_denied": lambda **kw: audit_log.record(action="authz.ownership_denied", **kw),
    "transfer.denied": lambda **kw: audit_log.record(action="transfer.denied", **kw),
    "transfer.insufficient_funds": lambda **kw: audit_log.record(action="transfer.insufficient_funds", **kw),
    "limit.exceeded": lambda **kw: audit_log.record(action="limit.exceeded", **kw),
    "idempotency.conflict": lambda **kw: audit_log.record(action="idempotency.conflict", **kw),
    "approval.denied": lambda **kw: audit_log.record(action="approval.denied", **kw),
    "approval.mismatch": lambda **kw: audit_log.record(action="approval.mismatch", **kw),
    "approval.self_denied": lambda **kw: audit_log.record(action="approval.self_denied", **kw),
    "recon.started": lambda **kw: audit_log.record(action="recon.started", **kw),
    "ledger.lock_timeout": lambda **kw: audit_log.record(action="ledger.lock_timeout", **kw),
    "ledger.deadlock": lambda **kw: audit_log.record(action="ledger.deadlock", **kw),
    "ledger.invariant_violation": lambda **kw: audit_log.record(action="ledger.invariant_violation", **kw),
}

_MARK_REFUSAL = {
    "input.rejected": lambda: observability.action("input.rejected"),
    "authz.ownership_denied": lambda: observability.action("authz.ownership_denied"),
}


def mark(err: LedgerError) -> None:
    """Name a refusal on the request log line when it happened outside a money transaction.
    Refusals from a money transaction were already named by audit_log.record(); leave those alone."""
    marker = _MARK_REFUSAL.get(err.action)
    if marker:
        marker()


def _record_denial(db: Session, actor: Actor, err: LedgerError, details: dict | None = None) -> None:
    """Denials go to the log in their own transaction, after the money transaction is rolled back
    (so this never waits on a chain lock our own transaction holds)."""
    extra = {"reason": err.code}
    extra.update(details or {})
    _RECORD_REFUSAL[err.action](
        session_factory=sessionmaker(bind=db.get_bind()), outcome="error" if err.status >= 500 else "denied",
        user_id=actor.user_id, role=actor.role, src_ip=actor.src_ip, details=extra)


_SQLSTATE_TO_ERROR = {
    "LG004": InsufficientFunds,
    "LG006": TransferDenied,
    "LG005": ApprovalConflict,
    "55P03": Busy,    # lock_not_available (lock_timeout)
    "57014": Busy,    # query_canceled (statement_timeout)
}


def _error_for(exc: DBAPIError) -> LedgerError | None:
    state = getattr(exc.orig, "sqlstate", None)
    if state == "LG007":
        # the trigger's message is the limit's name (per_transfer_limit / daily_limit)
        message = str(getattr(getattr(exc.orig, "diag", None), "message_primary", "") or "")
        return LimitRefused(message if message in ("per_transfer_limit", "daily_limit") else None)
    if state in _SQLSTATE_TO_ERROR:
        return _SQLSTATE_TO_ERROR[state]()
    if state and state.startswith(("LG", "AU")):
        log.error("ledger.invariant_violation sqlstate=%s", state)
        return InvariantViolation()
    return None


def _run(db: Session, actor: Actor, work):
    """Run work(db) as one transaction; map database refusals to LedgerErrors; retry a deadlock once."""
    for attempt in (1, 2):
        try:
            _begin(db)
            result = work(db)
            db.commit()
            return result
        except LedgerError as err:
            db.rollback()
            _record_denial(db, actor, err)
            raise
        except DBAPIError as exc:
            db.rollback()
            state = getattr(exc.orig, "sqlstate", None)
            if state == "40P01" and attempt == 1:
                log.warning("ledger.deadlock retrying once")
                continue
            if state == "40P01":
                err: LedgerError | None = Busy("busy")
                err.action = "ledger.deadlock"
            else:
                err = _error_for(exc)
            if err is None:
                raise  # unexpected: the app's catch-all returns a generic 500
            _record_denial(db, actor, err, details={"error_code": state})
            raise err from None
    raise AssertionError("unreachable")


# ------------------------------------------------------------------ idempotency (lock order step 1)

def _claim_key(db: Session, actor: Actor, scope: str, idem: Idempotency | None) -> dict | None:
    """Reserve the key, or return the stored response if this user already used it.

    A parallel request with the same key waits on the INSERT until the first one commits
    (then replays its response) or rolls back (then runs itself). The same key with a
    different body is refused and nothing runs.
    """
    if idem is None:
        return None
    params = {"u": actor.user_id, "s": scope, "k": idem.key_hash, "f": idem.fingerprint}
    claimed = db.execute(text(
        "INSERT INTO idempotency_keys (user_id, scope, key_hash, fingerprint) VALUES (:u, :s, :k, :f) "
        "ON CONFLICT DO NOTHING RETURNING 1"
    ), params).first()
    if claimed:
        return None
    prior = db.execute(text(
        "SELECT fingerprint, response FROM idempotency_keys WHERE user_id = :u AND scope = :s AND key_hash = :k"
    ), params).one()
    if prior.fingerprint != idem.fingerprint:
        raise IdempotencyConflict()
    if prior.response is None:  # cannot happen: the response is written in the transaction that made the row
        raise Busy()
    return dict(prior.response)


def _store_response(db: Session, actor: Actor, scope: str, idem: Idempotency | None, result: TransferResult) -> None:
    if idem is None:
        return
    db.execute(text(
        "UPDATE idempotency_keys SET response = CAST(:r AS jsonb) WHERE user_id = :u AND scope = :s AND key_hash = :k"
    ), {"r": json.dumps({"id": result.id, "status": result.status}), "u": actor.user_id, "s": scope,
        "k": idem.key_hash})


def _replay(db: Session, actor: Actor, prior: dict, object_type: str) -> TransferResult:
    audit_log.append(db, action="transfer.duplicate", outcome="ok", details={"status": prior["status"]},
                     **_ctx(actor, prior["id"], object_type))
    return TransferResult(prior["id"], prior["status"], replayed=True)


# ------------------------------------------------------------------ limits and fraud (step 4)

def _check_limits(db: Session, account_id, amount_cents: int, exclude_request=None) -> None:
    used = db.execute(text("SELECT ledger_daily_outgoing(:a, :x)"),
                      {"a": account_id, "x": exclude_request}).scalar_one()
    try:
        controls.check_transfer_limits(amount_cents, used)
    except controls.LimitExceeded as e:
        raise LimitRefused(e.reason if e.reason in ("per_transfer_limit", "daily_limit") else None) from None


_OPEN_OR_POSTED = "(status = 'posted' OR (status IN ('pending_approval', 'held_review') AND expires_at > now()))"


def _assess_fraud(db: Session, src, to_account_id, amount_cents: int) -> fraud.Assessment:
    """Adam's assess(), fed with the sender's history read under the account lock."""
    h = db.execute(text(
        "SELECT "
        " (SELECT percentile_disc(0.5) WITHIN GROUP (ORDER BY amount) FROM ("
        "    SELECT amount FROM transfer_requests WHERE from_account_id = :s AND status = 'posted'"
        "    ORDER BY created_at DESC LIMIT 20) AS recent) AS typical,"
        " (SELECT count(*) FROM transfer_requests WHERE from_account_id = :s"
        "    AND created_at > now() - interval '10 minutes' AND " + _OPEN_OR_POSTED + ") AS n10,"
        " (SELECT COALESCE(SUM(amount), 0) FROM transfer_requests WHERE from_account_id = :s"
        "    AND created_at > now() - interval '10 minutes' AND " + _OPEN_OR_POSTED + ") AS total10,"
        " EXISTS (SELECT 1 FROM transfer_requests WHERE from_account_id = :s AND to_account_id = :d"
        "    AND status = 'posted') AS paid,"
        " GREATEST(0, floor(extract(epoch FROM now() - CAST(:created AS timestamptz)) / 3600))::int AS age_hours"
    ), {"s": src.id, "d": to_account_id, "created": src.created_at}).one()
    return fraud.assess(
        fraud.TransferRisk(amount_cents=amount_cents),
        fraud.SenderHistory(
            typical_transfer_cents=int(h.typical) if h.typical is not None else None,
            prior_transfer_count_10m=int(h.n10),
            prior_transfer_total_cents_10m=int(h.total10),
            recipient_previously_paid=bool(h.paid),
            account_age_hours=int(h.age_hours),
            available_balance_cents=max(0, available_balance(db, src.id)),
        ),
    )


# ------------------------------------------------------------------ transfers

def create_transfer(
    db: Session,
    actor: Actor,
    *,
    from_account_id,
    to_account_id,
    amount_cents: int,
    memo: str | None = None,
    idempotency: Idempotency | None = None,
    fraud_decision: str | None = None,
) -> TransferResult:
    """Move money from the caller's own account, or route it to approval, review or block.

    fraud_decision: None runs Adam's assess() (production); tests may force allow/review/block.
    """
    if fraud_decision is not None and fraud_decision not in FRAUD_DECISIONS:
        raise ValueError("fraud_decision must be allow, review or block")
    if amount_cents < MIN_TRANSFER_CENTS:
        raise InvalidAmount("amount_too_small")

    def work(db: Session) -> TransferResult:
        prior = _claim_key(db, actor, "transfer", idempotency)                 # step 1
        if prior:
            return _replay(db, actor, prior, "transfer_request")
        if str(from_account_id) == str(to_account_id):
            raise TransferDenied("same_account")
        accounts = lock_accounts(db, [from_account_id])                       # step 3 (credits take no lock)
        src = accounts.get(str(from_account_id))
        if src is None or src.kind != "customer" or str(src.owner_id) != str(actor.user_id):
            raise NotFound()
        dst = db.execute(text("SELECT kind, status FROM accounts WHERE id = :d"), {"d": to_account_id}).first()
        if dst is None or dst.kind != "customer" or dst.status == "closed":
            raise NotFound()
        if src.status != "active":
            raise TransferDenied("account_not_active")

        _check_limits(db, from_account_id, amount_cents)                       # step 4
        if fraud_decision is None:
            assessment = _assess_fraud(db, src, to_account_id, amount_cents)
        else:
            assessment = fraud.Assessment(fraud_decision, ())
        threshold = db.execute(text("SELECT ledger_setting('approval_threshold_cents')")).scalar_one()
        status = ("blocked" if assessment.decision == "block" else
                  "held_review" if assessment.decision == "review" else
                  "pending_approval" if amount_cents > threshold else
                  "posted")
        if status != "blocked" and available_balance(db, from_account_id) - amount_cents < src.min_balance:
            raise InsufficientFunds()

        txn = _post_entries(db, actor, from_account_id, to_account_id, amount_cents) if status == "posted" else None
        request_id = db.execute(text(
            "INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, memo, status, "
            "ledger_transaction_id, fraud_reasons) VALUES (:mk, :s, :d, :a, :m, :st, :t, :fr) RETURNING id"
        ), {"mk": actor.user_id, "s": from_account_id, "d": to_account_id, "a": amount_cents,
            "m": memo, "st": status, "t": txn, "fr": list(assessment.reasons) or None}).scalar_one()
        db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))                      # step 6
        result = TransferResult(str(request_id), status)
        _store_response(db, actor, "transfer", idempotency, result)

        # step 7: fraud reasons only ever go into the audit row, never into a customer's response
        details = {"amount_cents": amount_cents, "from_account_id": from_account_id,
                   "to_account_id": to_account_id, "ledger_transaction_id": txn,
                   "rule_ids": list(assessment.reasons)}
        if status == "posted":
            audit_log.append(db, action="transfer.created", outcome="ok", details=details, **_ctx(actor, request_id))
        elif status == "pending_approval":
            audit_log.append(db, action="transfer.pending_approval", outcome="ok", details=details,
                             **_ctx(actor, request_id))
        elif status == "held_review":
            audit_log.append(db, action="transfer.review", outcome="ok", details=details, **_ctx(actor, request_id))
        else:
            audit_log.append(db, action="transfer.blocked", outcome="denied", details=details,
                             **_ctx(actor, request_id))
        return result

    return _run(db, actor, work)


def list_approvals(db: Session, viewer_id) -> list[dict]:
    """The approvals queue: open requests (waiting for a checker or held for review), never your own.
    Approvers see the fraud reasons; customers never do."""
    rows = db.execute(text(
        "SELECT id, from_account_id, to_account_id, amount, status, fraud_reasons, created_at, expires_at "
        "FROM transfer_requests WHERE status IN ('pending_approval', 'held_review') AND expires_at > now() "
        "AND maker_id <> :v ORDER BY created_at LIMIT 100"
    ), {"v": viewer_id}).all()
    return [{"id": str(r.id), "from_account_id": str(r.from_account_id), "to_account_id": str(r.to_account_id),
             "amount": from_cents(r.amount), "status": r.status, "reasons": list(r.fraud_reasons or []),
             "created_at": r.created_at.isoformat(), "expires_at": r.expires_at.isoformat()} for r in rows]


def _lock_open(db: Session, request_id):
    req = db.execute(text(
        "SELECT id, maker_id, from_account_id, to_account_id, amount, status, expires_at <= now() AS expired "
        "FROM transfer_requests WHERE id = :r FOR UPDATE"
    ), {"r": request_id}).first()
    if req is None:
        raise NotFound()
    if req.status not in OPEN_STATES:
        raise ApprovalConflict("already_decided")
    if req.expired:
        raise ApprovalConflict("expired")
    return req


def approve(db: Session, actor: Actor, *, request_id, expected_amount_cents: int) -> TransferResult:
    """A checker approves a pending approval or releases a held review; it posts in the same transaction.
    Role check: Kathy's dependency (approver)."""
    failed: list[str] = []

    def work(db: Session) -> TransferResult:
        req = _lock_open(db, request_id)                                       # step 2
        if str(req.maker_id) == str(actor.user_id):
            raise SelfApproval()
        if req.amount != expected_amount_cents:
            raise AmountMismatch()
        src = lock_accounts(db, [req.from_account_id])[str(req.from_account_id)]  # step 3

        # Funds re-checked now. "available" already subtracts this request's own hold (= its amount),
        # so posting keeps the account at or above its floor exactly when available >= min_balance.
        reason = ("account_not_active" if src.status != "active" else
                  "insufficient_funds" if available_balance(db, req.from_account_id) < src.min_balance else None)
        if reason:
            db.execute(text("UPDATE transfer_requests SET status = 'failed', failure_reason = :f WHERE id = :r"),
                       {"f": reason, "r": req.id})
            audit_log.append(db, action="transfer.failed", outcome="denied", **_ctx(actor, req.id),
                             details={"reason": reason, "amount_cents": req.amount})
            failed.append(reason)
            return TransferResult(str(req.id), "failed")
        # Limits re-checked at posting, without counting this request twice. A refusal leaves the
        # request open: the approver can reject it, or it expires.
        _check_limits(db, req.from_account_id, req.amount, exclude_request=req.id)

        txn = _post_entries(db, actor, req.from_account_id, req.to_account_id, req.amount)
        db.execute(text(
            "UPDATE transfer_requests SET status = 'posted', checker_id = :c, ledger_transaction_id = :t WHERE id = :r"
        ), {"c": actor.user_id, "t": txn, "r": req.id})
        db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        audit_log.append(db, action="approval.granted", outcome="ok", **_ctx(actor, req.id), details={
            "amount_cents": req.amount, "from_account_id": req.from_account_id,
            "to_account_id": req.to_account_id, "maker_id": req.maker_id, "ledger_transaction_id": txn,
            "old_status": req.status, "new_status": "posted",
        })
        return TransferResult(str(req.id), "posted")

    result = _run(db, actor, work)
    if failed:  # committed as 'failed' (hold released); tell the caller why
        raise InsufficientFunds() if failed[0] == "insufficient_funds" else TransferDenied(failed[0])
    return result


def reject(db: Session, actor: Actor, *, request_id) -> TransferResult:
    """Reject a pending approval (-> rejected) or block a held review (-> blocked)."""
    def work(db: Session) -> TransferResult:
        req = _lock_open(db, request_id)
        if str(req.maker_id) == str(actor.user_id):
            raise SelfApproval()
        new_status = "blocked" if req.status == "held_review" else "rejected"
        db.execute(text("UPDATE transfer_requests SET status = :st, checker_id = :c WHERE id = :r"),
                   {"st": new_status, "c": actor.user_id, "r": req.id})
        audit_log.append(db, action="approval.rejected", outcome="ok", **_ctx(actor, req.id),
                         details={"amount_cents": req.amount, "maker_id": req.maker_id,
                                  "old_status": req.status, "new_status": new_status})
        return TransferResult(str(req.id), new_status)

    return _run(db, actor, work)


# ------------------------------------------------------------------ reversals

def request_reversal(db: Session, actor: Actor, *, transfer_request_id, reason: str,
                     idempotency: Idempotency | None = None) -> TransferResult:
    """A teller asks for a full reversal of a posted transfer; a different approver must approve it.
    The amount and accounts always come from the original transfer, never from the request."""
    def work(db: Session) -> TransferResult:
        prior = _claim_key(db, actor, "reversal", idempotency)
        if prior:
            return _replay(db, actor, prior, "reversal_request")
        orig = db.execute(text(
            "SELECT id, status, amount, ledger_transaction_id FROM transfer_requests WHERE id = :r FOR UPDATE"
        ), {"r": transfer_request_id}).first()
        if orig is None:
            raise NotFound()
        if orig.status != "posted":
            raise ApprovalConflict("not_posted")
        live = db.execute(text(
            "SELECT 1 FROM reversal_requests WHERE transfer_request_id = :r AND status IN ('pending_approval', 'posted')"
        ), {"r": orig.id}).first()
        if live:
            raise ApprovalConflict("already_reversed")
        rid = db.execute(text(
            "INSERT INTO reversal_requests (transfer_request_id, original_transaction_id, amount, maker_id, reason, "
            "status) VALUES (:r, :t, :a, :m, :why, 'pending_approval') RETURNING id"
        ), {"r": orig.id, "t": orig.ledger_transaction_id, "a": orig.amount, "m": actor.user_id,
            "why": reason}).scalar_one()
        result = TransferResult(str(rid), "pending_approval")
        _store_response(db, actor, "reversal", idempotency, result)
        audit_log.append(db, action="approval.requested", outcome="ok", **_ctx(actor, rid, "reversal_request"),
                         details={"kind": "reversal", "transfer_id": orig.id, "amount_cents": orig.amount,
                                  "reverses_id": orig.ledger_transaction_id})
        return result

    return _run(db, actor, work)


def _lock_reversal(db: Session, reversal_id):
    rr = db.execute(text(
        "SELECT id, transfer_request_id, original_transaction_id, amount, maker_id, status, "
        "expires_at <= now() AS expired FROM reversal_requests WHERE id = :r FOR UPDATE"
    ), {"r": reversal_id}).first()
    if rr is None:
        raise NotFound()
    if rr.status != "pending_approval":
        raise ApprovalConflict("already_decided")
    if rr.expired:
        raise ApprovalConflict("expired")
    return rr


def approve_reversal(db: Session, actor: Actor, *, reversal_id, expected_amount_cents: int) -> TransferResult:
    """Post the exact opposite of the original transfer. If the recipient has already spent the money,
    the reversal fails (no customer account goes below its floor) and is recorded as failed."""
    failed: list[str] = []

    def work(db: Session) -> TransferResult:
        rr = _lock_reversal(db, reversal_id)                                   # step 2
        if str(rr.maker_id) == str(actor.user_id):
            raise SelfApproval()
        if rr.amount != expected_amount_cents:
            raise AmountMismatch()
        original = [controls.EntryDelta(str(r.account_id), r.amount) for r in db.execute(text(
            "SELECT account_id, amount FROM entries WHERE transaction_id = :t"), {"t": rr.original_transaction_id})]
        opposite = controls.build_reversal_entries(original)
        locked = lock_accounts(db, [e.account_id for e in opposite if e.amount_cents < 0])  # step 3
        short = [e for e in opposite if e.amount_cents < 0
                 and available_balance(db, e.account_id) + e.amount_cents < locked[e.account_id].min_balance]
        if short:
            db.execute(text("UPDATE reversal_requests SET status = 'failed', failure_reason = 'insufficient_funds' "
                            "WHERE id = :r"), {"r": rr.id})
            audit_log.append(db, action="transfer.failed", outcome="denied", **_ctx(actor, rr.id, "reversal_request"),
                             details={"reason": "insufficient_funds", "kind": "reversal", "amount_cents": rr.amount})
            failed.append("insufficient_funds")
            return TransferResult(str(rr.id), "failed")

        txn = db.execute(text(
            "INSERT INTO ledger_transactions (kind, reverses_id, created_by) VALUES ('reversal', :o, :u) RETURNING id"
        ), {"o": rr.original_transaction_id, "u": actor.user_id}).scalar_one()
        for e in opposite:
            db.execute(text("INSERT INTO entries (transaction_id, account_id, amount) VALUES (:t, :a, :m)"),
                       {"t": txn, "a": e.account_id, "m": e.amount_cents})
        db.execute(text("UPDATE reversal_requests SET status = 'posted', checker_id = :c, ledger_transaction_id = :t "
                        "WHERE id = :r"), {"c": actor.user_id, "t": txn, "r": rr.id})
        db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        audit_log.append(db, action="transfer.reversed", outcome="ok", **_ctx(actor, rr.id, "reversal_request"),
                         details={"transfer_id": rr.transfer_request_id, "amount_cents": rr.amount,
                                  "ledger_transaction_id": txn, "reverses_id": rr.original_transaction_id,
                                  "maker_id": rr.maker_id})
        return TransferResult(str(rr.id), "posted")

    result = _run(db, actor, work)
    if failed:
        raise InsufficientFunds()
    return result


def reject_reversal(db: Session, actor: Actor, *, reversal_id) -> TransferResult:
    def work(db: Session) -> TransferResult:
        rr = _lock_reversal(db, reversal_id)
        if str(rr.maker_id) == str(actor.user_id):
            raise SelfApproval()
        db.execute(text("UPDATE reversal_requests SET status = 'rejected', checker_id = :c WHERE id = :r"),
                   {"c": actor.user_id, "r": rr.id})
        audit_log.append(db, action="approval.rejected", outcome="ok", **_ctx(actor, rr.id, "reversal_request"),
                         details={"kind": "reversal", "amount_cents": rr.amount, "maker_id": rr.maker_id})
        return TransferResult(str(rr.id), "rejected")

    return _run(db, actor, work)
