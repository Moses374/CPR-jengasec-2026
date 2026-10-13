"""Ledger core: amounts, balances, transfers, approvals (docs/DECISIONS.md, Moses section).

Every money function here runs one database transaction in the agreed lock order and commits it:

  1. idempotency key row               (Adam: not built yet, see create_transfer)
  2. the transfer_requests row         FOR UPDATE, when acting on an existing request
  3. debited accounts                  lock_accounts(): FOR NO KEY UPDATE, sorted by id
  4. checks: balance, holds, limits, fraud, all after the locks
  5. inserts
  6. SET CONSTRAINTS ALL IMMEDIATE     database invariants fire here, inside our error handling
  7. audit_log.append()                always last, held briefly (global chain lock)
  8. commit

The database (migration 0002) enforces the same rules again, so a bug here cannot move money
that does not exist; these checks exist to give callers clean errors.

Amounts: strings with exactly 2 decimals at the edge, int cents everywhere inside.
"""

import logging
import re
import uuid
from dataclasses import dataclass
from decimal import Decimal

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app import audit_log, observability

log = logging.getLogger("app.ledger")

AMOUNT_RE = r"^(0|[1-9][0-9]{0,9})\.[0-9]{2}$"
_AMOUNT = re.compile(AMOUNT_RE)
MIN_TRANSFER_CENTS = 100  # KES 1.00, same as the CHECK on transfer_requests.amount

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
class TransferResult:
    id: str
    status: str


def _begin(db: Session) -> None:
    # Fail fast instead of piling up behind a hot account (DECISIONS Q3).
    db.execute(text("SET LOCAL lock_timeout = '3s'"))
    db.execute(text("SET LOCAL statement_timeout = '10s'"))


def lock_accounts(db: Session, account_ids) -> dict:
    """Lock the accounts being debited, always in id order (the only order anyone may use)."""
    ids = sorted({str(a) for a in account_ids})
    rows = db.execute(text(
        "SELECT id, owner_id, kind, status, min_balance FROM accounts "
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


def _ctx(actor: Actor, request_id) -> dict:
    return {"user_id": actor.user_id, "role": actor.role, "src_ip": actor.src_ip,
            "object_type": "transfer_request", "object_id": request_id}


# Refusals log one of a fixed set of names. Each name is a literal at its call site, so no text from a
# request can ever become an action (tests/test_audit_actions.py enforces it).
_RECORD_REFUSAL = {
    "input.rejected": lambda **kw: audit_log.record(action="input.rejected", **kw),
    "authz.ownership_denied": lambda **kw: audit_log.record(action="authz.ownership_denied", **kw),
    "transfer.denied": lambda **kw: audit_log.record(action="transfer.denied", **kw),
    "transfer.insufficient_funds": lambda **kw: audit_log.record(action="transfer.insufficient_funds", **kw),
    "approval.denied": lambda **kw: audit_log.record(action="approval.denied", **kw),
    "approval.mismatch": lambda **kw: audit_log.record(action="approval.mismatch", **kw),
    "approval.self_denied": lambda **kw: audit_log.record(action="approval.self_denied", **kw),
    "ledger.lock_timeout": lambda **kw: audit_log.record(action="ledger.lock_timeout", **kw),
    "ledger.deadlock": lambda **kw: audit_log.record(action="ledger.deadlock", **kw),
    "ledger.invariant_violation": lambda **kw: audit_log.record(action="ledger.invariant_violation", **kw),
}

_MARK_REFUSAL = {
    "input.rejected": lambda: observability.action("input.rejected"),
    "authz.ownership_denied": lambda: observability.action("authz.ownership_denied"),
}


def mark(err: LedgerError) -> None:
    """Name a refusal on the request log line when it happened outside a money transaction."""
    _MARK_REFUSAL.get(err.action, lambda: observability.action("transfer.denied"))()


def _record_denial(db: Session, actor: Actor, err: LedgerError, request_id=None, details: dict | None = None) -> None:
    """Denials go to the log in their own transaction, after the money transaction is rolled back
    (so this never waits on a chain lock our own transaction holds)."""
    extra = {"reason": err.code}
    extra.update(details or {})
    _RECORD_REFUSAL[err.action](
        session_factory=sessionmaker(bind=db.get_bind()), outcome="error" if err.status >= 500 else "denied",
        user_id=actor.user_id, role=actor.role, src_ip=actor.src_ip,
        object_type="transfer_request" if request_id else None, object_id=request_id, details=extra)


_SQLSTATE_TO_ERROR = {
    "LG004": InsufficientFunds,
    "LG006": TransferDenied,
    "LG005": ApprovalConflict,
    "55P03": Busy,    # lock_not_available (lock_timeout)
    "57014": Busy,    # query_canceled (statement_timeout)
}


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
                err: LedgerError = Busy("busy")
                err.action = "ledger.deadlock"
            elif state in _SQLSTATE_TO_ERROR:
                err = _SQLSTATE_TO_ERROR[state]()
            elif state and state.startswith(("LG", "AU")):
                err = InvariantViolation()
                log.error("ledger.invariant_violation sqlstate=%s", state)
            else:
                raise  # unexpected: the app's catch-all returns a generic 500
            _record_denial(db, actor, err, details={"error_code": state})
            raise err from None
    raise AssertionError("unreachable")


def create_transfer(
    db: Session,
    actor: Actor,
    *,
    from_account_id,
    to_account_id,
    amount_cents: int,
    memo: str | None = None,
    fraud_decision: str = "allow",
) -> TransferResult:
    """Move money from the caller's own account, or route it to approval, review or block.

    Adam's hooks, not built yet:
    - idempotency (lock order step 1): until it exists, a replayed request posts twice.
    - limits and fraud (step 4): the caller passes fraud_decision; limits are not enforced yet.
    """
    if fraud_decision not in FRAUD_DECISIONS:
        raise ValueError("fraud_decision must be allow, review or block")
    if amount_cents < MIN_TRANSFER_CENTS:
        raise InvalidAmount("amount_too_small")

    def work(db: Session) -> TransferResult:
        if str(from_account_id) == str(to_account_id):
            raise TransferDenied("same_account")
        accounts = lock_accounts(db, [from_account_id])  # credits take no lock (DECISIONS Q3)
        src = accounts.get(str(from_account_id))
        if src is None or src.kind != "customer" or str(src.owner_id) != str(actor.user_id):
            raise NotFound()
        dst = db.execute(text("SELECT kind, status FROM accounts WHERE id = :d"), {"d": to_account_id}).first()
        if dst is None or dst.kind != "customer" or dst.status == "closed":
            raise NotFound()
        if src.status != "active":
            raise TransferDenied("account_not_active")

        threshold = db.execute(text("SELECT ledger_setting('approval_threshold_cents')")).scalar_one()
        status = ("blocked" if fraud_decision == "block" else
                  "held_review" if fraud_decision == "review" else
                  "pending_approval" if amount_cents > threshold else
                  "posted")

        if status != "blocked" and available_balance(db, from_account_id) - amount_cents < src.min_balance:
            raise InsufficientFunds()

        txn = _post_entries(db, actor, from_account_id, to_account_id, amount_cents) if status == "posted" else None
        request_id = db.execute(text(
            "INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, memo, status, "
            "ledger_transaction_id) VALUES (:mk, :s, :d, :a, :m, :st, :t) RETURNING id"
        ), {"mk": actor.user_id, "s": from_account_id, "d": to_account_id, "a": amount_cents,
            "m": memo, "st": status, "t": txn}).scalar_one()
        db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))

        details = {"amount_cents": amount_cents, "from_account_id": from_account_id,
                   "to_account_id": to_account_id, "ledger_transaction_id": txn}
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
        return TransferResult(str(request_id), status)

    return _run(db, actor, work)


def _lock_pending(db: Session, request_id):
    req = db.execute(text(
        "SELECT id, maker_id, from_account_id, to_account_id, amount, status, expires_at <= now() AS expired "
        "FROM transfer_requests WHERE id = :r FOR UPDATE"
    ), {"r": request_id}).first()
    if req is None:
        raise NotFound()
    if req.status != "pending_approval":
        raise ApprovalConflict("already_decided")
    if req.expired:
        raise ApprovalConflict("expired")
    return req


def approve(db: Session, actor: Actor, *, request_id, expected_amount_cents: int) -> TransferResult:
    """The checker approves and the transfer posts, in one transaction. Role check: Kathy's dependency."""
    failed: list[str] = []

    def work(db: Session) -> TransferResult:
        req = _lock_pending(db, request_id)                     # step 2
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

        txn = _post_entries(db, actor, req.from_account_id, req.to_account_id, req.amount)
        db.execute(text(
            "UPDATE transfer_requests SET status = 'posted', checker_id = :c, ledger_transaction_id = :t WHERE id = :r"
        ), {"c": actor.user_id, "t": txn, "r": req.id})
        db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        audit_log.append(db, action="approval.granted", outcome="ok", **_ctx(actor, req.id), details={
            "amount_cents": req.amount, "from_account_id": req.from_account_id,
            "to_account_id": req.to_account_id, "maker_id": req.maker_id, "ledger_transaction_id": txn,
        })
        return TransferResult(str(req.id), "posted")

    result = _run(db, actor, work)
    if failed:  # committed as 'failed' (hold released); tell the caller why
        raise InsufficientFunds() if failed[0] == "insufficient_funds" else TransferDenied(failed[0])
    return result


def reject(db: Session, actor: Actor, *, request_id) -> TransferResult:
    def work(db: Session) -> TransferResult:
        req = _lock_pending(db, request_id)
        if str(req.maker_id) == str(actor.user_id):
            raise SelfApproval()
        db.execute(text("UPDATE transfer_requests SET status = 'rejected', checker_id = :c WHERE id = :r"),
                   {"c": actor.user_id, "r": req.id})
        audit_log.append(db, action="approval.rejected", outcome="ok", **_ctx(actor, req.id),
                         details={"amount_cents": req.amount, "maker_id": req.maker_id})
        return TransferResult(str(req.id), "rejected")

    return _run(db, actor, work)
