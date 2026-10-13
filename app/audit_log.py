"""Append-only, hash-chained audit log (docs/DECISIONS.md, Ethan section E1).

Two ways to write, one call each. Both also set the action on the request log line
(app/observability.py), so the stdout record and the database record can never disagree.

    from app import audit_log

    # Money and approvals: inside the request's transaction, as the LAST statement before commit.
    # No audit row, no commit: if this raises, the whole transfer rolls back.
    audit_log.append(db, action="transfer.created", outcome="ok", user_id=str(user.id), role=user.role,
                     src_ip=request.client.host, object_type="transfer_request", object_id=str(req.id),
                     details={"amount_cents": req.amount, "to_account_id": str(req.to_account_id)})
    db.commit()

    # Denials and other events where the money transaction is rolled back or never started:
    # own short transaction. Best effort; a failure is logged loudly, never turned into a 500.
    audit_log.record(action="transfer.denied", outcome="denied", user_id=..., details={"reason": "limit_daily"})

Rules:
- action must be a literal from ACTIONS (tests/test_audit_actions.py fails the build otherwise).
- details keys must be in DETAIL_KEYS; anything else is dropped and noted, so a typo cannot leak a secret.
- Never put passwords, tokens, full idempotency keys or request bodies in any argument.

Why the hash chain is computed here and not in a trigger: a person who can rewrite the database can
also rewrite a trigger. verify_chain() recomputes every hash in Python from the stored columns.
The anchor line (anchor()) gives a copy of the head that lives in the platform logs, outside the database.
"""

import hashlib
import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from app import observability

log = logging.getLogger("app.audit")
log.setLevel(logging.INFO)

GENESIS_HASH = bytes(32)
LOCK_KEY = 0x41554449544C4F47  # ASCII "AUDITLOG"; migration 0003 and its trigger use the same number
MAX_VERIFY_ROWS = 10_000
OUTCOMES = frozenset({"ok", "denied", "error"})

Executor = Session | Connection

# ---------------------------------------------------------------------------------------------
# Vocabulary. Names come from docs/TASKS.md where the owners already chose one; the rest are in
# docs/DECISIONS.md (E3). Format: area.event or area.event.qualifier, lowercase.
# ---------------------------------------------------------------------------------------------
_ACTION_RE = re.compile(r"[a-z0-9_]+(\.[a-z0-9_]+){1,2}")  # used with fullmatch: "$" would let a trailing newline through

ACTIONS = frozenset({
    # authentication (Kathy)
    "login.ok", "login.failed", "login.locked", "login.logout", "token.invalid",
    # access control
    "authz.denied", "authz.ownership_denied", "account.read_privileged",
    # input and abuse
    "input.rejected", "ratelimit.hit",
    # transfers (Moses, Adam)
    "transfer.created", "transfer.denied", "transfer.insufficient_funds", "transfer.duplicate",
    "transfer.review", "transfer.blocked", "transfer.pending_approval", "transfer.reversed", "transfer.failed",
    "limit.exceeded", "idempotency.conflict",
    # maker-checker (Kathy, Moses)
    "approval.requested", "approval.granted", "approval.rejected", "approval.expired",
    "approval.self_denied", "approval.denied", "approval.mismatch",
    # ledger controls (Moses)
    "ledger.invariant_violation", "ledger.controls_disabled", "ledger.lock_timeout", "ledger.deadlock",
    "ledger.imbalance",
    # reconciliation (Adam)
    "recon.started", "recon.passed", "recon.mismatch",
    # the audit log itself (Ethan)
    "auditlog.read", "auditlog.chain_ok", "auditlog.chain_broken", "auditlog.anchor",
    "auditlog.controls_disabled", "auditlog.write_failed",
    # system
    "seed.loaded", "app.error",
})

# The names RequestLogMiddleware falls back to when a handler sets none (app/observability.py).
FALLBACK_ACTIONS = frozenset({
    "health.check", "auth.unauthenticated", "authz.denied", "http.not_found", "http.method_not_allowed",
    "input.rejected", "ratelimit.hit", "http.error", "http.request",
})

# Keys allowed in details. Everything is non-secret by construction: ids, amounts in cents, reason codes.
DETAIL_KEYS = frozenset({
    "reason", "decision", "kind", "status", "old_status", "new_status", "trigger", "error_code",
    "amount_cents", "expected_amount_cents", "limit_cents", "count", "attempts", "window_minutes",
    "retry_after_s", "locked_until", "business_date",
    "account_id", "from_account_id", "to_account_id", "transfer_id", "request_id", "approval_id",
    "ledger_transaction_id", "reverses_id", "maker_id", "checker_id", "target_user_id", "role_required",
    "rule_ids", "key_hash", "username_hash",
    "run_id", "checks", "mismatches", "from_seq", "to_seq", "head_seq", "head_hash",
})
_MAX_STR = 200
_MAX_ITEMS = 20
_MAX_DEPTH = 3


class AuditError(ValueError):
    """The caller passed an action or outcome the log refuses. Fix the call, not the log."""


# ---------------------------------------------------------------------------------------------
# Rows and hashing. Pure functions: tested without a database.
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class AuditRow:
    seq: int
    ts: datetime
    user_id: str | None
    role: str | None
    src_ip: str | None
    action: str
    outcome: str
    object_type: str | None
    object_id: str | None
    details: dict
    prev_hash: bytes
    row_hash: bytes

    def expected_hash(self) -> bytes:
        return compute_hash(self.prev_hash, canonical_body(
            self.seq, self.ts, self.user_id, self.role, self.src_ip, self.action, self.outcome,
            self.object_type, self.object_id, self.details,
        ))


def _ts_text(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_body(seq, ts, user_id, role, src_ip, action, outcome, object_type, object_id, details) -> bytes:
    return canonical_json({
        "seq": seq, "ts": _ts_text(ts), "user_id": user_id, "role": role, "src_ip": src_ip,
        "action": action, "outcome": outcome, "object_type": object_type, "object_id": object_id,
        "details": details,
    }).encode("ascii")


def compute_hash(prev_hash: bytes, body: bytes) -> bytes:
    return hashlib.sha256(prev_hash + b"\x1f" + body).digest()


class ChainChecker:
    """Walks rows in seq order. feed() returns None for a good row, or (seq, reason) for the first bad one."""

    def __init__(self, next_seq: int = 1, prev_hash: bytes = GENESIS_HASH):
        self.next_seq = next_seq
        self.prev_hash = prev_hash

    def feed(self, row: AuditRow) -> tuple[int, str] | None:
        if row.seq != self.next_seq:
            return self.next_seq, f"expected seq {self.next_seq} but found {row.seq} (row removed or inserted)"
        if row.prev_hash != self.prev_hash:
            return row.seq, "prev_hash does not match the row before"
        if row.expected_hash() != row.row_hash:
            return row.seq, "row content does not match its hash (row edited)"
        self.next_seq += 1
        self.prev_hash = row.row_hash
        return None


# ---------------------------------------------------------------------------------------------
# Cleaning what goes in. A bug here must not be able to put a secret in the log.
# ---------------------------------------------------------------------------------------------
def _clean_str(value: Any, limit: int = _MAX_STR) -> str:
    return str(value).replace("\x00", "")[:limit]


def _clean_value(value: Any, depth: int = 0) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if -(2**63) <= value < 2**63 else _clean_str(value)
    if isinstance(value, (list, tuple)) and depth < _MAX_DEPTH:
        return [_clean_value(v, depth + 1) for v in list(value)[:_MAX_ITEMS]]
    if isinstance(value, dict) and depth < _MAX_DEPTH:
        return {_clean_str(k, 40): _clean_value(v, depth + 1) for k, v in list(value.items())[:_MAX_ITEMS]}
    return _clean_str(value)  # floats, UUIDs, Decimals, anything else: text, so the hash never depends on float formatting


def clean_details(details: dict | None) -> dict:
    out: dict[str, Any] = {}
    dropped: list[str] = []
    for key, value in (details or {}).items():
        if key in DETAIL_KEYS:
            out[key] = _clean_value(value)
        else:
            dropped.append(_clean_str(key, 40))
    if dropped:
        out["dropped_keys"] = sorted(dropped)[:_MAX_ITEMS]
    return out


def _optional(value: Any, limit: int) -> str | None:
    return None if value is None else _clean_str(value, limit)


# ---------------------------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------------------------
def append(
    db: Executor,
    *,
    action: str,
    outcome: str,
    user_id: Any = None,
    role: str | None = None,
    src_ip: str | None = None,
    object_type: str | None = None,
    object_id: Any = None,
    details: dict | None = None,
) -> AuditRow:
    """Add one row inside the caller's transaction. Does not commit. Raises if it cannot write."""
    if not _ACTION_RE.fullmatch(action or "") or len(action) > 64:
        raise AuditError(f"bad audit action {action!r}")
    if outcome not in OUTCOMES:
        raise AuditError(f"bad audit outcome {outcome!r}")

    # One writer at a time, until this transaction ends. The caller calls us last, so the lock
    # is held only for the commit. The chain trigger takes the same lock (re-entrant for us).
    db.execute(text("SELECT pg_advisory_xact_lock(CAST(:k AS bigint))"), {"k": LOCK_KEY})
    head = db.execute(text(
        "SELECT l.seq, l.row_hash, clock_timestamp() AS now "
        "FROM (SELECT 1) AS one "
        "LEFT JOIN LATERAL (SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1) AS l ON true"
    )).one()

    seq = (head.seq or 0) + 1
    prev_hash = bytes(head.row_hash) if head.row_hash is not None else GENESIS_HASH
    row_fields = {
        "user_id": _optional(user_id, 64),
        "role": _optional(role, 32),
        "src_ip": _optional(src_ip, 64),
        "object_type": _optional(object_type, 32),
        "object_id": _optional(object_id, 64),
    }
    details_clean = clean_details(details)
    body = canonical_body(seq, head.now, row_fields["user_id"], row_fields["role"], row_fields["src_ip"],
                          action, outcome, row_fields["object_type"], row_fields["object_id"], details_clean)
    row_hash = compute_hash(prev_hash, body)

    db.execute(
        text(
            "INSERT INTO audit_log (seq, ts, user_id, role, src_ip, action, outcome, object_type, object_id, "
            "details, prev_hash, row_hash) VALUES (:seq, :ts, :user_id, :role, :src_ip, :action, :outcome, "
            ":object_type, :object_id, CAST(:details AS jsonb), :prev_hash, :row_hash)"
        ),
        {"seq": seq, "ts": head.now, "action": action, "outcome": outcome, **row_fields,
         "details": canonical_json(details_clean), "prev_hash": prev_hash, "row_hash": row_hash},
    )
    observability.action(action)
    return AuditRow(seq, head.now, row_fields["user_id"], row_fields["role"], row_fields["src_ip"], action,
                    outcome, row_fields["object_type"], row_fields["object_id"], details_clean, prev_hash, row_hash)


def _default_factory() -> Callable[[], Session]:
    from app.db import SessionLocal  # late: unit tests import this module without an engine

    return SessionLocal


def record(*, session_factory: Callable[[], Session] | None = None, **kwargs: Any) -> int | None:
    """append() in its own short transaction, for events where the main transaction is gone.

    Returns the seq, or None if the write failed. A failure is logged (error type only, never the
    statement or its parameters) and the request carries on: the request log line on stdout
    already holds the action, so the denial is still on record.
    """
    action = kwargs.get("action", "")
    try:
        with (session_factory or _default_factory())() as session:
            row = append(session, **kwargs)
            session.commit()
            return row.seq
    except AuditError:
        raise  # a bad call is a bug: fail in tests, not silently in production
    except Exception as exc:
        log.error("auditlog.write_failed action=%s error=%s", _clean_str(action, 64), type(exc).__name__)
        observability.action(action)
        return None


# ---------------------------------------------------------------------------------------------
# Reading and checking
# ---------------------------------------------------------------------------------------------
def _to_row(r: Any) -> AuditRow:
    return AuditRow(
        seq=r.seq, ts=r.ts, user_id=r.user_id, role=r.role, src_ip=r.src_ip, action=r.action,
        outcome=r.outcome, object_type=r.object_type, object_id=r.object_id, details=dict(r.details),
        prev_hash=bytes(r.prev_hash), row_hash=bytes(r.row_hash),
    )


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None
    head_seq: int | None = None
    head_hash: str | None = None

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


def verify_chain(
    db: Executor,
    *,
    from_seq: int = 1,
    limit: int = MAX_VERIFY_ROWS,
    expected_head: tuple[int, str] | None = None,
    batch: int = 500,
) -> VerifyResult:
    """Recompute every hash from the stored columns, outside the database's own logic.

    from_seq > 1 starts from the stored hash of the row before it, so check the earlier range first.
    expected_head=(seq, hex) is an anchor taken from the platform logs: it catches rows removed from
    the end of the log, which no chain can show by itself.
    """
    from_seq = max(1, int(from_seq))
    limit = max(1, min(int(limit), 1_000_000))

    if expected_head is not None:
        problem = _check_anchor(db, *expected_head)
        if problem:
            return VerifyResult(False, 0, expected_head[0], problem)

    if from_seq == 1:
        checker = ChainChecker()
    else:
        before = db.execute(text("SELECT row_hash FROM audit_log WHERE seq = :s"), {"s": from_seq - 1}).scalar()
        if before is None:
            return VerifyResult(False, 0, from_seq - 1, "the row before from_seq is missing")
        checker = ChainChecker(from_seq, bytes(before))

    checked = 0
    cursor = from_seq
    last_seq: int | None = None
    last_hash: str | None = None
    while checked < limit:
        want = min(batch, limit - checked)
        rows = db.execute(
            text(
                "SELECT seq, ts, user_id, role, src_ip, action, outcome, object_type, object_id, details, "
                "prev_hash, row_hash FROM audit_log WHERE seq >= :c ORDER BY seq LIMIT :n"
            ),
            {"c": cursor, "n": want},
        ).all()
        for r in rows:
            row = _to_row(r)
            bad = checker.feed(row)
            if bad:
                return VerifyResult(False, checked, bad[0], bad[1], last_seq, last_hash)
            checked += 1
            last_seq, last_hash = row.seq, row.row_hash.hex()
        if len(rows) < want:
            break
        cursor = rows[-1].seq + 1
    return VerifyResult(True, checked, head_seq=last_seq, head_hash=last_hash)


def _check_anchor(db: Executor, seq: int, row_hash_hex: str) -> str | None:
    found = db.execute(text("SELECT row_hash FROM audit_log WHERE seq = :s"), {"s": seq}).scalar()
    if found is None:
        return f"anchor seq {seq} no longer exists (rows removed from the end or the middle)"
    if bytes(found).hex() != row_hash_hex.lower():
        return f"row {seq} differs from the anchor taken earlier"
    return None


_EXPECTED_TRIGGERS = ("audit_log_append_only", "audit_log_no_truncate", "audit_log_chain")


def check_controls(db: Executor) -> list[str]:
    """Problems with the log's own protections (empty list = healthy). Run at startup and by reconciliation."""
    problems = []
    state = dict(db.execute(text(
        "SELECT tgname, tgenabled FROM pg_trigger WHERE tgrelid = CAST('audit_log' AS regclass) AND NOT tgisinternal"
    )).all())
    for name in _EXPECTED_TRIGGERS:
        if name not in state:
            problems.append(f"trigger {name} is missing")
        elif state[name] != "O":
            problems.append(f"trigger {name} is disabled")
    if db.execute(text("SELECT current_setting('is_superuser')")).scalar() != "on":
        for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
            if db.execute(text("SELECT has_table_privilege(current_user, 'audit_log', :p)"), {"p": privilege}).scalar():
                problems.append(f"{privilege} is granted on audit_log")
    return problems


def anchor(db: Executor | None = None) -> dict | None:
    """Write the committed head of the chain to the platform logs. Call it after a commit, never before:
    an anchor for a row that later rolls back would look like a deleted row."""
    def read(session: Executor):
        return session.execute(text("SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1")).first()

    if db is None:
        with _default_factory()() as session:
            head = read(session)
    else:
        head = read(db)
    if head is None:
        return None
    result = {"seq": head.seq, "row_hash": bytes(head.row_hash).hex()}
    log.info("auditlog.anchor seq=%d row_hash=%s", result["seq"], result["row_hash"])
    return result


def list_events(
    db: Executor,
    *,
    before_seq: int | None = None,
    limit: int = 100,
    action: str | None = None,
    user_id: str | None = None,
) -> list[dict]:
    """Newest first, keyset pagination: pass the smallest seq you already have as before_seq."""
    rows = db.execute(
        text(
            "SELECT seq, ts, user_id, role, src_ip, action, outcome, object_type, object_id, details "
            "FROM audit_log "
            "WHERE (CAST(:before AS bigint) IS NULL OR seq < CAST(:before AS bigint)) "
            "AND (CAST(:action AS text) IS NULL OR action = CAST(:action AS text)) "
            "AND (CAST(:uid AS text) IS NULL OR user_id = CAST(:uid AS text)) "
            "ORDER BY seq DESC LIMIT :n"
        ),
        {"before": before_seq, "action": action, "uid": user_id, "n": max(1, min(int(limit), 100))},
    ).all()
    return [
        {"seq": r.seq, "ts": _ts_text(r.ts), "user_id": r.user_id, "role": r.role, "src_ip": r.src_ip,
         "action": r.action, "outcome": r.outcome, "object_type": r.object_type, "object_id": r.object_id,
         "details": r.details}
        for r in rows
    ]
