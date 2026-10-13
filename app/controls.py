"""Reusable request controls for transfer idempotency, limits, and reversals."""

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from pydantic import BaseModel
from sqlalchemy import text

IDEMPOTENCY_KEY_RE = r"^[A-Za-z0-9_-]{8,64}$"
_IDEMPOTENCY_KEY_PATTERN = re.compile(IDEMPOTENCY_KEY_RE)
MIN_TRANSFER_CENTS = 100
MAX_TRANSFER_CENTS = 250_000
MAX_DAILY_OUTGOING_CENTS = 1_000_000
IDEMPOTENCY_RETENTION_HOURS = 24


class LimitExceeded(ValueError):
    """A transfer exceeds a server-side amount limit."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class TransferLimits:
    minimum_cents: int
    per_transfer_cents: int
    per_day_cents: int


DEFAULT_TRANSFER_LIMITS = TransferLimits(
    MIN_TRANSFER_CENTS,
    MAX_TRANSFER_CENTS,
    MAX_DAILY_OUTGOING_CENTS,
)


def load_transfer_limits(db) -> TransferLimits:
    """Read policy values from immutable ledger settings, never from the request."""
    names = {
        "minimum": "min_transfer_cents",
        "per_transfer": "max_transfer_cents",
        "per_day": "max_daily_outgoing_cents",
    }
    rows = db.execute(
        text("SELECT key, value FROM ledger_settings WHERE key IN (:minimum, :per_transfer, :per_day)"),
        names,
    ).all()
    values = {row.key: int(row.value) for row in rows}
    required = set(names.values())
    if not required.issubset(values):
        raise RuntimeError("transfer limit settings are incomplete")
    limits = TransferLimits(
        minimum_cents=values[names["minimum"]],
        per_transfer_cents=values[names["per_transfer"]],
        per_day_cents=values[names["per_day"]],
    )
    if (
        limits.minimum_cents <= 0
        or limits.per_transfer_cents < limits.minimum_cents
        or limits.per_day_cents < limits.minimum_cents
    ):
        raise RuntimeError("transfer limit settings are invalid")
    return limits


def daily_outgoing_used_cents(db, account_id, *, exclude_request_id=None) -> int:
    """Read today's posted debits plus unexpired holds, optionally excluding one request."""
    result = db.execute(
        text(
            "SELECT COALESCE(SUM(CASE "
            "WHEN tr.status = 'posted' AND lt.created_at >= "
            "     date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' "
            " AND lt.created_at < (date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') + interval '1 day' "
            "THEN tr.amount "
            "WHEN tr.status IN ('pending_approval', 'held_review') AND tr.expires_at > now() "
            "THEN tr.amount ELSE 0 END), 0)::BIGINT "
            "FROM transfer_requests tr "
            "LEFT JOIN ledger_transactions lt ON lt.id = tr.ledger_transaction_id "
            "WHERE tr.from_account_id = :account_id "
            "AND (CAST(:exclude_request_id AS uuid) IS NULL OR tr.id <> CAST(:exclude_request_id AS uuid))"
        ),
        {"account_id": account_id, "exclude_request_id": exclude_request_id},
    ).scalar_one()
    return int(result)


def validate_idempotency_key(key: str) -> str:
    """Enforce the same restricted key format used by FastAPI header validation."""
    if not isinstance(key, str) or not _IDEMPOTENCY_KEY_PATTERN.fullmatch(key):
        raise ValueError("Idempotency-Key must match [A-Za-z0-9_-]{8,64}")
    return key


def idempotency_key_hash(key: str) -> str:
    """Return the stored key identifier without retaining the client-supplied key."""
    validated = validate_idempotency_key(key)
    return hashlib.sha256(validated.encode("ascii")).hexdigest()


def request_fingerprint(body: Mapping[str, object]) -> str:
    """Hash canonical JSON so object key order does not change request identity."""
    encoded = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def fingerprint_operation(method: str, path: str, body: BaseModel) -> str:
    """Fingerprint the validated model the handler executes, including route identity."""
    if not method or not path.startswith("/") or "?" in path:
        raise ValueError("method and absolute path are required")
    if not isinstance(body, BaseModel):
        raise TypeError("body must be the validated Pydantic request model")
    return request_fingerprint(
        {"method": method.upper(), "path": path, "body": body.model_dump(mode="json")}
    )


def check_transfer_limits(
    amount_cents: int,
    daily_used_cents: int,
    limits: TransferLimits = DEFAULT_TRANSFER_LIMITS,
) -> None:
    """Enforce transfer and UTC-day caps against posted plus reserved outgoing value.

    The caller must compute ``daily_used_cents`` while holding the sender account
    lock and include pending/held transfers, so concurrent requests cannot race
    past the daily limit.
    """
    if isinstance(amount_cents, bool) or not isinstance(amount_cents, int):
        raise LimitExceeded("amount_invalid")
    if isinstance(daily_used_cents, bool) or not isinstance(daily_used_cents, int):
        raise ValueError("daily_used_cents must be an integer")
    if amount_cents < limits.minimum_cents:
        raise LimitExceeded("amount_invalid")
    if amount_cents > limits.per_transfer_cents:
        raise LimitExceeded("per_transfer_limit")
    if daily_used_cents < 0:
        raise ValueError("daily_used_cents cannot be negative")
    if daily_used_cents + amount_cents > limits.per_day_cents:
        raise LimitExceeded("daily_limit")


def check_transfer_request_limits(db, *, account_id, amount_cents: int, request_id) -> None:
    """Check a pending request at approval without counting its own reservation twice."""
    limits = load_transfer_limits(db)
    daily_used = daily_outgoing_used_cents(db, account_id, exclude_request_id=request_id)
    check_transfer_limits(amount_cents, daily_used, limits)


@dataclass(frozen=True)
class EntryDelta:
    account_id: str
    amount_cents: int


def build_reversal_entries(entries: Iterable[EntryDelta]) -> tuple[EntryDelta, ...]:
    """Build the exact opposite entries for a balanced, non-empty transaction."""
    original = tuple(entries)
    if len(original) < 2:
        raise ValueError("a reversal requires at least two ledger entries")
    if any(entry.amount_cents == 0 for entry in original):
        raise ValueError("zero-value ledger entries cannot be reversed")
    if sum(entry.amount_cents for entry in original) != 0:
        raise ValueError("only a balanced transaction can be reversed")
    return tuple(EntryDelta(entry.account_id, -entry.amount_cents) for entry in original)
