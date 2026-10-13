"""Reusable request controls for transfer idempotency, limits, and reversals."""

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

# One definition of a valid key, used by the route and here (letters, digits, - and _; UUIDs fit).
IDEMPOTENCY_KEY_RE = r"^[A-Za-z0-9_-]{8,64}$"
_IDEMPOTENCY_KEY = re.compile(IDEMPOTENCY_KEY_RE)
MAX_IDEMPOTENCY_KEY_LENGTH = 64

# Bank scale, agreed 13 Oct: min < approval threshold (KSh 100,000) < per transfer <= per day.
# The database enforces the same values (ledger_settings, migration 0004).
MIN_TRANSFER_CENTS = 100                  # KSh 1.00
MAX_TRANSFER_CENTS = 25_000_000           # KSh 250,000
MAX_DAILY_OUTGOING_CENTS = 100_000_000    # KSh 1,000,000 per account per UTC day


class LimitExceeded(ValueError):
    """A transfer exceeds a server-side amount limit."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def validate_idempotency_key(key: str) -> str:
    """Return the key if it matches IDEMPOTENCY_KEY_RE (8-64 of A-Z a-z 0-9 - _), else raise."""
    if not isinstance(key, str) or not _IDEMPOTENCY_KEY.fullmatch(key):
        raise ValueError("Idempotency-Key must be 8 to 64 letters, digits, '-' or '_'")
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


def check_transfer_limits(amount_cents: int, daily_used_cents: int) -> None:
    """Enforce transfer and UTC-day caps against posted plus reserved outgoing value.

    The caller must compute ``daily_used_cents`` while holding the sender account
    lock and include pending/held transfers, so concurrent requests cannot race
    past the daily limit.
    """
    if isinstance(amount_cents, bool) or not isinstance(amount_cents, int):
        raise LimitExceeded("amount_invalid")
    if isinstance(daily_used_cents, bool) or not isinstance(daily_used_cents, int):
        raise ValueError("daily_used_cents must be an integer")
    if amount_cents < MIN_TRANSFER_CENTS:
        raise LimitExceeded("amount_invalid")
    if amount_cents > MAX_TRANSFER_CENTS:
        raise LimitExceeded("per_transfer_limit")
    if daily_used_cents < 0:
        raise ValueError("daily_used_cents cannot be negative")
    if daily_used_cents + amount_cents > MAX_DAILY_OUTGOING_CENTS:
        raise LimitExceeded("daily_limit")


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
