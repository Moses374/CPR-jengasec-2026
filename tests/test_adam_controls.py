import pytest

from app.controls import (
    EntryDelta,
    LimitExceeded,
    build_reversal_entries,
    check_transfer_limits,
    idempotency_key_hash,
    request_fingerprint,
    validate_idempotency_key,
)


def test_idempotency_fingerprint_is_independent_of_object_key_order():
    assert request_fingerprint({"amount": 120, "to": "acct-b"}) == request_fingerprint(
        {"to": "acct-b", "amount": 120}
    )
    assert request_fingerprint({"amount": 120}) != request_fingerprint({"amount": 121})


@pytest.mark.parametrize("key", ["", "has space", "line\nbreak", "x" * 65, "é"])
def test_idempotency_key_rejects_invalid_values(key):
    with pytest.raises(ValueError):
        validate_idempotency_key(key)


def test_idempotency_key_accepts_visible_ascii():
    assert validate_idempotency_key("req_ABC-123") == "req_ABC-123"
    assert len(validate_idempotency_key("x" * 64)) == 64
    assert idempotency_key_hash("req_ABC-123") != "req_ABC-123"


def test_transfer_limits_accept_boundary_and_enforce_daily_total():
    check_transfer_limits(250_000, 750_000)
    with pytest.raises(LimitExceeded, match="per_transfer_limit"):
        check_transfer_limits(250_001, 0)
    with pytest.raises(LimitExceeded, match="daily_limit"):
        check_transfer_limits(100, 1_000_000)
    with pytest.raises(LimitExceeded, match="amount_invalid"):
        check_transfer_limits(0, 0)
    with pytest.raises(LimitExceeded, match="amount_invalid"):
        check_transfer_limits(99, 0)


def test_reversal_entries_are_exact_opposites():
    original = (EntryDelta("source", -12_500), EntryDelta("target", 12_500))
    reversed_entries = build_reversal_entries(original)
    assert reversed_entries == (EntryDelta("source", 12_500), EntryDelta("target", -12_500))
    assert sum(entry.amount_cents for entry in reversed_entries) == 0


def test_unbalanced_transaction_cannot_be_reversed():
    with pytest.raises(ValueError, match="balanced"):
        build_reversal_entries((EntryDelta("source", -100), EntryDelta("target", 99)))
