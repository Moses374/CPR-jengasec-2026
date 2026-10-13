from app.fraud import Assessment, SenderHistory, TransferRisk, assess
from app.recon import LedgerEntry, ReconciliationSnapshot, reconcile


def _assess(
    *,
    amount=1_000,
    typical=None,
    count=0,
    recent_total=0,
    known_payee=True,
    account_age=1_000,
    balance=1_000_000,
):
    return assess(
        TransferRisk(amount_cents=amount),
        SenderHistory(
            typical_transfer_cents=typical,
            prior_transfer_count_10m=count,
            prior_transfer_total_cents_10m=recent_total,
            recipient_previously_paid=known_payee,
            account_age_hours=account_age,
            available_balance_cents=balance,
        ),
    )


def test_fraud_allows_transfer_without_signals():
    assert _assess() == Assessment("allow", ())


def test_fraud_reviews_each_ambiguous_signal():
    assert _assess(count=5).reasons == ("velocity_count_10m",)
    assert _assess(amount=1_000, recent_total=499_000).reasons == ("velocity_amount_10m",)
    assert _assess(amount=50_000, typical=10_000).reasons == ("amount_vs_typical",)
    assert _assess(amount=100_000, known_payee=False).reasons == ("new_payee_amount",)
    assert _assess(amount=50_000, account_age=23).reasons == ("new_account_amount",)
    assert _assess(amount=100_000, balance=110_000).reasons == ("rapid_drain",)
    assert _assess(amount=100_000, balance=2_000_000).decision == "allow"


def test_extreme_velocity_blocks_before_other_review_signals():
    assert _assess(count=10, amount=100_000, known_payee=False).decision == "block"
    assert _assess(count=10).reasons == ("velocity_block_10m",)


def test_fraud_rejects_invalid_transfer_inputs():
    import pytest

    with pytest.raises(ValueError, match="positive"):
        _assess(amount=0)


def _clean_snapshot():
    return ReconciliationSnapshot(
        entries=(
            LedgerEntry("tx-1", "account-a", -500),
            LedgerEntry("tx-1", "account-b", 500),
        ),
        ledger_transaction_ids=frozenset({"tx-1"}),
        audit_transaction_ids=frozenset({"tx-1"}),
        account_minimums_cents={"account-a": -1_000, "account-b": 0},
        audit_chain_valid=True,
    )


def test_reconciliation_passes_for_balanced_ledger_and_matching_audit():
    result = reconcile(_clean_snapshot())
    assert result.passed
    assert result.mismatches == ()
    assert result.transaction_count == 1
    assert result.entry_count == 2


def test_reconciliation_detects_ledger_mismatch_and_audit_chain_failure():
    snapshot = ReconciliationSnapshot(
        entries=(
            LedgerEntry("tx-1", "account-a", -500),
            LedgerEntry("tx-1", "account-b", 400),
        ),
        ledger_transaction_ids=frozenset({"tx-1", "tx-empty"}),
        audit_transaction_ids=frozenset({"tx-orphan"}),
        account_minimums_cents={"account-a": 0},
        audit_chain_valid=False,
    )

    result = reconcile(snapshot)
    assert not result.passed
    assert "transaction_unbalanced:tx-1" in result.mismatches
    assert "ledger_total_nonzero" in result.mismatches
    assert "transaction_without_entries:tx-empty" in result.mismatches
    assert "account_below_minimum:account-a" in result.mismatches
    assert "audit_missing:tx-1" in result.mismatches
    assert "audit_without_transaction:tx-orphan" in result.mismatches
    assert "audit_chain_invalid" in result.mismatches
