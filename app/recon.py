"""Pure reconciliation checks for a consistent ledger and audit-log snapshot."""

from collections import defaultdict
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class LedgerEntry:
    transaction_id: str
    account_id: str
    amount_cents: int


@dataclass(frozen=True)
class ReconciliationSnapshot:
    entries: tuple[LedgerEntry, ...]
    ledger_transaction_ids: frozenset[str]
    audit_transaction_ids: frozenset[str]
    account_minimums_cents: Mapping[str, int]
    audit_chain_valid: bool


@dataclass(frozen=True)
class ReconciliationResult:
    passed: bool
    mismatches: tuple[str, ...]
    transaction_count: int
    entry_count: int


def reconcile(snapshot: ReconciliationSnapshot) -> ReconciliationResult:
    """Verify double-entry totals, minimums, ledger/audit coverage, and hash chain.

    Load all fields for a run from one consistent database snapshot. The caller
    persists the returned counts and mismatch codes in ``recon_runs`` and emits
    the appropriate audit action.
    """
    transaction_totals: dict[str, int] = defaultdict(int)
    account_balances: dict[str, int] = defaultdict(int)
    for entry in snapshot.entries:
        transaction_totals[entry.transaction_id] += entry.amount_cents
        account_balances[entry.account_id] += entry.amount_cents

    mismatches: list[str] = []
    for transaction_id, total in sorted(transaction_totals.items()):
        if total != 0:
            mismatches.append(f"transaction_unbalanced:{transaction_id}")

    if sum(entry.amount_cents for entry in snapshot.entries) != 0:
        mismatches.append("ledger_total_nonzero")

    for transaction_id in sorted(snapshot.ledger_transaction_ids - transaction_totals.keys()):
        mismatches.append(f"transaction_without_entries:{transaction_id}")
    for transaction_id in sorted(transaction_totals.keys() - snapshot.ledger_transaction_ids):
        mismatches.append(f"entries_without_transaction:{transaction_id}")

    for account_id, minimum_cents in sorted(snapshot.account_minimums_cents.items()):
        if account_balances[account_id] < minimum_cents:
            mismatches.append(f"account_below_minimum:{account_id}")

    for transaction_id in sorted(snapshot.ledger_transaction_ids - snapshot.audit_transaction_ids):
        mismatches.append(f"audit_missing:{transaction_id}")
    for transaction_id in sorted(snapshot.audit_transaction_ids - snapshot.ledger_transaction_ids):
        mismatches.append(f"audit_without_transaction:{transaction_id}")
    if not snapshot.audit_chain_valid:
        mismatches.append("audit_chain_invalid")

    return ReconciliationResult(
        passed=not mismatches,
        mismatches=tuple(mismatches),
        transaction_count=len(snapshot.ledger_transaction_ids),
        entry_count=len(snapshot.entries),
    )
