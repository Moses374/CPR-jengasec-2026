"""Pure reconciliation checks for a consistent ledger and audit-log snapshot."""

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Mapping

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError


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
    audit_controls_problems: tuple[str, ...] = ()
    audit_head_seq: int | None = None
    audit_head_hash: str | None = None


@dataclass(frozen=True)
class ReconciliationResult:
    passed: bool
    mismatches: tuple[str, ...]
    transaction_count: int
    entry_count: int


class ReconciliationRunAlreadyActive(RuntimeError):
    """A different reconciliation currently owns the single-run slot."""


def load_reconciliation_snapshot(db, *, expected_audit_head: tuple[int, str] | None = None) -> ReconciliationSnapshot:
    """Load ledger/audit data from one repeatable-read, read-only snapshot.

    Use a fresh connection/transaction. Audit rows are verified in pages no larger
    than Ethan's 10,000-row limit. The optional expected head must come from the
    platform logs, not from the database.
    """
    from app import audit_log

    db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
    entries = tuple(
        LedgerEntry(str(row.transaction_id), str(row.account_id), int(row.amount))
        for row in db.execute(
            text("SELECT transaction_id, account_id, amount FROM entries ORDER BY transaction_id, account_id")
        ).all()
    )
    ledger_transaction_ids = frozenset(
        str(row.id) for row in db.execute(text("SELECT id FROM ledger_transactions")).all()
    )
    account_minimums = {
        str(row.id): int(row.min_balance) for row in db.execute(text("SELECT id, min_balance FROM accounts")).all()
    }
    # Seed, transfer/approval, and reversal writers identify the posted money in
    # this allowlisted audit detail field.
    audit_transaction_ids = frozenset(
        str(row.transaction_id)
        for row in db.execute(
            text(
                "SELECT DISTINCT details->>'ledger_transaction_id' AS transaction_id "
                "FROM audit_log WHERE details->>'ledger_transaction_id' IS NOT NULL"
            )
        ).all()
    )

    audit_chain_valid = True
    audit_head_seq = None
    audit_head_hash = None
    from_seq = 1
    first_page = True
    while True:
        verified = audit_log.verify_chain(
            db,
            from_seq=from_seq,
            limit=audit_log.MAX_VERIFY_ROWS,
            expected_head=expected_audit_head if first_page else None,
        )
        first_page = False
        if not verified.ok:
            audit_chain_valid = False
            break
        if verified.head_seq is not None:
            audit_head_seq = verified.head_seq
            audit_head_hash = verified.head_hash
        if verified.checked < audit_log.MAX_VERIFY_ROWS or verified.head_seq is None:
            break
        from_seq = verified.head_seq + 1

    return ReconciliationSnapshot(
        entries=entries,
        ledger_transaction_ids=ledger_transaction_ids,
        audit_transaction_ids=audit_transaction_ids,
        account_minimums_cents=account_minimums,
        audit_chain_valid=audit_chain_valid,
        audit_controls_problems=tuple(audit_log.check_controls(db)),
        audit_head_seq=audit_head_seq,
        audit_head_hash=audit_head_hash,
    )


def start_reconciliation_run(db, *, business_date: date, started_by, role: str, src_ip: str | None = None):
    """Persist a run and its audit event in the caller's transaction.

    Abandoned runs older than 30 minutes are finalized as failed before claiming
    the single active slot. Commit the caller's transaction, then write Ethan's
    external audit-chain anchor.
    """
    if not isinstance(business_date, date) or isinstance(business_date, datetime):
        raise ValueError("business_date must be a date")

    from app import audit_log

    abandoned = db.execute(
        text(
            "UPDATE recon_runs SET status = 'failed', "
            "mismatches = CAST(:mismatches AS jsonb), finished_at = now() "
            "WHERE status = 'running' AND started_at < now() - interval '30 minutes' "
            "RETURNING id"
        ),
        {"mismatches": '["run_interrupted"]'},
    ).all()
    for row in abandoned:
        audit_log.append(
            db,
            action="recon.mismatch",
            outcome="error",
            user_id=started_by,
            role=role,
            src_ip=src_ip,
            object_type="recon_run",
            object_id=row.id,
            details={"run_id": row.id, "mismatches": ["run_interrupted"]},
        )

    try:
        with db.begin_nested():
            run = db.execute(
                text(
                    "INSERT INTO recon_runs (business_date, started_by) VALUES (:business_date, :started_by) "
                    "RETURNING id"
                ),
                {"business_date": business_date, "started_by": started_by},
            ).one()
    except IntegrityError as exc:
        constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
        if constraint == "recon_runs_one_active":
            raise ReconciliationRunAlreadyActive("a reconciliation run is already active") from exc
        raise

    audit_log.append(
        db,
        action="recon.started",
        outcome="ok",
        user_id=started_by,
        role=role,
        src_ip=src_ip,
        object_type="recon_run",
        object_id=run.id,
        details={"run_id": run.id, "business_date": business_date.isoformat()},
    )
    return run.id


def finish_reconciliation_run(
    db,
    run_id,
    result: ReconciliationResult,
    *,
    checks: Mapping[str, Any],
    actor_id,
    role: str,
    src_ip: str | None = None,
    audit_head_seq: int | None = None,
    audit_head_hash: str | None = None,
) -> None:
    """Persist final checks and the corresponding audit row atomically."""
    if audit_head_hash is not None and (
        len(audit_head_hash) != 64 or any(char not in "0123456789abcdef" for char in audit_head_hash)
    ):
        raise ValueError("audit_head_hash must be lowercase SHA-256 hex")
    checks_json = json.dumps(dict(checks), sort_keys=True, separators=(",", ":"), allow_nan=False)
    mismatches_json = json.dumps(list(result.mismatches), separators=(",", ":"), allow_nan=False)
    status = "passed" if result.passed else "mismatch"
    updated = db.execute(
        text(
            "UPDATE recon_runs SET status = :status, finished_at = now(), checks = CAST(:checks AS jsonb), "
            "mismatches = CAST(:mismatches AS jsonb), transaction_count = :transaction_count, "
            "entry_count = :entry_count, audit_head_seq = :audit_head_seq, audit_head_hash = :audit_head_hash "
            "WHERE id = :run_id AND status = 'running' RETURNING id"
        ),
        {
            "status": status,
            "checks": checks_json,
            "mismatches": mismatches_json,
            "transaction_count": result.transaction_count,
            "entry_count": result.entry_count,
            "audit_head_seq": audit_head_seq,
            "audit_head_hash": audit_head_hash,
            "run_id": run_id,
        },
    ).first()
    if updated is None:
        raise ValueError("reconciliation run does not exist or is already final")

    audit_log_details = {
        "run_id": run_id,
        "checks": dict(checks),
        "mismatches": list(result.mismatches),
        "head_seq": audit_head_seq,
        "head_hash": audit_head_hash,
    }
    from app import audit_log

    if result.passed:
        audit_log.append(
            db,
            action="recon.passed",
            outcome="ok",
            user_id=actor_id,
            role=role,
            src_ip=src_ip,
            object_type="recon_run",
            object_id=run_id,
            details=audit_log_details,
        )
    else:
        audit_log.append(
            db,
            action="recon.mismatch",
            outcome="error",
            user_id=actor_id,
            role=role,
            src_ip=src_ip,
            object_type="recon_run",
            object_id=run_id,
            details=audit_log_details,
        )


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
    mismatches.extend(
        f"audit_controls_disabled:{problem}" for problem in snapshot.audit_controls_problems
    )

    return ReconciliationResult(
        passed=not mismatches,
        mismatches=tuple(mismatches),
        transaction_count=len(snapshot.ledger_transaction_ids),
        entry_count=len(snapshot.entries),
    )
