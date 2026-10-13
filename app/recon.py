"""Pure reconciliation checks for a consistent ledger and audit-log snapshot."""

import datetime
import json
import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass
from typing import Mapping

from sqlalchemy import text
from sqlalchemy.orm import Session


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
    # Transactions that must have an audit row (transfers and reversals). Opening balances come from
    # migrations, not from a user action, so they are left out. None means every ledger transaction.
    audit_required_transaction_ids: frozenset[str] | None = None
    # Problems found by checks that need the database itself (controls switched off, requests that
    # do not match their entries); reported in the same run.
    extra_mismatches: tuple[str, ...] = ()


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

    required = (snapshot.ledger_transaction_ids if snapshot.audit_required_transaction_ids is None
                else snapshot.audit_required_transaction_ids)
    for transaction_id in sorted(required - snapshot.audit_transaction_ids):
        mismatches.append(f"audit_missing:{transaction_id}")
    for transaction_id in sorted(snapshot.audit_transaction_ids - snapshot.ledger_transaction_ids):
        mismatches.append(f"audit_without_transaction:{transaction_id}")
    if not snapshot.audit_chain_valid:
        mismatches.append("audit_chain_invalid")
    mismatches.extend(snapshot.extra_mismatches)

    return ReconciliationResult(
        passed=not mismatches,
        mismatches=tuple(mismatches),
        transaction_count=len(snapshot.ledger_transaction_ids),
        entry_count=len(snapshot.entries),
    )


# ---------------------------------------------------------------------------------------------
# Running a reconciliation against the database (Moses, wiring Adam's checks above)
# ---------------------------------------------------------------------------------------------
_log = logging.getLogger("app.recon")
RECON_LOCK_KEY = 0x5245434F4E52554E  # ASCII "RECONRUN": one run at a time across both workers
MAX_REPORTED_MISMATCHES = 500

# Every protection the ledger relies on. A missing or disabled trigger is a reconciliation mismatch.
LEDGER_TRIGGERS = {
    "entries": ("entries_append_only", "entries_no_truncate", "entries_server_time",
                "entries_check_transaction", "entries_check_funds"),
    "ledger_transactions": ("ledger_transactions_append_only", "ledger_transactions_no_truncate",
                            "ledger_transactions_server_time", "ledger_transactions_validate"),
    "ledger_settings": ("ledger_settings_append_only", "ledger_settings_no_truncate"),
    "accounts": ("accounts_no_delete", "accounts_no_truncate", "accounts_guard_update"),
    "transfer_requests": ("transfer_requests_no_delete", "transfer_requests_no_truncate",
                          "transfer_requests_server_time", "transfer_requests_guard_insert",
                          "transfer_requests_guard_update", "transfer_requests_check_posted",
                          "transfer_requests_limits", "transfer_requests_checker_is_approver"),
    "idempotency_keys": ("idempotency_keys_guard_update", "idempotency_keys_no_delete",
                         "idempotency_keys_no_truncate", "idempotency_keys_server_time"),
    "reversal_requests": ("reversal_requests_checker_is_approver", "reversal_requests_guard_insert",
                          "reversal_requests_guard_update",
                          "reversal_requests_no_delete", "reversal_requests_no_truncate",
                          "reversal_requests_check_posted"),
    "recon_runs": ("recon_runs_append_only", "recon_runs_no_truncate", "recon_runs_server_time"),
}


class ReconBusy(Exception):
    """Another reconciliation run is in progress."""


def check_ledger_controls(db) -> list[str]:
    """Missing or disabled ledger triggers (empty list = healthy). Run at startup and in every run."""
    rows = db.execute(text(
        "SELECT c.relname, t.tgname, t.tgenabled FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
        "WHERE NOT t.tgisinternal AND c.relname = ANY(CAST(:tables AS text[]))"
    ), {"tables": list(LEDGER_TRIGGERS)}).all()
    state = {(r.relname, r.tgname): r.tgenabled for r in rows}
    problems = []
    for table, names in LEDGER_TRIGGERS.items():
        for name in names:
            if (table, name) not in state:
                problems.append(f"trigger {name} is missing")
            elif state[(table, name)] != "O":
                problems.append(f"trigger {name} is disabled")
    return problems


def run(db: Session, *, started_by, business_date: datetime.date, src_ip: str | None = None,
        role: str | None = None) -> dict:
    """Reconcile the whole ledger from one consistent snapshot, store the run, log the result.

    Never edits the ledger. The caller gets the stored run; a mismatch also logs recon.mismatch.
    """
    from app import audit_log  # late: unit tests import this module without a database

    db.rollback()   # a run is its own transaction: the isolation level can only be set before any query
    db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))   # one snapshot for every check
    db.execute(text("SET LOCAL statement_timeout = '60s'"))
    if not db.execute(text("SELECT pg_try_advisory_xact_lock(CAST(:k AS bigint))"), {"k": RECON_LOCK_KEY}).scalar():
        db.rollback()
        raise ReconBusy()

    entries = tuple(LedgerEntry(str(r.transaction_id), str(r.account_id), int(r.amount)) for r in db.execute(
        text("SELECT transaction_id, account_id, amount FROM entries")))
    kinds = {str(r.id): r.kind for r in db.execute(text("SELECT id, kind FROM ledger_transactions"))}
    audited = frozenset(str(r.txn_id) for r in db.execute(text(
        "SELECT DISTINCT details->>'ledger_transaction_id' AS txn_id FROM audit_log "
        "WHERE action IN ('transfer.created', 'approval.granted', 'transfer.reversed') "
        "AND details->>'ledger_transaction_id' IS NOT NULL")))
    minimums = {str(r.id): int(r.min_balance) for r in db.execute(text("SELECT id, min_balance FROM accounts"))}
    chain = audit_log.verify_chain(db, limit=1_000_000)

    extra = [f"ledger_control:{p}" for p in check_ledger_controls(db)]
    extra += [f"auditlog_control:{p}" for p in audit_log.check_controls(db)]
    # Posted requests whose ledger entries do not match them exactly (the database refuses this;
    # finding one means a control was bypassed).
    extra += [f"request_mismatch:{r.id}" for r in db.execute(text(
        "SELECT r.id FROM transfer_requests r WHERE r.status = 'posted' AND ("
        " (SELECT count(*) FROM entries e WHERE e.transaction_id = r.ledger_transaction_id) <> 2"
        " OR NOT EXISTS (SELECT 1 FROM entries e WHERE e.transaction_id = r.ledger_transaction_id"
        "                AND e.account_id = r.from_account_id AND e.amount = -r.amount)"
        " OR NOT EXISTS (SELECT 1 FROM entries e WHERE e.transaction_id = r.ledger_transaction_id"
        "                AND e.account_id = r.to_account_id AND e.amount = r.amount))"))]

    result = reconcile(ReconciliationSnapshot(
        entries=entries,
        ledger_transaction_ids=frozenset(kinds),
        audit_transaction_ids=audited,
        account_minimums_cents=minimums,
        audit_chain_valid=chain.ok,
        # opening balances come from migrations, not a user action: no audit row is required
        audit_required_transaction_ids=frozenset(t for t, k in kinds.items() if k in ("transfer", "reversal")),
        extra_mismatches=tuple(extra),
    ))
    posted_that_day = db.execute(text(
        "SELECT count(*) FROM transfer_requests WHERE status = 'posted' "
        "AND created_at >= CAST(:d AS date) AND created_at < CAST(:d AS date) + 1"
    ), {"d": business_date}).scalar_one()
    checks = {"transactions": result.transaction_count, "entries": result.entry_count,
              "audit_rows_checked": chain.checked, "transfers_posted_on_date": int(posted_that_day),
              "mismatch_count": len(result.mismatches)}
    mismatches = list(result.mismatches[:MAX_REPORTED_MISMATCHES])
    status = "passed" if result.passed else "mismatch"

    run_id = db.execute(text(
        "INSERT INTO recon_runs (business_date, started_by, status, checks, mismatches) "
        "VALUES (:d, :u, :s, CAST(:c AS jsonb), CAST(:m AS jsonb)) RETURNING id"
    ), {"d": business_date, "u": started_by, "s": status, "c": json.dumps(checks),
        "m": json.dumps(mismatches)}).scalar_one()
    ctx = {"user_id": started_by, "role": role, "src_ip": src_ip, "object_type": "recon_run", "object_id": run_id}
    details = {"run_id": run_id, "business_date": business_date.isoformat(), "checks": checks,
               "mismatches": mismatches[:20]}
    if status == "passed":
        audit_log.append(db, action="recon.passed", outcome="ok", details=details, **ctx)
    else:
        audit_log.append(db, action="recon.mismatch", outcome="error", details=details, **ctx)
        _log.error("recon.mismatch run_id=%s count=%d", run_id, len(result.mismatches))
    db.commit()
    audit_log.anchor(db)   # after the commit: the head goes to the platform logs, outside the database
    return {"id": str(run_id), "business_date": business_date.isoformat(), "status": status,
            "checks": checks, "mismatches": mismatches}


def list_runs(db: Session, limit: int = 50) -> list[dict]:
    rows = db.execute(text(
        "SELECT id, business_date, status, checks, created_at FROM recon_runs ORDER BY created_at DESC LIMIT :n"
    ), {"n": max(1, min(int(limit), 100))}).all()
    return [{"id": str(r.id), "business_date": r.business_date.isoformat(), "status": r.status,
             "checks": r.checks, "created_at": r.created_at.isoformat()} for r in rows]


def get_run(db: Session, run_id: uuid.UUID) -> dict | None:
    r = db.execute(text(
        "SELECT id, business_date, status, checks, mismatches, created_at FROM recon_runs WHERE id = :r"
    ), {"r": run_id}).first()
    if r is None:
        return None
    return {"id": str(r.id), "business_date": r.business_date.isoformat(), "status": r.status,
            "checks": r.checks, "mismatches": r.mismatches, "created_at": r.created_at.isoformat()}
