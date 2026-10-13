"""Persistence guarantees for Adam's controls; these tests need PostgreSQL."""

from datetime import UTC, datetime
import threading
import time
import uuid

import pytest
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app import audit_log
from app.controls import (
    LimitExceeded,
    check_transfer_request_limits,
    check_transfer_limits,
    daily_outgoing_used_cents,
    fingerprint_operation,
    idempotency_key_hash,
    load_transfer_limits,
)
from app.idempotency import (
    IdempotencyConflict,
    claim_idempotency_key,
    prune_expired_idempotency_keys,
    save_idempotency_response,
)
from app.recon import (
    ReconciliationResult,
    ReconciliationRunAlreadyActive,
    finish_reconciliation_run,
    load_reconciliation_snapshot,
    reconcile,
    start_reconciliation_run,
)

pytestmark = pytest.mark.db


class RequestFingerprintBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    amount: str
    from_account_id: str | None = None
    to_account_id: str | None = None


def one(conn, sql, params=None, **kwargs):
    return conn.execute(text(sql), params or kwargs).scalar_one()


def make_user(conn):
    return one(conn, "INSERT INTO users (username) VALUES (:u) RETURNING id", u=f"u{uuid.uuid4().hex[:12]}")


def make_account(conn, owner=None, *, kind="customer", min_balance=0):
    return one(
        conn,
        "INSERT INTO accounts (owner_id, kind, name, min_balance) VALUES (:owner, :kind, 'adam-test', :floor) RETURNING id",
        owner=owner,
        kind=kind,
        floor=min_balance,
    )


def make_entry(conn, transaction_id, account_id, amount):
    conn.execute(
        text("INSERT INTO entries (transaction_id, account_id, amount) VALUES (:transaction_id, :account_id, :amount)"),
        {"transaction_id": transaction_id, "account_id": account_id, "amount": amount},
    )


def open_transfer(conn, maker, source, destination, amount, *, status="pending_approval"):
    return one(
        conn,
        "INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, status) "
        "VALUES (:maker, :source, :destination, :amount, :status) RETURNING id",
        maker=maker,
        source=source,
        destination=destination,
        amount=amount,
        status=status,
    )


def sqlstate(exc):
    return getattr(exc.orig, "sqlstate", None)


def expect_sqlstate(code, conn, fn):
    with pytest.raises(DBAPIError) as error:
        fn()
        conn.commit()
    conn.rollback()
    assert sqlstate(error.value) == code, str(error.value.orig)


@pytest.fixture
def conn(db_engine):
    with db_engine.connect() as connection:
        yield connection
        connection.rollback()


@pytest.fixture
def funded_accounts(conn):
    maker, teller, checker = make_user(conn), make_user(conn), make_user(conn)
    funding = make_account(conn, kind="system", min_balance=-(10**12))
    source = make_account(conn, maker)
    destination_owner = make_user(conn)
    destination = make_account(conn, destination_owner)
    transaction_id = one(conn, "INSERT INTO ledger_transactions (kind) VALUES ('opening') RETURNING id")
    make_entry(conn, transaction_id, funding, -200_000_000)
    make_entry(conn, transaction_id, source, 200_000_000)
    conn.commit()
    return {
        "maker": maker,
        "teller": teller,
        "checker": checker,
        "funding": funding,
        "source": source,
        "destination": destination,
        "destination_owner": destination_owner,
        "opening_transaction": transaction_id,
    }


def test_idempotency_claim_stores_and_replays_response(conn):
    user_id = make_user(conn)
    body = RequestFingerprintBody(from_account_id="a", to_account_id="b", amount="12.00")
    request_hash = fingerprint_operation("POST", "/api/v1/transfers", body)
    claim = claim_idempotency_key(conn, user_id=user_id, key="same-key", request_hash=request_hash)
    assert claim.owner and not claim.is_replay
    save_idempotency_response(conn, claim, status=201, body={"id": "request-id", "status": "posted"})
    conn.commit()

    replay = claim_idempotency_key(conn, user_id=user_id, key="same-key", request_hash=request_hash)
    assert replay.is_replay
    assert replay.response_status == 201
    assert replay.response_body == {"id": "request-id", "status": "posted"}
    conn.rollback()


def test_idempotency_conflict_is_user_scoped_and_does_not_replace_result(conn):
    user_a, user_b = make_user(conn), make_user(conn)
    first_hash = fingerprint_operation("POST", "/api/v1/transfers", RequestFingerprintBody(amount="10.00"))
    other_hash = fingerprint_operation("POST", "/api/v1/transfers", RequestFingerprintBody(amount="11.00"))
    claim = claim_idempotency_key(conn, user_id=user_a, key="shared-key", request_hash=first_hash)
    save_idempotency_response(conn, claim, status=201, body={"status": "posted"})
    conn.commit()

    with pytest.raises(IdempotencyConflict):
        claim_idempotency_key(conn, user_id=user_a, key="shared-key", request_hash=other_hash)
    user_b_claim = claim_idempotency_key(conn, user_id=user_b, key="shared-key", request_hash=other_hash)
    assert user_b_claim.owner
    conn.rollback()


def test_parallel_same_key_claims_return_one_saved_response(db_engine):
    with db_engine.begin() as conn:
        user_id = make_user(conn)
    request_hash = fingerprint_operation("POST", "/api/v1/transfers", RequestFingerprintBody(amount="25.00"))
    barrier = threading.Barrier(2)
    outcomes = []
    outcome_lock = threading.Lock()

    def worker():
        with db_engine.connect() as conn:
            barrier.wait()
            claim = claim_idempotency_key(
                conn,
                user_id=user_id,
                key="parallel-same-key",
                request_hash=request_hash,
            )
            if claim.owner:
                time.sleep(0.1)
                save_idempotency_response(conn, claim, status=202, body={"status": "held_review"})
                conn.commit()
                result = ("owner", 202, {"status": "held_review"})
            else:
                result = ("replay", claim.response_status, claim.response_body)
                conn.rollback()
        with outcome_lock:
            outcomes.append(result)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcome[0] for outcome in outcomes) == ["owner", "replay"]
    assert all(outcome[1:] == (202, {"status": "held_review"}) for outcome in outcomes)


def test_expired_idempotency_key_can_be_claimed_again_and_pruned(conn):
    user_id = make_user(conn)
    key_hash = idempotency_key_hash("a" * 64)
    request_hash = "b" * 64
    conn.execute(
        text(
            "INSERT INTO idempotency_keys (user_id, key_hash, request_hash, created_at, expires_at) "
            "VALUES (:user_id, :key_hash, :request_hash, now() - interval '48 hours', now() - interval '24 hours')"
        ),
        {"user_id": user_id, "key_hash": key_hash, "request_hash": request_hash},
    )
    conn.commit()

    claim = claim_idempotency_key(conn, user_id=user_id, key="a" * 64, request_hash=request_hash)
    assert claim.owner
    save_idempotency_response(conn, claim, status=200, body={"ok": True})
    conn.commit()
    conn.execute(
        text(
            "INSERT INTO idempotency_keys (user_id, key_hash, request_hash, created_at, expires_at) "
            "VALUES (:user_id, :key_hash, :request_hash, now() - interval '48 hours', now() - interval '24 hours')"
        ),
        {"user_id": user_id, "key_hash": idempotency_key_hash("expired1"), "request_hash": "e" * 64},
    )
    conn.commit()
    assert prune_expired_idempotency_keys(conn, batch_size=10) == 1
    conn.commit()


def test_idempotency_rows_cannot_be_changed_or_deleted_before_expiry(conn):
    user_id = make_user(conn)
    claim = claim_idempotency_key(conn, user_id=user_id, key="protected", request_hash="c" * 64)
    save_idempotency_response(conn, claim, status=200, body={"ok": True})
    conn.commit()
    expect_sqlstate(
        "LG002",
        conn,
        lambda: conn.execute(
            text("UPDATE idempotency_keys SET request_hash = :h WHERE id = :id"),
            {"h": "d" * 64, "id": claim.row_id},
        ),
    )
    expect_sqlstate("LG002", conn, lambda: conn.execute(text("DELETE FROM idempotency_keys WHERE id = :id"), {"id": claim.row_id}))


def test_idempotency_claim_cannot_commit_without_a_response(conn):
    user_id = make_user(conn)
    expect_sqlstate(
        "LG002",
        conn,
        lambda: conn.execute(
            text("INSERT INTO idempotency_keys (user_id, key_hash, request_hash) VALUES (:u, :k, :r)"),
            {"u": user_id, "k": "f" * 64, "r": "1" * 64},
        ),
    )


def test_transfer_limits_are_loaded_from_database_and_approval_excludes_its_own_hold(conn, funded_accounts):
    limits = load_transfer_limits(conn)
    assert (limits.minimum_cents, limits.per_transfer_cents, limits.per_day_cents) == (
        100,
        250_000,
        1_000_000,
    )

    requests = []
    for _ in range(4):
        requests.append(open_transfer(
            conn,
            funded_accounts["maker"],
            funded_accounts["source"],
            funded_accounts["destination"],
            250_000,
        ))
    assert daily_outgoing_used_cents(conn, funded_accounts["source"]) == 1_000_000
    # At approval, exclude the request's own open hold before adding its amount.
    check_transfer_request_limits(
        conn,
        account_id=funded_accounts["source"],
        amount_cents=250_000,
        request_id=requests[3],
    )
    with pytest.raises(LimitExceeded, match="daily_limit"):
        check_transfer_limits(100, daily_outgoing_used_cents(conn, funded_accounts["source"]), limits)
    with pytest.raises(LimitExceeded, match="per_transfer_limit"):
        check_transfer_limits(250_001, 0, limits)
    conn.commit()



def test_reversal_request_reserves_funds_and_only_posts_exact_opposite_entries(conn, funded_accounts):
    original_transaction = one(conn, "INSERT INTO ledger_transactions (kind) VALUES ('transfer') RETURNING id")
    make_entry(conn, original_transaction, funded_accounts["source"], -50_000)
    make_entry(conn, original_transaction, funded_accounts["destination"], 50_000)
    original_request = one(
        conn,
        "INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, status, ledger_transaction_id) "
        "VALUES (:maker, :source, :destination, 50000, 'posted', :transaction_id) RETURNING id",
        {
            "maker": funded_accounts["maker"],
            "source": funded_accounts["source"],
            "destination": funded_accounts["destination"],
            "transaction_id": original_transaction,
        },
    )
    conn.commit()

    reversal_request = one(
        conn,
        "INSERT INTO reversal_requests (original_request_id, requester_id, reason) "
        "VALUES (:original, :requester, 'customer claim') RETURNING id",
        {"original": original_request, "requester": funded_accounts["teller"]},
    )
    assert one(conn, "SELECT ledger_available_balance(:account)", account=funded_accounts["destination"]) == 0
    conn.commit()

    expect_sqlstate(
        "LG004",
        conn,
        lambda: open_transfer(
            conn,
            funded_accounts["destination"],
            funded_accounts["destination"],
            funded_accounts["source"],
            100,
        ),
    )

    reversal_transaction = one(
        conn,
        "INSERT INTO ledger_transactions (kind, reverses_id) VALUES ('reversal', :original) RETURNING id",
        {"original": original_transaction},
    )
    make_entry(conn, reversal_transaction, funded_accounts["destination"], -50_000)
    make_entry(conn, reversal_transaction, funded_accounts["source"], 50_000)
    conn.execute(
        text(
            "UPDATE reversal_requests SET status = 'posted', checker_id = :checker, "
            "reversal_transaction_id = :transaction_id WHERE id = :request_id"
        ),
        {
            "checker": funded_accounts["checker"],
            "transaction_id": reversal_transaction,
            "request_id": reversal_request,
        },
    )
    audit_log.append(
        conn,
        action="transfer.reversed",
        outcome="ok",
        user_id=funded_accounts["teller"],
        role="approver",
        object_type="reversal_request",
        object_id=reversal_request,
        details={
            "ledger_transaction_id": reversal_transaction,
            "reverses_id": original_transaction,
        },
    )
    conn.commit()
    assert one(conn, "SELECT ledger_posted_balance(:account)", account=funded_accounts["destination"]) == 0
    assert one(conn, "SELECT ledger_posted_balance(:account)", account=funded_accounts["source"]) == 200_000_000
    conn.commit()
    snapshot = load_reconciliation_snapshot(conn)
    assert str(reversal_transaction) in snapshot.audit_transaction_ids


def test_reversal_with_wrong_entries_is_rejected(conn, funded_accounts):
    original_transaction = one(conn, "INSERT INTO ledger_transactions (kind) VALUES ('transfer') RETURNING id")
    make_entry(conn, original_transaction, funded_accounts["source"], -10_000)
    make_entry(conn, original_transaction, funded_accounts["destination"], 10_000)
    original_request = one(
        conn,
        "INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, status, ledger_transaction_id) "
        "VALUES (:maker, :source, :destination, 10000, 'posted', :transaction_id) RETURNING id",
        {
            "maker": funded_accounts["maker"],
            "source": funded_accounts["source"],
            "destination": funded_accounts["destination"],
            "transaction_id": original_transaction,
        },
    )
    conn.commit()

    def post_wrong_reversal():
        reversal_request = one(
            conn,
            "INSERT INTO reversal_requests (original_request_id, requester_id, reason) "
            "VALUES (:original, :requester, 'incorrect reverse') RETURNING id",
            {"original": original_request, "requester": funded_accounts["teller"]},
        )
        reversal_transaction = one(
            conn,
            "INSERT INTO ledger_transactions (kind, reverses_id) VALUES ('reversal', :original) RETURNING id",
            {"original": original_transaction},
        )
        make_entry(conn, reversal_transaction, funded_accounts["destination"], -9_999)
        make_entry(conn, reversal_transaction, funded_accounts["source"], 9_999)
        conn.execute(
            text(
                "UPDATE reversal_requests SET status = 'posted', checker_id = :checker, "
                "reversal_transaction_id = :transaction_id WHERE id = :request_id"
            ),
            {
                "checker": funded_accounts["checker"],
                "transaction_id": reversal_transaction,
                "request_id": reversal_request,
            },
        )

    expect_sqlstate("LG003", conn, post_wrong_reversal)


def test_reconciliation_runs_are_single_active_and_persist_results(conn):
    admin = make_user(conn)
    today = datetime.now(UTC).date()
    run_id = start_reconciliation_run(conn, business_date=today, started_by=admin, role="admin")
    with pytest.raises(ReconciliationRunAlreadyActive):
        start_reconciliation_run(conn, business_date=today, started_by=admin, role="admin")
    conn.commit()

    finish_reconciliation_run(
        conn,
        run_id,
        ReconciliationResult(True, (), 12, 24),
        checks={"entries_balanced": True, "audit_chain": True},
        actor_id=admin,
        role="admin",
        audit_head_seq=1,
        audit_head_hash="a" * 64,
    )
    conn.commit()
    row = conn.execute(
        text("SELECT status, checks, mismatches, transaction_count, entry_count FROM recon_runs WHERE id = :id"),
        {"id": run_id},
    ).one()
    assert row.status == "passed"
    assert row.checks == {"entries_balanced": True, "audit_chain": True}
    assert row.mismatches == []
    assert (row.transaction_count, row.entry_count) == (12, 24)
    next_run = start_reconciliation_run(conn, business_date=today, started_by=admin, role="admin")
    assert next_run != run_id
    finish_reconciliation_run(
        conn,
        next_run,
        ReconciliationResult(False, ("ledger_total_nonzero",), 12, 24),
        checks={"entries_balanced": False},
        actor_id=admin,
        role="admin",
    )
    conn.commit()
    failed = conn.execute(text("SELECT status, mismatches FROM recon_runs WHERE id = :id"), {"id": next_run}).one()
    assert failed.status == "mismatch"
    assert failed.mismatches == ["ledger_total_nonzero"]


def test_reconciliation_loader_uses_ledger_transaction_ids_from_audit_details(conn, funded_accounts):
    transaction_id = funded_accounts["opening_transaction"]
    unaudited_transaction = one(conn, "INSERT INTO ledger_transactions (kind) VALUES ('opening') RETURNING id")
    make_entry(conn, unaudited_transaction, funded_accounts["funding"], -100)
    make_entry(conn, unaudited_transaction, funded_accounts["source"], 100)
    audit_log.append(
        conn,
        action="seed.loaded",
        outcome="ok",
        object_type="ledger_transaction",
        object_id=transaction_id,
        details={"ledger_transaction_id": transaction_id},
    )
    conn.commit()

    snapshot = load_reconciliation_snapshot(conn)
    assert str(transaction_id) in snapshot.audit_transaction_ids
    assert str(unaudited_transaction) not in snapshot.audit_transaction_ids
    assert snapshot.audit_chain_valid
    assert snapshot.audit_controls_problems == ()
    assert snapshot.audit_head_seq is not None
    result = reconcile(snapshot)
    assert f"audit_missing:{unaudited_transaction}" in result.mismatches
