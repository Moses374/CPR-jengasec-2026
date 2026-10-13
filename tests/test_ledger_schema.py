"""The database guarantees of migration 0002, each proven to fire.

These tests write raw SQL on purpose: they prove the database refuses bad data even when
application code is wrong or skipped. Amounts are cents (10000 = KES 100.00).
"""

import threading
import time
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.db import make_engine

pytestmark = pytest.mark.db

THRESHOLD = 10_000_000  # ledger_settings.approval_threshold_cents (KES 100,000.00)


# ---------------------------------------------------------------- helpers

def sqlstate(exc: DBAPIError) -> str | None:
    return getattr(exc.orig, "sqlstate", None)


def expect(code: str, conn, fn):
    """Run fn (which may defer the failure to commit) and assert the SQLSTATE."""
    with pytest.raises(DBAPIError) as e:
        fn()
        conn.commit()
    conn.rollback()
    assert sqlstate(e.value) == code, str(e.value.orig)


def one(conn, sql, **params):
    return conn.execute(text(sql), params).scalar_one()


def make_user(conn):
    return one(conn, "INSERT INTO users (username) VALUES (:u) RETURNING id", u=f"u{uuid.uuid4().hex[:12]}")


def make_account(conn, owner=None, *, kind="customer", min_balance=0, status="active"):
    return one(
        conn,
        "INSERT INTO accounts (owner_id, kind, name, min_balance, status) "
        "VALUES (:o, :k, 'test', :m, :s) RETURNING id",
        o=owner, k=kind, m=min_balance, s=status,
    )


def new_txn(conn, kind="transfer"):
    return one(conn, "INSERT INTO ledger_transactions (kind) VALUES (:k) RETURNING id", k=kind)


def add_entry(conn, txn, account, amount):
    conn.execute(
        text("INSERT INTO entries (transaction_id, account_id, amount) VALUES (:t, :a, :m)"),
        {"t": txn, "a": account, "m": amount},
    )


def post_transfer(conn, maker, src, dst, amount):
    """The full posting shape, without any app-level locking or checks."""
    txn = new_txn(conn)
    add_entry(conn, txn, src, -amount)
    add_entry(conn, txn, dst, amount)
    return one(
        conn,
        "INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, status, ledger_transaction_id) "
        "VALUES (:mk, :s, :d, :a, 'posted', :t) RETURNING id",
        mk=maker, s=src, d=dst, a=amount, t=txn,
    )


def open_request(conn, maker, src, dst, amount, status="pending_approval", expires="24 hours"):
    return one(
        conn,
        "INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, status, expires_at) "
        "VALUES (:mk, :s, :d, :a, :st, now() + CAST(:e AS interval)) RETURNING id",
        mk=maker, s=src, d=dst, a=amount, st=status, e=expires,
    )


def balance(conn, fn, account):
    return one(conn, f"SELECT {fn}(:a)", a=account)


@pytest.fixture
def conn(db_engine):
    with db_engine.connect() as c:
        yield c
        c.rollback()


@pytest.fixture
def world(conn):
    """A funded customer (KES 1,000.00), a second customer, a checker, and the funding account."""
    maker, other, checker = make_user(conn), make_user(conn), make_user(conn)
    conn.execute(text("UPDATE users SET role = 'approver' WHERE id = :c"), {"c": checker})  # migration 0004: checkers must be approvers
    funding = make_account(conn, kind="system", min_balance=-(10**15))
    src, dst = make_account(conn, maker), make_account(conn, other)
    opening = new_txn(conn, "opening")
    add_entry(conn, opening, funding, -100_000)
    add_entry(conn, opening, src, 100_000)
    conn.commit()
    return {"maker": maker, "checker": checker, "funding": funding, "src": src, "dst": dst}


# ------------------------------------------------------- double entry holds

def test_opening_balance_commits_and_is_derived(conn, world):
    assert balance(conn, "ledger_posted_balance", world["src"]) == 100_000
    assert balance(conn, "ledger_available_balance", world["src"]) == 100_000


@pytest.mark.parametrize("amounts", [[-500, 400], [700]], ids=["sum-not-zero", "single-entry"])
def test_unbalanced_transaction_rejected_at_commit(conn, world, amounts):
    def go():
        txn = new_txn(conn, "opening")
        for account, amount in zip([world["funding"], world["src"]], amounts):
            add_entry(conn, txn, account, amount)
    expect("LG001", conn, go)


def test_transaction_without_entries_rejected(conn, world):
    expect("LG001", conn, lambda: new_txn(conn, "opening"))


def test_opening_cannot_debit_a_customer(conn, world):
    def go():
        txn = new_txn(conn, "opening")
        add_entry(conn, txn, world["src"], -1_000)
        add_entry(conn, txn, world["dst"], 1_000)
    expect("LG003", conn, go)


def test_same_account_twice_in_one_transaction_rejected(conn, world):
    def go():
        txn = new_txn(conn, "opening")
        add_entry(conn, txn, world["src"], 1_000)
        add_entry(conn, txn, world["src"], -1_000)
    expect("23505", conn, go)  # unique_violation


@pytest.mark.parametrize("sql", [
    "UPDATE entries SET amount = amount * 2",
    "DELETE FROM entries",
    "TRUNCATE entries",
    "UPDATE ledger_transactions SET memo = 'x'",
    "DELETE FROM ledger_transactions",
    "TRUNCATE ledger_transactions CASCADE",
    "UPDATE ledger_settings SET value = 999999999999",
    "DELETE FROM ledger_settings",
])
def test_ledger_is_append_only(conn, world, sql):
    expect("LG002", conn, lambda: conn.execute(text(sql)))


def test_reversals_blocked_until_enabled(conn, world):
    def go():
        txn = one(conn, "SELECT ledger_transaction_id FROM transfer_requests WHERE id = :r",
                  r=post_transfer(conn, world["maker"], world["src"], world["dst"], 1_000))
        rev = one(conn, "INSERT INTO ledger_transactions (kind, reverses_id) VALUES ('reversal', :t) RETURNING id", t=txn)
        add_entry(conn, rev, world["dst"], -1_000)
        add_entry(conn, rev, world["src"], 1_000)
    expect("LG003", conn, go)


def test_timestamps_come_from_the_database(conn, world):
    txn = one(conn, "INSERT INTO ledger_transactions (kind, created_at) VALUES ('opening', '2000-01-01') RETURNING id")
    add_entry(conn, txn, world["funding"], -100)
    add_entry(conn, txn, world["dst"], 100)
    assert one(conn, "SELECT created_at > now() - interval '1 minute' FROM ledger_transactions WHERE id = :t", t=txn)
    conn.rollback()


# -------------------------------------------- ledger and requests agree

def test_transfer_commits_and_moves_money(conn, world):
    post_transfer(conn, world["maker"], world["src"], world["dst"], 25_000)
    conn.commit()
    assert balance(conn, "ledger_posted_balance", world["src"]) == 75_000
    assert balance(conn, "ledger_posted_balance", world["dst"]) == 25_000


def test_transfer_without_request_rejected(conn, world):
    def go():
        txn = new_txn(conn)
        add_entry(conn, txn, world["src"], -1_000)
        add_entry(conn, txn, world["dst"], 1_000)
    expect("LG003", conn, go)


def test_ledger_must_match_request_amount(conn, world):
    """Request says KES 10.00; the entries try to move KES 500.00."""
    def go():
        txn = new_txn(conn)
        add_entry(conn, txn, world["src"], -50_000)
        add_entry(conn, txn, world["dst"], 50_000)
        conn.execute(text(
            "INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, status, ledger_transaction_id) "
            "VALUES (:mk, :s, :d, 1000, 'posted', :t)"),
            {"mk": world["maker"], "s": world["src"], "d": world["dst"], "t": txn})
    expect("LG003", conn, go)


def test_posted_request_must_point_at_a_transfer(conn, world):
    def go():
        txn = new_txn(conn, "opening")
        add_entry(conn, txn, world["funding"], -1_000)
        add_entry(conn, txn, world["dst"], 1_000)
        conn.execute(text(
            "INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, status, ledger_transaction_id) "
            "VALUES (:mk, :s, :d, 1000, 'posted', :t)"),
            {"mk": world["maker"], "s": world["src"], "d": world["dst"], "t": txn})
    expect("LG003", conn, go)


# ------------------------------------------- an approval binds the request

@pytest.mark.parametrize("change", ["amount = 9000000", "to_account_id = :other", "maker_id = :other_user",
                                    "memo = 'edited'", "expires_at = now() + interval '5 days'"])
def test_request_core_fields_immutable(conn, world, change):
    """Approve-100-then-edit-to-1,000,000: every core field is refused, even alongside a legal transition."""
    req = open_request(conn, world["maker"], world["src"], world["dst"], 10_000)
    other, other_user = make_account(conn, world["checker"]), make_user(conn)
    conn.commit()
    expect("LG002", conn, lambda: conn.execute(
        text(f"UPDATE transfer_requests SET {change}, status = 'rejected', checker_id = :c WHERE id = :r"),
        {"c": world["checker"], "r": req, "other": other, "other_user": other_user}))


def test_requests_cannot_be_deleted(conn, world):
    open_request(conn, world["maker"], world["src"], world["dst"], 10_000)
    conn.commit()
    expect("LG002", conn, lambda: conn.execute(text("DELETE FROM transfer_requests")))
    expect("LG002", conn, lambda: conn.execute(text("TRUNCATE transfer_requests CASCADE")))


def approve(conn, req, checker, src, dst, amount):
    txn = new_txn(conn)
    add_entry(conn, txn, src, -amount)
    add_entry(conn, txn, dst, amount)
    conn.execute(text("UPDATE transfer_requests SET status = 'posted', checker_id = :c, ledger_transaction_id = :t "
                      "WHERE id = :r"), {"c": checker, "t": txn, "r": req})


def test_approval_posts_and_releases_hold(conn, world):
    req = open_request(conn, world["maker"], world["src"], world["dst"], 30_000)
    conn.commit()
    assert balance(conn, "ledger_available_balance", world["src"]) == 70_000
    approve(conn, req, world["checker"], world["src"], world["dst"], 30_000)
    conn.commit()
    assert balance(conn, "ledger_posted_balance", world["src"]) == 70_000
    assert balance(conn, "ledger_available_balance", world["src"]) == 70_000
    assert one(conn, "SELECT decided_at IS NOT NULL FROM transfer_requests WHERE id = :r", r=req)


def test_pending_approval_cannot_post_without_checker(conn, world):
    req = open_request(conn, world["maker"], world["src"], world["dst"], 10_000)
    conn.commit()
    expect("LG006", conn, lambda: approve(conn, req, None, world["src"], world["dst"], 10_000))


def test_maker_cannot_be_checker(conn, world):
    conn.execute(text("UPDATE users SET role = 'approver' WHERE id = :m"), {"m": world["maker"]})  # so only the CHECK can refuse
    req = open_request(conn, world["maker"], world["src"], world["dst"], 10_000)
    conn.commit()
    expect("23514", conn, lambda: approve(conn, req, world["maker"], world["src"], world["dst"], 10_000))


def test_checker_must_be_an_active_approver(conn, world):
    """Migration 0004: the database refuses a checker who is not an approver, or not active."""
    req = open_request(conn, world["maker"], world["src"], world["dst"], 10_000)
    conn.commit()
    customer = make_user(conn)  # default role: customer
    conn.commit()
    expect("AC001", conn, lambda: approve(conn, req, customer, world["src"], world["dst"], 10_000))
    conn.execute(text("UPDATE users SET is_active = false WHERE id = :c"), {"c": world["checker"]})
    conn.commit()
    expect("AC001", conn, lambda: approve(conn, req, world["checker"], world["src"], world["dst"], 10_000))


def test_above_threshold_cannot_post_directly(conn, world):
    rich = make_account(conn, world["maker"])
    txn = new_txn(conn, "opening")
    add_entry(conn, txn, world["funding"], -(THRESHOLD + 100))
    add_entry(conn, txn, rich, THRESHOLD + 100)
    conn.commit()
    expect("LG006", conn, lambda: post_transfer(conn, world["maker"], rich, world["dst"], THRESHOLD + 100))
    # held for review, then released without a checker: still refused
    req = open_request(conn, world["maker"], rich, world["dst"], THRESHOLD + 100, status="held_review")
    conn.commit()
    def release():
        t = new_txn(conn)
        add_entry(conn, t, rich, -(THRESHOLD + 100))
        add_entry(conn, t, world["dst"], THRESHOLD + 100)
        conn.execute(text("UPDATE transfer_requests SET status = 'posted', ledger_transaction_id = :t WHERE id = :r"),
                     {"t": t, "r": req})
    expect("LG006", conn, release)


def test_final_status_cannot_change(conn, world):
    req = open_request(conn, world["maker"], world["src"], world["dst"], 10_000)
    conn.execute(text("UPDATE transfer_requests SET status = 'rejected', checker_id = :c WHERE id = :r"),
                 {"c": world["checker"], "r": req})
    conn.commit()
    expect("LG005", conn, lambda: approve(conn, req, world["checker"], world["src"], world["dst"], 10_000))


def test_illegal_transition_rejected(conn, world):
    req = open_request(conn, world["maker"], world["src"], world["dst"], 10_000)
    conn.commit()
    expect("LG005", conn, lambda: conn.execute(
        text("UPDATE transfer_requests SET status = 'blocked' WHERE id = :r"), {"r": req}))


def test_checker_only_set_when_deciding(conn, world):
    req = open_request(conn, world["maker"], world["src"], world["dst"], 10_000, status="held_review")
    conn.commit()
    expect("LG006", conn, lambda: conn.execute(
        text("UPDATE transfer_requests SET status = 'pending_approval', checker_id = :c WHERE id = :r"),
        {"c": world["checker"], "r": req}))


def test_expiry_without_a_scheduler(conn, world):
    req = open_request(conn, world["maker"], world["src"], world["dst"], 40_000, expires="1 second")
    conn.commit()
    expect("LG005", conn, lambda: conn.execute(
        text("UPDATE transfer_requests SET status = 'expired' WHERE id = :r"), {"r": req}))  # not yet
    assert balance(conn, "ledger_available_balance", world["src"]) == 60_000
    conn.commit()
    time.sleep(1.2)
    # the hold is gone the moment it expires, with nothing having run
    assert balance(conn, "ledger_available_balance", world["src"]) == 100_000
    conn.commit()
    expect("LG005", conn, lambda: approve(conn, req, world["checker"], world["src"], world["dst"], 40_000))
    conn.execute(text("UPDATE transfer_requests SET status = 'expired' WHERE id = :r"), {"r": req})
    conn.commit()


def test_expiry_cannot_be_set_far_ahead(conn, world):
    expect("LG006", conn, lambda: open_request(conn, world["maker"], world["src"], world["dst"], 1_000,
                                               expires="30 days"))


# ----------------------------------------------------- funds and holds

def test_holds_reserve_funds(conn, world):
    open_request(conn, world["maker"], world["src"], world["dst"], 80_000)
    conn.commit()
    assert balance(conn, "ledger_available_balance", world["src"]) == 20_000
    expect("LG004", conn, lambda: open_request(conn, world["maker"], world["src"], world["dst"], 30_000))
    # a direct transfer cannot spend held money either
    expect("LG004", conn, lambda: post_transfer(conn, world["maker"], world["src"], world["dst"], 30_000))


def test_overdraft_rejected(conn, world):
    expect("LG004", conn, lambda: post_transfer(conn, world["maker"], world["src"], world["dst"], 100_001))


def test_open_requests_capped_per_account(conn, world):
    for _ in range(5):
        open_request(conn, world["maker"], world["src"], world["dst"], 1_000)
    conn.commit()
    expect("LG006", conn, lambda: open_request(conn, world["maker"], world["src"], world["dst"], 1_000))


def test_minimum_transfer_amount(conn, world):
    expect("23514", conn, lambda: open_request(conn, world["maker"], world["src"], world["dst"], 99))


# ------------------------------------------------------------ accounts

def test_system_accounts_cannot_send_or_receive_transfers(conn, world):
    expect("LG006", conn, lambda: post_transfer(conn, world["maker"], world["funding"], world["dst"], 1_000))
    expect("LG006", conn, lambda: post_transfer(conn, world["maker"], world["src"], world["funding"], 1_000))


def test_frozen_account_cannot_send(conn, world):
    conn.execute(text("UPDATE accounts SET status = 'frozen' WHERE id = :a"), {"a": world["src"]})
    conn.commit()
    expect("LG006", conn, lambda: post_transfer(conn, world["maker"], world["src"], world["dst"], 1_000))


@pytest.mark.parametrize("change", ["owner_id = NULL, kind = 'system'", "min_balance = -1000000", "currency = 'USD'"])
def test_account_ownership_and_floor_immutable(conn, world, change):
    expect("LG002", conn, lambda: conn.execute(text(f"UPDATE accounts SET {change} WHERE id = :a"), {"a": world["src"]}))


def test_accounts_cannot_be_deleted_or_reopened(conn, world):
    expect("LG002", conn, lambda: conn.execute(text("DELETE FROM accounts WHERE id = :a"), {"a": world["dst"]}))
    conn.execute(text("UPDATE accounts SET status = 'closed' WHERE id = :a"), {"a": world["dst"]})
    conn.commit()
    expect("LG005", conn, lambda: conn.execute(
        text("UPDATE accounts SET status = 'active' WHERE id = :a"), {"a": world["dst"]}))


def test_usernames_are_lowercase_only(conn):
    expect("23514", conn, lambda: conn.execute(text("INSERT INTO users (username) VALUES ('Admin')")))


# ---------------------------------------------------------- concurrency

def test_parallel_transfers_without_app_locks_never_overdraw(db_engine, conn, world):
    """50 transfers of KES 100.00 race on an account holding KES 1,000.00, with no
    application locking at all. The database alone must let exactly 10 through."""
    barrier = threading.Barrier(50)
    results: list[str] = []
    lock = threading.Lock()

    def worker():
        with db_engine.connect() as c:
            barrier.wait()
            try:
                post_transfer(c, world["maker"], world["src"], world["dst"], 10_000)
                c.commit()
                outcome = "ok"
            except DBAPIError as e:
                c.rollback()
                outcome = sqlstate(e) or "unknown"
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count("ok") == 10, results
    assert results.count("LG004") == 40, results  # nothing else (no deadlocks, no other errors)
    assert balance(conn, "ledger_posted_balance", world["src"]) == 0


def test_whole_ledger_sums_to_zero(conn):
    assert one(conn, "SELECT COALESCE(SUM(amount), 0) FROM entries") == 0


# ------------------------------------------------------------ app engine

def test_app_engine_pins_read_committed(db_url, db_engine):
    """Even if the server default is REPEATABLE READ, the app's engine uses READ COMMITTED."""
    name = db_url.rsplit("/", 1)[1]
    with db_engine.connect() as c:
        c.execute(text(f'ALTER DATABASE "{name}" SET default_transaction_isolation = \'repeatable read\''))
        c.commit()
    engine = make_engine(db_url)
    try:
        with engine.connect() as c:
            assert c.execute(text("SHOW transaction_isolation")).scalar_one() == "read committed"
    finally:
        engine.dispose()
        with db_engine.connect() as c:
            c.execute(text(f'ALTER DATABASE "{name}" RESET default_transaction_isolation'))
            c.commit()
