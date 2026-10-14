"""Idempotency, limits, fraud routing, held reviews, reversals and reconciliation (migration 0004,
app/ledger.py, app/recon.py). Amounts are cents: KSh 1.00 = 100.

Limits at bank scale: approval threshold KSh 100,000, KSh 250,000 per transfer, KSh 1,000,000 per day.
"""

import datetime
import threading
import uuid
from collections import Counter

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app import audit_log, controls, fraud, ledger, recon
from app.auth import CurrentUser, current_user
from app.db import get_db
from app.main import app
from ledger_test_helpers import fund

pytestmark = pytest.mark.db

KSH = 100
THRESHOLD = 100_000 * KSH
PER_TRANSFER = 250_000 * KSH
PER_DAY = 1_000_000 * KSH


@pytest.fixture(autouse=True)
def fraud_allows_unless_marked(request, monkeypatch):
    """Fraud is tested on purpose below (marked real_fraud); elsewhere it would hold the large transfers
    these tests make from brand-new accounts. Test-only: production has no switch for this."""
    if "real_fraud" not in request.keywords:
        monkeypatch.setattr(ledger, "_assess_fraud", lambda *a, **k: fraud.Assessment("allow", ()))


@pytest.fixture(scope="module")
def engine(fresh_db_url):
    # A clean database for this module, so reconciliation starts from a ledger with nothing unaudited.
    e = create_engine(fresh_db_url, isolation_level="READ COMMITTED", pool_size=40, max_overflow=0)
    yield e
    e.dispose()


@pytest.fixture
def Session(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _one(db, sql, **p):
    return db.execute(text(sql), p).scalar_one()


def person(db, cents=0, role="customer", age_days=30):
    """A user with one account funded by an opening balance, created age_days ago (so fraud's
    new-account signal only fires where a test wants it)."""
    uid = _one(db, "INSERT INTO users (username) VALUES (:u) RETURNING id", u=f"u{uuid.uuid4().hex[:12]}")
    acct = _one(db, "INSERT INTO accounts (owner_id, kind, name, created_at) VALUES (:o, 'customer', 'current', "
                    "now() - make_interval(days => :d)) RETURNING id", o=uid, d=age_days)
    if cents:
        funding = _one(db, "INSERT INTO accounts (kind, name, min_balance) VALUES ('system', 'funding', :m) "
                           "RETURNING id", m=-(10**15))
        fund(db, funding, acct, cents)
    db.commit()
    return ledger.Actor(user_id=uid, role=role, src_ip="10.0.0.9"), acct


def staff(db, role):
    uid = _one(db, "INSERT INTO users (username, role) VALUES (:u, :r) RETURNING id", u=f"s{uuid.uuid4().hex[:12]}",
               r=role)
    db.commit()
    return ledger.Actor(user_id=uid, role=role, src_ip="10.0.0.8")


def key(body: dict, k: str | None = None) -> ledger.Idempotency:
    return ledger.Idempotency.from_request(k or uuid.uuid4().hex, body)


def parallel(n, fn):
    barrier, out, lock = threading.Barrier(n), [], threading.Lock()

    def run(i):
        barrier.wait()
        try:
            r = fn(i)
            res = (r.status, r.replayed)
        except ledger.LedgerError as e:
            res = type(e).__name__
        except Exception as e:  # anything unexpected must show in the assertion
            res = f"UNEXPECTED {type(e).__name__}: {e}"
        with lock:
            out.append(res)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return Counter(out)


# ================================================================ idempotency

def test_replay_returns_the_first_result_and_moves_money_once(Session):
    with Session() as db:
        alice, a = person(db, 10_000 * KSH)
        _, b = person(db)
        body = {"from_account_id": str(a), "to_account_id": str(b), "amount": "100.00", "memo": None}
        k = key(body, "replay-key-0001")
        first = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=100 * KSH,
                                       idempotency=k)
        again = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=100 * KSH,
                                       idempotency=k)
        assert (again.id, again.status, again.replayed) == (first.id, "posted", True)
        assert ledger.posted_balance(db, b) == 100 * KSH
        actions = [r.action for r in db.execute(text("SELECT action FROM audit_log WHERE object_id = :r ORDER BY seq"),
                                                {"r": first.id})]
        assert actions == ["transfer.created", "transfer.duplicate"]


def test_same_key_different_body_is_refused_and_moves_nothing(Session):
    with Session() as db:
        alice, a = person(db, 10_000 * KSH)
        _, b = person(db)
        ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=100 * KSH,
                               idempotency=key({"amount": "100.00"}, "swap-key-0001"))
        with pytest.raises(ledger.IdempotencyConflict):
            ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=9_000 * KSH,
                                   idempotency=key({"amount": "9000.00"}, "swap-key-0001"))
        assert ledger.posted_balance(db, b) == 100 * KSH


def test_keys_are_per_user(Session):
    with Session() as db:
        alice, a = person(db, 1_000 * KSH)
        bob, b = person(db, 1_000 * KSH)
        r1 = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=KSH,
                                    idempotency=key({"x": 1}, "shared-key-0001"))
        r2 = ledger.create_transfer(db, bob, from_account_id=b, to_account_id=a, amount_cents=KSH,
                                    idempotency=key({"x": 1}, "shared-key-0001"))
        assert r1.id != r2.id and not r2.replayed


def test_thirty_parallel_requests_with_one_key_make_one_transfer(Session):
    with Session() as db:
        alice, a = person(db, 10_000 * KSH)
        _, b = person(db)
    k = key({"amount": "50.00"}, "burst-key-0001")

    def send(_):
        with Session() as s:
            return ledger.create_transfer(s, alice, from_account_id=a, to_account_id=b, amount_cents=50 * KSH,
                                          idempotency=k)

    outcome = parallel(30, send)
    assert outcome == Counter({("posted", False): 1, ("posted", True): 29}), outcome
    with Session() as db:
        assert ledger.posted_balance(db, b) == 50 * KSH


def test_raw_key_is_never_stored_and_records_are_write_once(Session):
    with Session() as db:
        alice, a = person(db, 1_000 * KSH)
        _, b = person(db)
        ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=KSH,
                               idempotency=key({"x": 2}, "secret-looking-key-42"))
        assert _one(db, "SELECT count(*) FROM idempotency_keys WHERE key_hash = :k OR fingerprint = :k",
                    k="secret-looking-key-42") == 0
        for sql in ("UPDATE idempotency_keys SET response = '{}'", "DELETE FROM idempotency_keys",
                    "TRUNCATE idempotency_keys"):
            with pytest.raises(DBAPIError) as e:
                db.execute(text(sql))
            db.rollback()
            assert e.value.orig.sqlstate == "LG002"


# ================================================================ limits

def test_app_limits_match_the_database_settings(Session):
    with Session() as db:
        assert _one(db, "SELECT ledger_setting('max_transfer_cents')") == controls.MAX_TRANSFER_CENTS == PER_TRANSFER
        assert _one(db, "SELECT ledger_setting('max_daily_outgoing_cents')") == controls.MAX_DAILY_OUTGOING_CENTS == PER_DAY
        # maker-checker is reachable: minimum < threshold < per transfer <= per day
        assert controls.MIN_TRANSFER_CENTS < _one(db, "SELECT ledger_setting('approval_threshold_cents')") \
            < PER_TRANSFER <= PER_DAY


def test_per_transfer_cap(Session):
    with Session() as db:
        alice, a = person(db, 2 * PER_TRANSFER)
        _, b = person(db)
        with pytest.raises(ledger.LimitRefused, match="per_transfer_limit"):
            ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=PER_TRANSFER + 1)
        assert ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b,
                                      amount_cents=PER_TRANSFER).status == "pending_approval"


def test_daily_cap_counts_open_requests_and_approval_does_not_count_twice(Session):
    with Session() as db:
        alice, a = person(db, 2 * PER_DAY)
        _, b = person(db)
        checker = staff(db, "approver")
        reqs = [ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=PER_TRANSFER).id
                for _ in range(4)]                                     # four pending = the whole day
        with pytest.raises(ledger.LimitRefused, match="daily_limit"):
            ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=KSH)
        # approving one at the cap must not count it twice
        assert ledger.approve(db, checker, request_id=reqs[0], expected_amount_cents=PER_TRANSFER).status == "posted"


def test_database_enforces_limits_without_the_app(Session):
    with Session() as db:
        alice, a = person(db, 2 * PER_TRANSFER)
        _, b = person(db)
        with pytest.raises(DBAPIError) as e:
            db.execute(text("INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, status) "
                            "VALUES (:m, :a, :b, :x, 'pending_approval')"),
                       {"m": alice.user_id, "a": a, "b": b, "x": PER_TRANSFER + 1})
        db.rollback()
        assert e.value.orig.sqlstate == "LG007"


# ================================================================ fraud and held reviews

@pytest.mark.real_fraud
def test_new_account_large_transfer_is_held_with_reasons_only_staff_see(Session):
    with Session() as db:
        alice, a = person(db, 200_000 * KSH, age_days=0)
        _, b = person(db)
        checker = staff(db, "approver")
        r = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=60_000 * KSH)
        assert r.status == "held_review"
        assert ledger.available_balance(db, a) == 140_000 * KSH          # the hold reserves funds
        [item] = [i for i in ledger.list_approvals(db, checker.user_id) if i["id"] == r.id]
        assert "new_account_amount" in item["reasons"]
        assert "reasons" not in ledger.get_request(db, r.id, alice.user_id)  # the customer never sees rules


@pytest.mark.real_fraud
def test_a_burst_of_transfers_is_reviewed_then_blocked(Session):
    with Session() as db:
        alice, a = person(db, 10_000 * KSH)
        _, b = person(db)
        outcomes = [ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b,
                                           amount_cents=KSH).status for _ in range(12)]
        assert outcomes[:5] == ["posted"] * 5
        assert set(outcomes[5:10]) == {"held_review"} and outcomes[10:] == ["blocked", "blocked"]


@pytest.mark.real_fraud
def test_seed_history_gives_fraud_a_baseline(Session):
    """Amina usually pays Brian about KSh 12,000 (migration 0007); KSh 60,000 is 5x that, so it is held."""
    with Session() as db:
        amina = db.execute(text("SELECT id FROM users WHERE username = 'amina.wekesa'")).scalar_one()
        src, dst = (db.execute(text(
            "SELECT a.id FROM accounts a JOIN users u ON u.id = a.owner_id WHERE u.username = :u AND a.name = 'Current'"),
            {"u": u}).scalar_one() for u in ("amina.wekesa", "brian.otieno"))
        actor = ledger.Actor(user_id=amina, role="customer")
        normal = ledger.create_transfer(db, actor, from_account_id=src, to_account_id=dst, amount_cents=11_000 * KSH)
        unusual = ledger.create_transfer(db, actor, from_account_id=src, to_account_id=dst, amount_cents=60_000 * KSH)
        assert (normal.status, unusual.status) == ("posted", "held_review")
        reasons = db.execute(text("SELECT fraud_reasons FROM transfer_requests WHERE id = :r"), {"r": unusual.id}).scalar_one()
        assert "amount_vs_typical" in reasons


def test_held_review_is_released_or_blocked_only_by_another_person(Session):
    with Session() as db:
        alice, a = person(db, 10_000 * KSH)
        _, b = person(db)
        checker = staff(db, "approver")
        held = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=500 * KSH,
                                      fraud_decision="review").id
        maker_as_approver = ledger.Actor(user_id=alice.user_id, role="approver")
        with pytest.raises(ledger.SelfApproval):
            ledger.approve(db, maker_as_approver, request_id=held, expected_amount_cents=500 * KSH)
        assert ledger.approve(db, checker, request_id=held, expected_amount_cents=500 * KSH).status == "posted"
        assert _one(db, "SELECT checker_id FROM transfer_requests WHERE id = :r", r=held) == checker.user_id

        held2 = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=500 * KSH,
                                       fraud_decision="review").id
        assert ledger.reject(db, checker, request_id=held2).status == "blocked"


def test_database_refuses_releasing_a_held_review_without_a_checker(Session):
    with Session() as db:
        alice, a = person(db, 10_000 * KSH)
        _, b = person(db)
        held = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=500 * KSH,
                                      fraud_decision="review").id
        txn = _one(db, "INSERT INTO ledger_transactions (kind) VALUES ('transfer') RETURNING id")
        db.execute(text("INSERT INTO entries (transaction_id, account_id, amount) VALUES (:t, :a, :n), (:t, :b, :p)"),
                   {"t": txn, "a": a, "b": b, "n": -500 * KSH, "p": 500 * KSH})
        with pytest.raises(DBAPIError) as e:
            db.execute(text("UPDATE transfer_requests SET status = 'posted', ledger_transaction_id = :t WHERE id = :r"),
                       {"t": txn, "r": held})
        db.rollback()
        assert e.value.orig.sqlstate == "LG006"


# ================================================================ reversals

def posted_transfer(db, cents=1_000 * KSH):
    alice, a = person(db, 10_000 * KSH)
    bob, b = person(db, 0)
    r = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=cents)
    return alice, a, bob, b, r.id


def test_reversal_needs_a_teller_and_a_different_approver_and_restores_balances(Session):
    with Session() as db:
        _, a, _, b, tid = posted_transfer(db)
        teller, approver = staff(db, "teller"), staff(db, "approver")
        rid = ledger.request_reversal(db, teller, transfer_request_id=tid, reason="customer dispute").id
        with pytest.raises(ledger.SelfApproval):
            ledger.approve_reversal(db, teller, reversal_id=rid, expected_amount_cents=1_000 * KSH)
        with pytest.raises(ledger.AmountMismatch):
            ledger.approve_reversal(db, approver, reversal_id=rid, expected_amount_cents=999 * KSH)
        assert ledger.approve_reversal(db, approver, reversal_id=rid,
                                       expected_amount_cents=1_000 * KSH).status == "posted"
        assert (ledger.posted_balance(db, a), ledger.posted_balance(db, b)) == (10_000 * KSH, 0)
        rev_txn = _one(db, "SELECT ledger_transaction_id FROM reversal_requests WHERE id = :r", r=rid)
        assert _one(db, "SELECT kind FROM ledger_transactions WHERE id = :t", t=rev_txn) == "reversal"


def test_only_an_approver_can_approve_a_reversal(Session):
    """A second teller (not the maker) is still refused by the database: checkers must be approvers."""
    with Session() as db:
        _, _, _, b, tid = posted_transfer(db)
        teller, other_teller = staff(db, "teller"), staff(db, "teller")
        rid = ledger.request_reversal(db, teller, transfer_request_id=tid, reason="dispute").id
        with pytest.raises(ledger.NotApprover):
            ledger.approve_reversal(db, other_teller, reversal_id=rid, expected_amount_cents=1_000 * KSH)
        assert ledger.posted_balance(db, b) == 1_000 * KSH


def test_a_transfer_is_reversed_at_most_once(Session):
    with Session() as db:
        _, _, _, _, tid = posted_transfer(db)
        teller, approver = staff(db, "teller"), staff(db, "approver")
        rid = ledger.request_reversal(db, teller, transfer_request_id=tid, reason="first").id
        with pytest.raises(ledger.ApprovalConflict, match="already_reversed"):
            ledger.request_reversal(db, teller, transfer_request_id=tid, reason="second")
        ledger.reject_reversal(db, approver, reversal_id=rid)            # a rejected reversal frees the slot
        rid2 = ledger.request_reversal(db, teller, transfer_request_id=tid, reason="again").id
        ledger.approve_reversal(db, approver, reversal_id=rid2, expected_amount_cents=1_000 * KSH)
        with pytest.raises(ledger.ApprovalConflict, match="already_reversed"):
            ledger.request_reversal(db, teller, transfer_request_id=tid, reason="third")


def test_ten_parallel_approvals_of_one_reversal_post_once(Session):
    with Session() as db:
        _, a, _, b, tid = posted_transfer(db)
        teller = staff(db, "teller")
        approvers = [staff(db, "approver") for _ in range(10)]
        rid = ledger.request_reversal(db, teller, transfer_request_id=tid, reason="dispute").id

    def approve(i):
        with Session() as s:
            return ledger.approve_reversal(s, approvers[i], reversal_id=rid, expected_amount_cents=1_000 * KSH)

    assert parallel(10, approve) == Counter({("posted", False): 1, "ApprovalConflict": 9})
    with Session() as db:
        assert ledger.posted_balance(db, b) == 0


def test_reversal_fails_cleanly_when_the_recipient_spent_the_money(Session):
    with Session() as db:
        _, a, bob, b, tid = posted_transfer(db)
        _, c = person(db)
        ledger.create_transfer(db, bob, from_account_id=b, to_account_id=c, amount_cents=900 * KSH)
        teller, approver = staff(db, "teller"), staff(db, "approver")
        rid = ledger.request_reversal(db, teller, transfer_request_id=tid, reason="dispute").id
        with pytest.raises(ledger.InsufficientFunds):
            ledger.approve_reversal(db, approver, reversal_id=rid, expected_amount_cents=1_000 * KSH)
        assert _one(db, "SELECT status FROM reversal_requests WHERE id = :r", r=rid) == "failed"
        assert ledger.posted_balance(db, b) == 100 * KSH                 # nobody went below their floor


def test_only_posted_transfers_can_be_reversed(Session):
    with Session() as db:
        alice, a = person(db, 200_000 * KSH)
        _, b = person(db)
        pending = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b,
                                         amount_cents=THRESHOLD + KSH).id
        with pytest.raises(ledger.ApprovalConflict, match="not_posted"):
            ledger.request_reversal(db, staff(db, "teller"), transfer_request_id=pending, reason="x")


def test_database_refuses_a_reversal_that_is_not_the_exact_opposite(Session):
    with Session() as db:
        _, a, _, b, tid = posted_transfer(db)
        orig_txn = _one(db, "SELECT ledger_transaction_id FROM transfer_requests WHERE id = :r", r=tid)
        teller = staff(db, "teller")
        rid = ledger.request_reversal(db, teller, transfer_request_id=tid, reason="dispute").id
        approver = staff(db, "approver")
        txn = _one(db, "INSERT INTO ledger_transactions (kind, reverses_id) VALUES ('reversal', :o) RETURNING id",
                   o=orig_txn)
        db.execute(text("INSERT INTO entries (transaction_id, account_id, amount) VALUES (:t, :b, :n), (:t, :a, :p)"),
                   {"t": txn, "a": a, "b": b, "n": -10 * KSH, "p": 10 * KSH})   # only KSh 10 back, not 1,000
        db.execute(text("UPDATE reversal_requests SET status = 'posted', checker_id = :c, ledger_transaction_id = :t "
                        "WHERE id = :r"), {"c": approver.user_id, "t": txn, "r": rid})
        with pytest.raises(DBAPIError) as e:
            db.commit()
        db.rollback()
        assert e.value.orig.sqlstate == "LG003"


# ================================================================ reconciliation (last: it reads the whole ledger)

def test_zz_reconciliation_passes_on_a_clean_ledger_and_is_stored(Session):
    with Session() as db:
        admin = staff(db, "admin")
        result = recon.run(db, started_by=admin.user_id, business_date=datetime.date.today())
        assert result["status"] == "passed", result["mismatches"]
        assert result["checks"]["entries"] > 0
        assert recon.get_run(db, uuid.UUID(result["id"]))["status"] == "passed"
        with pytest.raises(DBAPIError):
            db.execute(text("UPDATE recon_runs SET status = 'passed'"))
        db.rollback()


def test_zz_reconciliation_finds_a_disabled_control_and_an_unaudited_transfer(Session, engine):
    with Session() as db:
        admin = staff(db, "admin")
        alice, a = person(db, 1_000 * KSH)
        _, b = person(db)
        # a transfer written straight into the database, bypassing the app (so no audit row)
        txn = _one(db, "INSERT INTO ledger_transactions (kind) VALUES ('transfer') RETURNING id")
        db.execute(text("INSERT INTO entries (transaction_id, account_id, amount) VALUES (:t, :a, :n), (:t, :b, :p)"),
                   {"t": txn, "a": a, "b": b, "n": -KSH, "p": KSH})
        db.execute(text("INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, status, "
                        "ledger_transaction_id) VALUES (:m, :a, :b, :x, 'posted', :t)"),
                   {"m": alice.user_id, "a": a, "b": b, "x": KSH, "t": txn})
        db.commit()
        db.execute(text("ALTER TABLE entries DISABLE TRIGGER entries_check_funds"))
        db.commit()
        try:
            result = recon.run(db, started_by=admin.user_id, business_date=datetime.date.today())
        finally:
            db.rollback()
            db.execute(text("ALTER TABLE entries ENABLE TRIGGER entries_check_funds"))
            db.commit()
        assert result["status"] == "mismatch"
        assert f"audit_missing:{txn}" in result["mismatches"]
        assert "ledger_control:trigger entries_check_funds is disabled" in result["mismatches"]


def test_zz_only_one_reconciliation_runs_at_a_time(Session, engine):
    with Session() as db, engine.connect() as holder:
        admin = staff(db, "admin")
        holder.execute(text("SELECT pg_advisory_lock(CAST(:k AS bigint))"), {"k": recon.RECON_LOCK_KEY})
        try:
            with pytest.raises(recon.ReconBusy):
                recon.run(db, started_by=admin.user_id, business_date=datetime.date.today())
        finally:
            holder.execute(text("SELECT pg_advisory_unlock(CAST(:k AS bigint))"), {"k": recon.RECON_LOCK_KEY})


# ================================================================ HTTP

@pytest.fixture
def api(Session):
    def db_override():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = db_override
    yield TestClient(app)
    app.dependency_overrides.clear()


def as_user(actor, role):
    app.dependency_overrides[current_user] = lambda: CurrentUser(id=actor.user_id, username="test-user", role=role, session_id=uuid.uuid4(), src_ip="127.0.0.1")


def test_http_replay_reversal_and_queue(api, Session):
    with Session() as db:
        alice, a = person(db, 10_000 * KSH)
        _, b = person(db)
        teller, approver = staff(db, "teller"), staff(db, "approver")
    as_user(alice, "customer")
    body = {"from_account_id": str(a), "to_account_id": str(b), "amount": "200.00"}
    k = {"Idempotency-Key": uuid.uuid4().hex}
    first = api.post("/api/v1/transfers", json=body, headers=k)
    replay = api.post("/api/v1/transfers", json=body, headers=k)
    assert (first.status_code, replay.status_code) == (201, 201) and first.json() == replay.json()
    assert api.post("/api/v1/transfers", json={**body, "amount": "201.00"}, headers=k).json() == \
        {"error": "idempotency_conflict"}

    as_user(teller, "teller")
    rev = api.post(f"/api/v1/transfers/{first.json()['id']}/reversals", json={"reason": "dispute"},
                   headers={"Idempotency-Key": uuid.uuid4().hex})
    assert rev.status_code == 202
    assert api.post(f"/api/v1/transfers/{first.json()['id']}/reversals", json={"reason": "x", "amount": "9.00"},
                    headers={"Idempotency-Key": uuid.uuid4().hex}).status_code == 422   # no amount field allowed
    as_user(approver, "approver")
    assert api.post(f"/api/v1/reversals/{rev.json()['id']}/approve",
                    json={"expected_amount": "200.00"}).json()["status"] == "posted"
    assert isinstance(api.get("/api/v1/approvals").json()["items"], list)
    as_user(approver, "customer")
    assert api.get("/api/v1/approvals").status_code == 403
