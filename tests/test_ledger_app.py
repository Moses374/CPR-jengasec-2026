"""app/ledger.py and its routes: flows, refusals, and the races from docs/DECISIONS.md Q3.

Amounts are cents (10000 = KES 100.00). The approval threshold is ledger_settings (KES 100,000.00).
"""

import threading
import uuid
from collections import Counter

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from app import audit_log, fraud, ledger
from app.auth import CurrentUser, current_user
from app.db import get_db
from app.main import app
from ledger_test_helpers import fund

THRESHOLD = 10_000_000


@pytest.fixture(autouse=True)
def fraud_allows_unless_marked(request, monkeypatch):
    """These tests are about locking, limits and approvals, not fraud: a burst of transfers from a
    brand-new account would (rightly) be held or blocked by Adam's rules. Tests marked real_fraud
    run the real assessment. Test-only: production has no switch for this."""
    if "real_fraud" not in request.keywords:
        monkeypatch.setattr(ledger, "_assess_fraud", lambda *a, **k: fraud.Assessment("allow", ()))


# --------------------------------------------------------------- amounts (no database)

@pytest.mark.parametrize("raw,cents", [("1.00", 100), ("1500.00", 150_000), ("9999999999.99", 999_999_999_999)])
def test_to_cents_exact(raw, cents):
    assert ledger.to_cents(raw) == cents
    assert ledger.from_cents(cents) == raw


@pytest.mark.parametrize("raw", [
    "0.00", "0.99", "1500", "1500.0", "1500.000", "0.001", "-5.00", "+5.00", "007.00", "1e3", "NaN", "Infinity",
    " 15.00", "15.00 ", "1_000.00", "1,000.00", "١٥٠٠.٠٠", "１００.００", "", "10000000000.00", 1500, 15.0, None,
])
def test_to_cents_rejects(raw):
    with pytest.raises(ledger.InvalidAmount):
        ledger.to_cents(raw)


def test_from_cents_negative():
    assert ledger.from_cents(-150) == "-1.50"


# --------------------------------------------------------------- database helpers


@pytest.fixture
def Session(db_engine):
    return sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)


def _one(db, sql, **p):
    return db.execute(text(sql), p).scalar_one()


def make_customer(db, cents=0, status="active"):
    """A user with one account holding `cents`, funded by an opening transaction."""
    user = _one(db, "INSERT INTO users (username) VALUES (:u) RETURNING id", u=f"u{uuid.uuid4().hex[:12]}")
    acct = _one(db, "INSERT INTO accounts (owner_id, kind, name) VALUES (:o, 'customer', 'current') RETURNING id", o=user)
    if cents:
        funding = _one(db, "INSERT INTO accounts (kind, name, min_balance) VALUES ('system', 'funding', :m) RETURNING id",
                       m=-(10**15))
        fund(db, funding, acct, cents)
    if status != "active":
        db.execute(text("UPDATE accounts SET status = :s WHERE id = :a"), {"s": status, "a": acct})
    db.commit()
    return ledger.Actor(user_id=user, role="customer", src_ip="10.0.0.1"), acct


def make_checker(db):
    user = _one(db, "INSERT INTO users (username, role) VALUES (:u, 'approver') RETURNING id",
                u=f"c{uuid.uuid4().hex[:12]}")
    db.commit()
    return ledger.Actor(user_id=user, role="approver", src_ip="10.0.0.2")


def audit_rows(db, request_id):
    return db.execute(text("SELECT action, details FROM audit_log WHERE object_id = :r ORDER BY seq"),
                      {"r": str(request_id)}).all()


# --------------------------------------------------------------- flows

@pytest.mark.db
def test_small_transfer_posts_with_audit_row(Session):
    with Session() as db:
        alice, a = make_customer(db, 100_000)
        _, b = make_customer(db)
        result = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=25_000)
        assert result.status == "posted"
        assert ledger.posted_balance(db, a) == 75_000 and ledger.posted_balance(db, b) == 25_000
        [(action, details)] = audit_rows(db, result.id)
        assert action == "transfer.created" and details["amount_cents"] == 25_000


@pytest.mark.db
def test_large_transfer_waits_holds_then_posts_on_approval(Session):
    with Session() as db:
        alice, a = make_customer(db, THRESHOLD + 50_000)
        _, b = make_customer(db)
        checker = make_checker(db)
        result = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=THRESHOLD + 1)
        assert result.status == "pending_approval"
        assert ledger.posted_balance(db, a) == THRESHOLD + 50_000
        assert ledger.available_balance(db, a) == 49_999          # held
        done = ledger.approve(db, checker, request_id=result.id, expected_amount_cents=THRESHOLD + 1)
        assert done.status == "posted"
        assert ledger.posted_balance(db, b) == THRESHOLD + 1
        assert [r.action for r in audit_rows(db, result.id)] == ["transfer.pending_approval", "approval.granted"]


@pytest.mark.db
def test_approval_refusals(Session):
    with Session() as db:
        alice, a = make_customer(db, THRESHOLD * 2)
        _, b = make_customer(db)
        checker = make_checker(db)
        req = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=THRESHOLD + 100).id
        maker_as_checker = ledger.Actor(user_id=alice.user_id, role="approver")
        with pytest.raises(ledger.SelfApproval):
            ledger.approve(db, maker_as_checker, request_id=req, expected_amount_cents=THRESHOLD + 100)
        with pytest.raises(ledger.ApprovalConflict, match="amount_mismatch"):
            ledger.approve(db, checker, request_id=req, expected_amount_cents=THRESHOLD + 99)
        assert ledger.reject(db, checker, request_id=req).status == "rejected"
        assert ledger.available_balance(db, a) == THRESHOLD * 2    # hold released
        with pytest.raises(ledger.ApprovalConflict, match="already_decided"):
            ledger.approve(db, checker, request_id=req, expected_amount_cents=THRESHOLD + 100)
        with pytest.raises(ledger.NotFound):
            ledger.approve(db, checker, request_id=uuid.uuid4(), expected_amount_cents=100)


@pytest.mark.db
def test_approval_fails_cleanly_when_account_frozen_meanwhile(Session):
    with Session() as db:
        alice, a = make_customer(db, THRESHOLD * 2)
        _, b = make_customer(db)
        checker = make_checker(db)
        req = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=THRESHOLD + 100).id
        db.execute(text("UPDATE accounts SET status = 'frozen' WHERE id = :a"), {"a": a})
        db.commit()
        with pytest.raises(ledger.TransferDenied, match="account_not_active"):
            ledger.approve(db, checker, request_id=req, expected_amount_cents=THRESHOLD + 100)
        assert _one(db, "SELECT status FROM transfer_requests WHERE id = :r", r=req) == "failed"
        assert ledger.available_balance(db, a) == THRESHOLD * 2    # hold released


@pytest.mark.db
def test_transfer_refusals(Session):
    with Session() as db:
        alice, a = make_customer(db, 10_000)
        bob, b = make_customer(db, 10_000)
        _, frozen = make_customer(db, 10_000, status="frozen")
        frozen_owner = ledger.Actor(user_id=_one(db, "SELECT owner_id FROM accounts WHERE id = :a", a=frozen))
        with pytest.raises(ledger.NotFound):                       # someone else's account
            ledger.create_transfer(db, alice, from_account_id=b, to_account_id=a, amount_cents=100)
        with pytest.raises(ledger.NotFound):                       # unknown destination
            ledger.create_transfer(db, alice, from_account_id=a, to_account_id=uuid.uuid4(), amount_cents=100)
        with pytest.raises(ledger.TransferDenied, match="same_account"):
            ledger.create_transfer(db, alice, from_account_id=a, to_account_id=a, amount_cents=100)
        with pytest.raises(ledger.InsufficientFunds):
            ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=10_001)
        with pytest.raises(ledger.TransferDenied, match="account_not_active"):
            ledger.create_transfer(db, frozen_owner, from_account_id=frozen, to_account_id=a, amount_cents=100)
        with pytest.raises(ledger.InvalidAmount):
            ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=99)
        assert ledger.posted_balance(db, a) == 10_000 and ledger.posted_balance(db, b) == 10_000
        logged = Counter(r.action for r in db.execute(text(
            "SELECT action FROM audit_log WHERE user_id = :u AND outcome = 'denied'"), {"u": str(alice.user_id)}))
        assert logged == Counter({"authz.ownership_denied": 2, "transfer.denied": 1, "transfer.insufficient_funds": 1})


@pytest.mark.db
def test_fraud_hooks_route_to_review_and_block(Session):
    with Session() as db:
        alice, a = make_customer(db, 50_000)
        _, b = make_customer(db)
        held = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=10_000,
                                      fraud_decision="review")
        blocked = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=10_000,
                                         fraud_decision="block")
        assert (held.status, blocked.status) == ("held_review", "blocked")
        assert ledger.available_balance(db, a) == 40_000           # review holds, block does not


# --------------------------------------------------------------- races

def _parallel(n, fn):
    barrier = threading.Barrier(n)
    out, lock = [], threading.Lock()

    def run(i):
        barrier.wait()
        try:
            r = fn(i)
            res = getattr(r, "status", "ok")
        except ledger.LedgerError as e:
            res = type(e).__name__
        except Exception as e:  # anything unexpected must show up in the assertion
            res = f"UNEXPECTED {type(e).__name__}: {e}"
        with lock:
            out.append(res)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return Counter(out)


@pytest.mark.db
def test_50_parallel_transfers_never_overspend(Session):
    with Session() as db:
        alice, a = make_customer(db, 100_000)                      # enough for exactly 10
        _, b = make_customer(db)

    def send(_):
        with Session() as s:
            return ledger.create_transfer(s, alice, from_account_id=a, to_account_id=b, amount_cents=10_000)

    assert _parallel(50, send) == Counter({"posted": 10, "InsufficientFunds": 40})
    with Session() as db:
        assert ledger.posted_balance(db, a) == 0
        assert _one(db, "SELECT COALESCE(SUM(amount), 0) FROM entries") == 0


@pytest.mark.db
def test_crossed_transfers_do_not_deadlock(Session):
    with Session() as db:
        alice, a = make_customer(db, 1_000_000)
        bob, b = make_customer(db, 1_000_000)

    def send(i):
        who, src, dst = (alice, a, b) if i % 2 else (bob, b, a)
        with Session() as s:
            return ledger.create_transfer(s, who, from_account_id=src, to_account_id=dst, amount_cents=1_000)

    assert _parallel(60, send) == Counter({"posted": 60})
    with Session() as db:
        assert ledger.posted_balance(db, a) + ledger.posted_balance(db, b) == 2_000_000


@pytest.mark.db
def test_20_parallel_approvals_post_once(Session):
    with Session() as db:
        alice, a = make_customer(db, THRESHOLD * 2)
        _, b = make_customer(db)
        checkers = [make_checker(db) for _ in range(20)]
        req = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=THRESHOLD + 100).id

    def approve(i):
        with Session() as s:
            return ledger.approve(s, checkers[i], request_id=req, expected_amount_cents=THRESHOLD + 100)

    assert _parallel(20, approve) == Counter({"posted": 1, "ApprovalConflict": 19})
    with Session() as db:
        assert ledger.posted_balance(db, b) == THRESHOLD + 100


@pytest.mark.db
def test_approve_and_reject_race_has_one_winner(Session):
    with Session() as db:
        alice, a = make_customer(db, THRESHOLD * 2)
        _, b = make_customer(db)
        approver, rejecter = make_checker(db), make_checker(db)
        req = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=THRESHOLD + 100).id

    def decide(i):
        with Session() as s:
            if i % 2:
                return ledger.approve(s, approver, request_id=req, expected_amount_cents=THRESHOLD + 100)
            return ledger.reject(s, rejecter, request_id=req)

    outcome = _parallel(2, decide)
    assert outcome["ApprovalConflict"] == 1 and outcome["posted"] + outcome["rejected"] == 1


@pytest.mark.db
def test_audit_chain_verifies_after_all_of_the_above(Session):
    with Session() as db:
        result = audit_log.verify_chain(db)
        assert result.ok, result


# --------------------------------------------------------------- HTTP layer

@pytest.fixture
def api(Session, monkeypatch):
    # login's rate limiter and the audit log open their own sessions through app.db.SessionLocal
    monkeypatch.setattr("app.db.SessionLocal", Session)

    def db_override():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = db_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def as_user(actor: ledger.Actor, role: str):
    app.dependency_overrides[current_user] = lambda: CurrentUser(id=actor.user_id, username="test-user", role=role, session_id=uuid.uuid4(), src_ip="127.0.0.1")


@pytest.mark.db
def test_routes_refuse_callers_without_a_valid_login(api):
    client = api
    assert client.get("/api/v1/accounts").status_code == 401
    r = client.post("/api/v1/transfers", headers={"Idempotency-Key": "k" * 16},
                    json={"from_account_id": str(uuid.uuid4()), "to_account_id": str(uuid.uuid4()), "amount": "1.00"})
    assert r.status_code == 401


@pytest.mark.db
def test_http_transfer_flow(api, Session):
    with Session() as db:
        alice, a = make_customer(db, 100_000)
        _, b = make_customer(db)
    as_user(alice, "customer")
    headers = {"Idempotency-Key": uuid.uuid4().hex}
    body = {"from_account_id": str(a), "to_account_id": str(b), "amount": "250.00"}

    r = api.post("/api/v1/transfers", json=body, headers=headers)
    assert r.status_code == 201 and r.json()["status"] == "posted"
    assert api.get(f"/api/v1/transfers/{r.json()['id']}").json()["amount"] == "250.00"
    [acct] = api.get("/api/v1/accounts").json()["items"]
    assert (acct["posted"], acct["available"]) == ("750.00", "750.00")

    fresh = lambda: {"Idempotency-Key": uuid.uuid4().hex}  # noqa: E731
    assert api.post("/api/v1/transfers", json={**body, "amount": "5000.00"}, headers=fresh()).json() == \
        {"error": "insufficient_funds"}
    swapped = {**body, "from_account_id": str(b), "to_account_id": str(a)}
    assert api.post("/api/v1/transfers", json=swapped, headers=fresh()).status_code == 404   # not hers
    # the first key, reused for a different body, is refused and moves nothing
    assert api.post("/api/v1/transfers", json={**body, "amount": "1.00"}, headers=headers).status_code == 409
    assert api.get("/api/v1/accounts").json()["items"][0]["posted"] == "750.00"


@pytest.mark.db
@pytest.mark.parametrize("change", [
    {"amount": 250}, {"amount": 2.5}, {"amount": "2.5"}, {"amount": "1e3"}, {"amount": "-1.00"},
    {"balance": "999999.00"}, {"status": "posted"}, {"maker_id": str(uuid.uuid4())},
    {"memo": "line\nbreak"}, {"memo": "x" * 141}, {"from_account_id": "1 OR 1=1"},
])
def test_http_rejects_bad_input_without_echo(api, Session, change):
    with Session() as db:
        alice, a = make_customer(db, 100_000)
        _, b = make_customer(db)
    as_user(alice, "customer")
    body = {"from_account_id": str(a), "to_account_id": str(b), "amount": "1.00", **change}
    r = api.post("/api/v1/transfers", json=body, headers={"Idempotency-Key": uuid.uuid4().hex})
    assert r.status_code == 422
    assert "999999" not in r.text and "OR 1=1" not in r.text and "break" not in r.text


@pytest.mark.db
def test_http_requires_idempotency_key_and_roles(api, Session):
    with Session() as db:
        alice, a = make_customer(db, 100_000)
        _, b = make_customer(db)
    as_user(alice, "customer")
    body = {"from_account_id": str(a), "to_account_id": str(b), "amount": "1.00"}
    assert api.post("/api/v1/transfers", json=body).status_code == 422
    assert api.post("/api/v1/transfers", json=body, headers={"Idempotency-Key": "short"}).status_code == 422
    r = api.post(f"/api/v1/approvals/{uuid.uuid4()}/approve", json={"expected_amount": "1.00"})
    assert r.status_code == 403                                   # customers cannot approve
    as_user(alice, "approver")
    assert api.post("/api/v1/transfers", json=body, headers={"Idempotency-Key": uuid.uuid4().hex}).status_code == 403


# --------------------------------------------------------------- body size limit

def test_chunked_body_without_content_length_is_still_limited():
    """A client that omits or lies about Content-Length still cannot send more than 16 KB."""
    client = TestClient(app)

    def chunks():
        for _ in range(40):
            yield b"A" * 1024

    r = client.post("/api/v1/transfers", content=chunks(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.json() == {"error": "payload_too_large"}
    r = client.post("/api/v1/transfers", content=b"{}", headers={"Content-Length": "999999999"})
    assert r.status_code == 413


@pytest.mark.db
def test_small_bodies_pass_the_limit(api):
    r = api.post("/api/v1/transfers", json={"amount": "1.00"}, headers={"Idempotency-Key": "k" * 16})
    assert r.status_code == 401   # reached the route (and its auth), not stopped by the limit
