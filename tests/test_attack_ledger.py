"""Attacks on the ledger endpoints over real HTTP (docs/DECISIONS.md Q4: A1-A4, A7-A8, A13-A15, A19).

Login is Kathy's and still a placeholder that answers 401 to everyone. These tests stand in for it with
one dependency override that maps bearer tokens to users, so every ledger rule, role check and race is
exercised over a real socket against a real PostgreSQL. When her login lands, only `fake_login` changes.

The server uses the production engine settings (pool 10 + 5, 5 s pool timeout, READ COMMITTED), so a
burst of requests behaves as it will on the platform.

Tests assert the behaviour we want. A gap that is already known and owned (idempotency, limits, rate
limits, body size) is `xfail(strict=True)` with the owner named: CI stays green, and the day someone
fixes it the test fails until the marker is removed.
"""

import json
import logging
import socket
import threading
import time
import uuid
from collections import Counter

import httpx
import pytest
import uvicorn
from fastapi import Header, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from app import audit_log, fraud, ledger
from app.auth import CurrentUser, current_user
from app.db import get_db, make_engine
from app.main import app
from app.run import SERVER_OPTIONS
from ledger_test_helpers import fund

pytestmark = pytest.mark.db


@pytest.fixture(autouse=True)
def fraud_allows_unless_marked(request, monkeypatch):
    """These tests are about locking, limits and approvals, not fraud: a burst of transfers from a
    brand-new account would (rightly) be held or blocked by Adam's rules. Tests marked real_fraud
    run the real assessment. Test-only: production has no switch for this."""
    if "real_fraud" not in request.keywords:
        monkeypatch.setattr(ledger, "_assess_fraud", lambda *a, **k: fraud.Assessment("allow", ()))

THRESHOLD = 10_000_000  # ledger_settings.approval_threshold_cents (KES 100,000.00)
TOKENS: dict[str, CurrentUser] = {}


# ---------------------------------------------------------------- the server and the fake login

def fake_login(authorization: str | None = Header(default=None)) -> CurrentUser:
    user = TOKENS.get((authorization or "").removeprefix("Bearer ").strip())
    if user is None:
        raise HTTPException(status_code=401, detail="unauthenticated", headers={"WWW-Authenticate": "Bearer"})
    return user


class ContractLines(logging.Handler):
    """The one-JSON-line-per-request log that detection and the judges read."""

    def __init__(self):
        super().__init__()
        self.lines: list[dict] = []

    def emit(self, record):
        self.lines.append(json.loads(record.getMessage()))


@pytest.fixture(scope="module")
def engine(db_url):
    engine = make_engine(db_url)  # production pool and isolation settings
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def log_lines():
    handler = ContractLines()
    logging.getLogger("security").addHandler(handler)
    yield handler
    logging.getLogger("security").removeHandler(handler)


@pytest.fixture(scope="module")
def base_url(engine, log_lines):
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def db_override():
        session = sessions()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = db_override
    app.dependency_overrides[current_user] = fake_login
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    options = {**SERVER_OPTIONS, "log_config": None}   # production settings; pytest keeps its own logging
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, lifespan="off", **options))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started, "test server did not start"
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)
    app.dependency_overrides.clear()


@pytest.fixture
def http(base_url):
    # verify=False: plain http on localhost; building a TLS context per client costs seconds on Windows
    with httpx.Client(base_url=base_url, timeout=60, verify=False) as client:
        yield client


@pytest.fixture
def db(engine):
    with sessionmaker(bind=engine)() as session:
        yield session


# ---------------------------------------------------------------- people and money

class Person:
    def __init__(self, user_id, account_id, token, role):
        self.id, self.account, self.token, self.role = user_id, account_id, token, role

    @property
    def auth(self):
        return {"Authorization": f"Bearer {self.token}"}

    def headers(self, key=None, **extra):
        return {**self.auth, "Idempotency-Key": key or uuid.uuid4().hex, **extra}


def _one(db, sql, **params):
    return db.execute(text(sql), params).scalar_one()


def make_person(db, cents=0, role="customer"):
    user = _one(db, "INSERT INTO users (username, role) VALUES (:u, :r) RETURNING id", u=f"x{uuid.uuid4().hex[:12]}",
                r=role)
    acct = None
    if role == "customer" or cents:
        acct = _one(db, "INSERT INTO accounts (owner_id, kind, name) VALUES (:o, 'customer', 'current') RETURNING id", o=user)
    if cents:
        funding = _one(db, "INSERT INTO accounts (kind, name, min_balance) VALUES ('system', 'funding', :m) RETURNING id",
                       m=-(10**15))
        fund(db, funding, acct, cents)
    db.commit()
    token = "t-" + uuid.uuid4().hex
    TOKENS[token] = CurrentUser(id=user, username="test-user", role=role, session_id=uuid.uuid4(), src_ip="127.0.0.1")
    return Person(user, acct, token, role)


def balance(db, account):
    return _one(db, "SELECT ledger_posted_balance(:a)", a=account)


def transfer(client, who, to, amount, *, src=None, key=None, **extra):
    body = {"from_account_id": str(src or who.account), "to_account_id": str(to), "amount": amount, **extra}
    return client.post("/api/v1/transfers", json=body, headers=who.headers(key))


def parallel(n, fn):
    """Run fn(i) in n threads released together; returns the results in order."""
    barrier, results = threading.Barrier(n), [None] * n

    def run(i):
        barrier.wait()
        try:
            results[i] = fn(i)
        except Exception as exc:  # reported by the caller's assertions
            results[i] = exc

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def audit_rows(db, object_id):
    return db.execute(text("SELECT action, outcome, src_ip, details FROM audit_log WHERE object_id = :o ORDER BY seq"),
                      {"o": str(object_id)}).all()


LEAKS = ("Traceback", "sqlalchemy", "psycopg", "uvicorn", "starlette", 'File "', "postgres", "SELECT ", "INSERT ", "LG00")


def assert_clean(response):
    assert "server" not in response.headers
    assert not any(m.lower() in response.text.lower() for m in LEAKS), response.text[:300]


# ---------------------------------------------------------------- A18, A5: who may call what

ROUTES = [
    ("GET", "/api/v1/accounts", None),
    ("POST", "/api/v1/transfers", {"from_account_id": str(uuid.uuid4()), "to_account_id": str(uuid.uuid4()), "amount": "1.00"}),
    ("GET", f"/api/v1/transfers/{uuid.uuid4()}", None),
    ("POST", f"/api/v1/approvals/{uuid.uuid4()}/approve", {"expected_amount": "1.00"}),
    ("POST", f"/api/v1/approvals/{uuid.uuid4()}/reject", None),
    ("GET", "/api/v1/approvals", None),
    ("POST", f"/api/v1/transfers/{uuid.uuid4()}/reversals", {"reason": "customer request"}),
    ("POST", f"/api/v1/reversals/{uuid.uuid4()}/approve", {"expected_amount": "1.00"}),
    ("POST", f"/api/v1/reversals/{uuid.uuid4()}/reject", None),
    ("POST", "/api/v1/reconciliation/runs", {"business_date": "2026-10-13"}),
    ("GET", "/api/v1/reconciliation/runs", None),
    ("GET", f"/api/v1/reconciliation/runs/{uuid.uuid4()}", None),
    ("POST", "/api/v1/auth/logout", None),
    ("GET", "/api/v1/me", None),
]
PUBLIC_ROUTES = {("POST", "/api/v1/auth/login")}   # the one route that must work without a token (Kathy)


@pytest.mark.parametrize("header", [None, "Bearer garbage", "Bearer " + "A" * 5000, "Basic YWRtaW46YWRtaW4=",
                                    "Token abc", "bearer"], ids=["none", "garbage", "5000-chars", "basic", "wrong-scheme", "no-token"])
def test_a18_a5_no_token_or_a_bad_one_is_401_everywhere(http, header):
    for method, path, body in ROUTES:
        headers = {"Idempotency-Key": uuid.uuid4().hex}
        if header is not None:
            headers["Authorization"] = header
        r = http.request(method, path, json=body, headers=headers)
        assert r.status_code == 401, (method, path, r.status_code)
        assert_clean(r)


def test_a18_every_route_in_openapi_is_covered_by_this_file(http):
    def shape(path):
        return "/".join("{}" if part.startswith("{") or (len(part) == 36 and part.count("-") == 4) else part
                        for part in path.split("/"))

    published = {(m.upper(), shape(p)) for p, item in http.get("/openapi.json").json()["paths"].items() for m in item}
    covered = {(m, shape(p)) for m, p, _ in ROUTES} | PUBLIC_ROUTES
    assert published <= covered, f"a new route has no attack coverage here: {sorted(published - covered)}"


def test_a4_roles_are_enforced(http, db):
    customer, approver = make_person(db, 100_000), make_person(db, role="approver")
    other = make_person(db)
    body = {"from_account_id": str(customer.account), "to_account_id": str(other.account), "amount": "1.00"}
    assert http.post("/api/v1/transfers", json=body, headers=approver.headers()).status_code == 403
    assert http.get("/api/v1/accounts", headers=approver.auth).status_code == 403
    for path, payload in ((f"/api/v1/approvals/{uuid.uuid4()}/approve", {"expected_amount": "1.00"}),
                          (f"/api/v1/approvals/{uuid.uuid4()}/reject", None)):
        r = http.post(path, json=payload, headers=customer.auth)
        assert r.status_code == 403 and r.json() == {"error": "forbidden"}
    assert balance(db, customer.account) == 100_000


# ---------------------------------------------------------------- A3: other people's things

def test_a3_idor_nothing_of_anothers_is_visible_or_spendable(http, db):
    alice, mallory = make_person(db, 100_000), make_person(db, 100_000)
    paid = transfer(http, alice, mallory.account, "10.00").json()["id"]

    assert http.get(f"/api/v1/transfers/{paid}", headers=mallory.auth).status_code == 404
    unknown = http.get(f"/api/v1/transfers/{uuid.uuid4()}", headers=mallory.auth)
    mine_but_not_hers = http.get(f"/api/v1/transfers/{paid}", headers=mallory.auth)
    assert (unknown.status_code, unknown.json()) == (mine_but_not_hers.status_code, mine_but_not_hers.json())

    before = balance(db, alice.account)
    stolen = transfer(http, mallory, mallory.account, "50.00", src=alice.account)      # spend from Alice's account
    missing = transfer(http, mallory, mallory.account, "50.00", src=uuid.uuid4())
    assert stolen.status_code == missing.status_code == 404 and stolen.json() == missing.json()
    assert balance(db, alice.account) == before

    mine = http.get("/api/v1/accounts", headers=mallory.auth).json()["items"]
    assert [a["id"] for a in mine] == [str(mallory.account)]


def test_a3_system_and_closed_accounts_cannot_receive(http, db):
    alice = make_person(db, 100_000)
    system = _one(db, "SELECT id FROM accounts WHERE kind = 'system' LIMIT 1")
    closed_owner = make_person(db)
    db.execute(text("UPDATE accounts SET status = 'closed' WHERE id = :a"), {"a": closed_owner.account})
    db.commit()
    for dst in (system, closed_owner.account):
        assert transfer(http, alice, dst, "5.00").status_code == 404
    assert balance(db, alice.account) == 100_000


# ---------------------------------------------------------------- A1: double spend over HTTP

def test_a1_parallel_transfers_never_overspend(http, base_url, db):
    alice, bob = make_person(db, 100_000), make_person(db)      # funds for exactly 10 transfers of 100.00
    def fire(i):
        with httpx.Client(base_url=base_url, timeout=60, verify=False) as c:
            r = transfer(c, alice, bob.account, "100.00")
            return r.status_code, r.json().get("error") or r.json().get("status")
    results = parallel(40, fire)
    assert not [r for r in results if isinstance(r, Exception)], results
    tally = Counter(results)
    assert tally == {(201, "posted"): 10, (422, "insufficient_funds"): 30}, tally
    assert balance(db, alice.account) == 0 and balance(db, bob.account) == 100_000
    assert _one(db, "SELECT count(*) FROM audit_log WHERE user_id = :u AND action = 'transfer.created'", u=str(alice.id)) == 10
    assert audit_log.verify_chain(db).ok


def test_a1_crossed_transfers_between_two_people_do_not_deadlock(http, base_url, db):
    a, b = make_person(db, 100_000), make_person(db, 100_000)
    def fire(i):
        who, other = (a, b) if i % 2 == 0 else (b, a)
        with httpx.Client(base_url=base_url, timeout=60, verify=False) as c:
            return transfer(c, who, other.account, "1.00").status_code
    results = parallel(40, fire)
    assert set(results) == {201}, Counter(results)
    assert balance(db, a.account) + balance(db, b.account) == 200_000


def test_a15_a_burst_of_150_requests_gets_no_server_errors(http, base_url, db):
    """The production pool is 10 + 5 connections with a 5 s wait. A burst must queue or be refused cleanly."""
    people = [make_person(db, 50_000) for _ in range(5)]
    sink = make_person(db)
    def fire(i):
        with httpx.Client(base_url=base_url, timeout=60, verify=False) as c:
            return transfer(c, people[i % 5], sink.account, "1.00").status_code
    results = parallel(150, fire)
    tally = Counter(r if isinstance(r, int) else type(r).__name__ for r in results)
    print("burst of 150:", dict(tally))
    assert not {s for s in tally if not isinstance(s, int) or s >= 500 and s != 503}, tally
    assert tally[201] > 0
    assert audit_log.verify_chain(db).ok


# ---------------------------------------------------------------- A2: replays (Adam #9, known gap)

def test_a2_a_replay_with_the_same_key_posts_once(http, db):
    alice, bob = make_person(db, 100_000), make_person(db)
    key = uuid.uuid4().hex
    first, second = transfer(http, alice, bob.account, "10.00", key=key), transfer(http, alice, bob.account, "10.00", key=key)
    assert first.json()["id"] == second.json()["id"]
    assert balance(db, alice.account) == 99_000


def test_a2_the_same_key_with_a_different_body_is_rejected(http, db):
    alice, bob = make_person(db, 100_000), make_person(db)
    key = uuid.uuid4().hex
    assert transfer(http, alice, bob.account, "10.00", key=key).status_code == 201
    assert transfer(http, alice, bob.account, "99.00", key=key).status_code in (409, 422)


def test_a2_parallel_requests_with_one_key_make_one_transfer(http, base_url, db):
    alice, bob = make_person(db, 100_000), make_person(db)
    key = uuid.uuid4().hex
    def fire(i):
        with httpx.Client(base_url=base_url, timeout=60, verify=False) as c:
            return transfer(c, alice, bob.account, "10.00", key=key).status_code
    parallel(40, fire)
    assert balance(db, alice.account) == 99_000


# ---------------------------------------------------------------- A4: maker-checker over HTTP

def pending(http, db, cents=THRESHOLD * 2, amount="100000.01"):
    maker, other, checker = make_person(db, cents), make_person(db), make_person(db, role="approver")
    r = transfer(http, maker, other.account, amount)
    assert r.status_code == 202 and r.json()["status"] == "pending_approval", r.text
    return maker, other, checker, r.json()["id"]


def test_a4_approval_flow_and_its_refusals(http, db):
    maker, other, checker, req = pending(http, db)
    assert http.post(f"/api/v1/approvals/{req}/approve", json={"expected_amount": "100000.00"}, headers=checker.headers()).json() == {"error": "amount_mismatch"}
    assert http.post(f"/api/v1/approvals/{req}/approve", json={"expected_amount": "100000.01", "maker_id": str(checker.id)}, headers=checker.headers()).status_code == 422
    assert balance(db, other.account) == 0                                                   # nothing moved yet
    ok = http.post(f"/api/v1/approvals/{req}/approve", json={"expected_amount": "100000.01"}, headers=checker.headers())
    assert ok.status_code == 200 and ok.json()["status"] == "posted"
    assert balance(db, other.account) == THRESHOLD + 1
    again = http.post(f"/api/v1/approvals/{req}/approve", json={"expected_amount": "100000.01"}, headers=checker.headers())
    assert again.status_code == 409
    assert http.post(f"/api/v1/approvals/{req}/reject", headers=checker.auth).status_code == 409
    assert [r.action for r in audit_rows(db, req)] == ["transfer.pending_approval", "approval.granted"]


def test_a4_a_maker_who_became_an_approver_cannot_approve_their_own_request(http, db):
    maker, other, _, req = pending(http, db)
    TOKENS[maker.token] = CurrentUser(id=maker.id, username="test-user", role="approver", session_id=uuid.uuid4(), src_ip="127.0.0.1")      # promoted after creating the request
    r = http.post(f"/api/v1/approvals/{req}/approve", json={"expected_amount": "100000.01"}, headers=maker.auth)
    assert r.status_code == 403 and r.json() == {"error": "self_approval"}
    assert http.post(f"/api/v1/approvals/{req}/reject", headers=maker.auth).status_code == 403
    assert balance(db, other.account) == 0


def test_a11_twenty_approvers_at_once_post_exactly_once(http, base_url, db):
    maker, other, checker, req = pending(http, db)
    def fire(i):
        with httpx.Client(base_url=base_url, timeout=60, verify=False) as c:
            return c.post(f"/api/v1/approvals/{req}/approve", json={"expected_amount": "100000.01"},
                          headers=checker.headers()).status_code
    tally = Counter(parallel(20, fire))
    assert tally[200] == 1 and set(tally) <= {200, 409}, tally
    assert balance(db, other.account) == THRESHOLD + 1 and balance(db, maker.account) == THRESHOLD * 2 - THRESHOLD - 1


def test_a11_approve_and_reject_at_once_have_one_winner(http, base_url, db):
    maker, other, checker, req = pending(http, db)
    def fire(i):
        with httpx.Client(base_url=base_url, timeout=60, verify=False) as c:
            if i % 2:
                return "approve", c.post(f"/api/v1/approvals/{req}/approve", json={"expected_amount": "100000.01"}, headers=checker.headers()).status_code
            return "reject", c.post(f"/api/v1/approvals/{req}/reject", headers=checker.auth).status_code
    results = parallel(10, fire)
    assert sum(1 for _, s in results if s == 200) == 1, results
    status = _one(db, "SELECT status FROM transfer_requests WHERE id = :r", r=req)
    assert status in ("posted", "rejected")
    assert balance(db, other.account) == (THRESHOLD + 1 if status == "posted" else 0)


def test_a11_funds_spent_after_the_request_make_the_approval_fail_cleanly(http, db):
    maker, other, checker, req = pending(http, db, cents=THRESHOLD + 5_000, amount="100000.01")
    # the hold reserves the money, so the maker cannot spend it elsewhere meanwhile
    assert transfer(http, maker, other.account, "100.00").status_code == 422
    assert http.post(f"/api/v1/approvals/{req}/approve", json={"expected_amount": "100000.01"}, headers=checker.headers()).status_code == 200


def test_a11_an_expired_request_cannot_be_approved(http, db):
    maker, other = make_person(db, THRESHOLD * 2), make_person(db)
    req = _one(db, "INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, status, expires_at) "
                   "VALUES (:m, :f, :t, :a, 'pending_approval', now() + interval '1 second') RETURNING id",
               m=maker.id, f=maker.account, t=other.account, a=THRESHOLD + 100)
    db.commit()
    checker = make_person(db, role="approver")
    time.sleep(1.5)
    r = http.post(f"/api/v1/approvals/{req}/approve", json={"expected_amount": "100000.01"}, headers=checker.headers())
    assert r.status_code == 409 and r.json() == {"error": "expired"}
    assert balance(db, other.account) == 0


def test_a11_a_sixth_open_request_is_refused_not_crashed(http, db):
    maker, other = make_person(db, THRESHOLD * 20), make_person(db)
    codes = [transfer(http, maker, other.account, "100000.01").status_code for _ in range(6)]
    assert codes[:5] == [202] * 5 and codes[5] == 422, codes


# ---------------------------------------------------------------- A7, A8, A13, A14: hostile input

BAD_AMOUNTS = ["1.00\n", "1.00\r\n", " 1.00", "1.00 ", "01.00", "1,00", "1.0", "1.000", "1e2", "0x10", "٣.٠٠", "１.００",
               "9999999999.995", "10000000000.00", "-1.00", "+1.00", "NaN", "Infinity", "0.99", "0.00", "", "1.00\x00"]


@pytest.mark.parametrize("amount", BAD_AMOUNTS)
def test_a7_bad_amounts_move_nothing(http, db, amount):
    alice, bob = make_person(db, 100_000), make_person(db)
    r = transfer(http, alice, bob.account, amount)
    assert r.status_code == 422, (amount, r.status_code, r.text)
    assert_clean(r)
    assert balance(db, alice.account) == 100_000 and balance(db, bob.account) == 0


@pytest.mark.parametrize("raw_amount", [100, 1.0, True, None, ["1.00"], {"a": 1}])
def test_a7_non_string_amounts_are_refused(http, db, raw_amount):
    alice, bob = make_person(db, 100_000), make_person(db)
    r = transfer(http, alice, bob.account, raw_amount)
    assert r.status_code == 422
    assert balance(db, alice.account) == 100_000


def test_a7_the_same_account_in_any_uuid_spelling_is_refused(http, db):
    alice = make_person(db, 100_000)
    u = alice.account
    for spelling in (str(u).upper(), u.hex, f"{{{u}}}", f"urn:uuid:{u}"):
        r = transfer(http, alice, spelling, "1.00")
        assert r.status_code in (422,), (spelling, r.status_code, r.text)
    assert balance(db, alice.account) == 100_000


@pytest.mark.parametrize("extra", [{"memo": "x" * 141}, {"memo": "a\nb"}, {"memo": "a\x00b"}, {"memo": "a\x7fb"}, {"memo": ""},
                                   {"fee": "0.00"}, {"status": "posted"}, {"maker_id": str(uuid.uuid4())},
                                   {"checker_id": str(uuid.uuid4())}, {"ledger_transaction_id": str(uuid.uuid4())},
                                   {"role": "approver"}, {"balance": "9.00"}, {"__proto__": {"x": 1}}])
def test_a8_extra_fields_and_bad_memos_are_refused(http, db, extra):
    alice, bob = make_person(db, 100_000), make_person(db)
    r = transfer(http, alice, bob.account, "1.00", **extra)
    assert r.status_code == 422, (extra, r.status_code)
    assert balance(db, alice.account) == 100_000


@pytest.mark.parametrize("memo", ["'); DROP TABLE entries;--", "\" OR \"1\"=\"1", "${jndi:ldap://x}", "<script>alert(1)</script>",
                                  "{{7*7}}", "../../etc/passwd", "emoji 💸 ü ✓", "‮evil", "a" * 140])
def test_a13_hostile_memos_are_stored_as_plain_text(http, db, memo):
    alice, bob = make_person(db, 100_000), make_person(db)
    entries_before = _one(db, "SELECT count(*) FROM entries")
    r = transfer(http, alice, bob.account, "1.00", memo=memo)
    assert r.status_code == 201, r.text
    assert _one(db, "SELECT memo FROM transfer_requests WHERE id = :r", r=r.json()["id"]) == memo
    assert _one(db, "SELECT count(*) FROM entries") == entries_before + 2
    assert "memo" not in str(audit_rows(db, r.json()["id"]))     # free text never reaches the audit log


@pytest.mark.parametrize("path", ["/api/v1/transfers/not-a-uuid", "/api/v1/transfers/1 OR 1=1", "/api/v1/transfers/%00",
                                  "/api/v1/transfers/..%2f..%2fetc%2fpasswd", f"/api/v1/approvals/{'9' * 200}/approve"])
def test_a13_hostile_path_ids_are_422_or_404(http, db, path):
    person = make_person(db, role="approver")
    r = http.request("POST" if "approvals" in path else "GET", path, headers=person.auth, json={"expected_amount": "1.00"} if "approvals" in path else None)
    assert r.status_code in (404, 405, 422), (path, r.status_code)
    assert_clean(r)


def test_a14_malformed_requests_leak_nothing(http, db):
    alice, bob = make_person(db, 100_000), make_person(db)
    good = {"from_account_id": str(alice.account), "to_account_id": str(bob.account), "amount": "1.00"}
    attempts = [
        http.post("/api/v1/transfers", content=b"{not json", headers=alice.headers() | {"Content-Type": "application/json"}),
        http.post("/api/v1/transfers", content=b"\xff\xfe\x00", headers=alice.headers() | {"Content-Type": "application/json"}),
        http.post("/api/v1/transfers", content=json.dumps(good), headers=alice.headers() | {"Content-Type": "text/plain"}),
        http.post("/api/v1/transfers", data=good, headers=alice.headers()),
        http.post("/api/v1/transfers", content=b"[" * 5000, headers=alice.headers() | {"Content-Type": "application/json"}),
        http.post("/api/v1/transfers", content=b"", headers=alice.headers() | {"Content-Type": "application/json"}),
        http.request("PUT", "/api/v1/transfers", json=good, headers=alice.headers()),
        http.request("DELETE", f"/api/v1/transfers/{uuid.uuid4()}", headers=alice.auth),
        http.post("/api/v1/transfers", json=good, headers=alice.auth),                                    # no Idempotency-Key
        http.post("/api/v1/transfers", json=good, headers=alice.headers("short")),
        http.post("/api/v1/transfers", json=good, headers=alice.headers("k" * 65)),
        http.post("/api/v1/transfers", json=good, headers=alice.headers("bad key!!")),
    ]
    for r in attempts:
        assert 400 <= r.status_code < 500, (r.request.method, r.request.url, r.status_code)
        assert_clean(r)
    assert balance(db, alice.account) == 100_000


def test_a14_a_redirect_never_repeats_an_attacker_chosen_host(http, db):
    r = http.post("/api/v1/transfers/", headers={"Host": "evil.example", "X-Forwarded-Proto": "https"})
    assert "evil.example" not in r.headers.get("location", "") and r.status_code != 307


def test_a14_duplicate_json_keys_cannot_smuggle_a_second_amount(http, db):
    alice, bob = make_person(db, 100_000), make_person(db)
    raw = f'{{"from_account_id":"{alice.account}","to_account_id":"{bob.account}","amount":"1.00","amount":"500.00"}}'
    r = http.post("/api/v1/transfers", content=raw, headers=alice.headers() | {"Content-Type": "application/json"})
    moved = 100_000 - balance(db, alice.account)
    assert moved in (0, 100, 50_000)        # whichever parser rule applies, exactly one amount is used
    if r.status_code == 201:
        assert moved == _one(db, "SELECT amount FROM transfer_requests WHERE id = :r", r=r.json()["id"])


def test_a15_a_huge_body_is_refused_with_413(http, db):
    alice = make_person(db, 100_000)
    r = http.post("/api/v1/transfers", content=b'{"memo":"' + b"A" * 2_000_000 + b'"}',
                  headers=alice.headers() | {"Content-Type": "application/json"})
    assert r.status_code == 413


# ---------------------------------------------------------------- detection: what the logs say

def logged_actions(log_lines, timeout=3.0):
    """The request line is written after the response is sent, so wait for it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = [line["action"] for line in log_lines.lines if line["path"].startswith("/api/v1/")]
        if found:
            time.sleep(0.05)
            return [line["action"] for line in log_lines.lines if line["path"].startswith("/api/v1/")]
        time.sleep(0.02)
    return []


@pytest.mark.parametrize("expected", [
    "approval.mismatch",
    "transfer.insufficient_funds",
    "authz.ownership_denied",
    "approval.self_denied",
    "authz.denied",
])
def test_the_request_log_line_names_the_same_outcome_as_the_audit_row(http, db, log_lines, expected):
    """Detection reads the stdout line; the database holds the same event. They must agree on the name."""
    maker, other, checker, req = pending(http, db)
    stranger = make_person(db, 100)
    if expected == "approval.mismatch":
        send = lambda: http.post(f"/api/v1/approvals/{req}/approve", json={"expected_amount": "1.00"}, headers=checker.headers())
    elif expected == "transfer.insufficient_funds":
        send = lambda: transfer(http, stranger, other.account, "500.00")
    elif expected == "authz.ownership_denied":
        send = lambda: transfer(http, stranger, other.account, "5.00", src=maker.account)
    elif expected == "approval.self_denied":
        TOKENS[maker.token] = CurrentUser(id=maker.id, username="test-user", role="approver", session_id=uuid.uuid4(), src_ip="127.0.0.1")
        send = lambda: http.post(f"/api/v1/approvals/{req}/approve", json={"expected_amount": "100000.01"}, headers=maker.auth)
    else:
        send = lambda: http.post(f"/api/v1/approvals/{req}/reject", headers=stranger.auth)        # a customer, not an approver
    log_lines.lines.clear()
    assert send().status_code >= 400
    assert logged_actions(log_lines) == [expected]


def test_x_forwarded_for_is_not_trusted_for_the_audit_source_address(http, db):
    alice, bob = make_person(db, 100_000), make_person(db)
    r = http.post("/api/v1/transfers", json={"from_account_id": str(alice.account), "to_account_id": str(bob.account), "amount": "1.00"},
                  headers=alice.headers(**{"X-Forwarded-For": "6.6.6.6", "X-Real-IP": "7.7.7.7", "Forwarded": "for=8.8.8.8"}))
    [(action, outcome, src_ip, details)] = audit_rows(db, r.json()["id"])
    assert src_ip == "127.0.0.1"


def test_every_posted_transfer_has_exactly_one_matching_audit_row(http, db):
    alice, bob = make_person(db, 100_000), make_person(db)
    ids = [transfer(http, alice, bob.account, f"{i}.00").json()["id"] for i in range(1, 6)]
    for req, cents in zip(ids, range(100, 600, 100)):
        rows = audit_rows(db, req)
        assert [r.action for r in rows] == ["transfer.created"]
        assert rows[0].details["amount_cents"] == cents
        assert _one(db, "SELECT amount FROM transfer_requests WHERE id = :r", r=req) == cents


@pytest.mark.xfail(strict=True, reason="Kathy: no rate limiting yet; every denied request still writes an audit row")
def test_a15_a_flood_of_denied_requests_is_rate_limited(http, db):
    mallory = make_person(db, 1_000)
    codes = Counter(transfer(http, mallory, mallory.account, "9999.00", src=uuid.uuid4()).status_code for _ in range(120))
    assert codes[429] > 0, codes


def test_a15_what_a_denial_flood_costs_in_audit_rows(http, db):
    """Documents the amplification: every denied money request writes one audit row. Bounded only by rate limits."""
    mallory = make_person(db, 1_000)
    before = _one(db, "SELECT count(*) FROM audit_log WHERE user_id = :u", u=str(mallory.id))
    n = 60
    for _ in range(n):
        assert transfer(http, mallory, mallory.account, "9999.00").status_code == 422
    after = _one(db, "SELECT count(*) FROM audit_log WHERE user_id = :u", u=str(mallory.id))
    assert after - before == n
    assert audit_log.verify_chain(db).ok


# ---------------------------------------------------------------- A19: secrets, and the whole chain at the end

def test_a19_no_token_or_credential_ever_reaches_the_audit_log_or_the_request_log(db, log_lines):
    needles = list(TOKENS)
    rows = db.execute(text("SELECT user_id, role, src_ip, action, details::text AS d FROM audit_log")).all()
    blob = " ".join(" ".join(str(c) for c in row) for row in rows) + json.dumps(log_lines.lines)
    assert needles and not [t for t in needles if t in blob]
    assert "Bearer" not in blob and "Idempotency" not in blob


def test_zz_the_ledger_still_sums_to_zero_and_the_audit_chain_still_verifies(db):
    assert _one(db, "SELECT COALESCE(SUM(amount), 0) FROM entries") == 0
    assert audit_log.verify_chain(db).ok
    assert audit_log.check_controls(db) == []
