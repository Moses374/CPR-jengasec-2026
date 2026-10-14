"""The runtime role ledger_app (app/db_roles.py): the app works through it, and it cannot do what
an attacker with SQL access would want (switch off triggers, edit money, raise its own privileges).

Fixtures (users, funded accounts) are written as the owner, as migrations would; everything the app
does is done as ledger_app.
"""

import datetime
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app import audit_log, db_roles, fraud, ledger, recon
from app.auth import hash_password
from app.db import make_engine
from ledger_test_helpers import fund

pytestmark = pytest.mark.db


@pytest.fixture(scope="module")
def runtime_url(fresh_db_url):
    url = db_roles.setup(fresh_db_url)
    assert url is not None, "setup() fell back: the test server should allow CREATE ROLE"
    return url


@pytest.fixture(scope="module")
def owner(fresh_db_url):
    e = create_engine(fresh_db_url)
    yield e
    e.dispose()


@pytest.fixture(scope="module")
def app_engine(runtime_url):
    e = make_engine(runtime_url)   # the app's own engine settings
    yield e
    e.dispose()


@pytest.fixture(autouse=True)
def fraud_allows(monkeypatch):
    monkeypatch.setattr(ledger, "_assess_fraud", lambda *a, **k: fraud.Assessment("allow", ()))


def _one(c, sql, **p):
    return c.execute(text(sql), p).scalar_one()


def people(owner, role="customer", cents=0):
    with owner.connect() as c:
        uid = _one(c, "INSERT INTO users (username, role, password_hash) VALUES (:u, :r, :h) RETURNING id",
                   u=f"p{uuid.uuid4().hex[:12]}", r=role, h=hash_password("correct horse battery"))
        acct = _one(c, "INSERT INTO accounts (owner_id, kind, name, created_at) VALUES (:o, 'customer', 'c', "
                       "now() - interval '30 days') RETURNING id", o=uid)
        if cents:
            funding = _one(c, "SELECT id FROM accounts WHERE kind = 'system' LIMIT 1")
            fund(c, funding, acct, cents)
        c.commit()
    return ledger.Actor(user_id=uid, role=role, src_ip="10.0.0.5"), acct


# ---------------------------------------------------------------- it really is restricted

def test_runtime_role_is_not_a_superuser_and_owns_nothing(app_engine):
    with app_engine.connect() as c:
        assert _one(c, "SELECT current_user") == "ledger_app"
        assert _one(c, "SELECT current_setting('is_superuser')") == "off"
        assert _one(c, "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tableowner = 'ledger_app'") == 0


@pytest.mark.parametrize("sql", [
    "ALTER TABLE entries DISABLE TRIGGER entries_check_funds",            # switch off the overdraft backstop
    "ALTER TABLE ledger_transactions DISABLE TRIGGER ledger_transactions_no_new_openings",
    "UPDATE entries SET amount = amount * 2",                             # edit money
    "DELETE FROM entries",
    "TRUNCATE audit_log",                                                 # destroy the record
    "UPDATE audit_log SET action = 'login.ok'",
    "UPDATE transfer_requests SET amount = 1",                            # change an approved amount
    "UPDATE transfer_requests SET maker_id = checker_id",
    "UPDATE accounts SET status = 'active'",                              # unfreeze a frozen account
    "UPDATE accounts SET min_balance = -1000000",
    "UPDATE users SET role = 'admin'",                                    # promote yourself
    "UPDATE users SET password_hash = 'known'",                           # take over an admin's login
    "INSERT INTO users (username, role, password_hash) VALUES ('evil.admin', 'admin', 'x')",   # new admin
    "INSERT INTO accounts (owner_id, kind, name) VALUES (NULL, 'system', 'stash')",
    "DELETE FROM transfer_requests",
    "INSERT INTO ledger_settings (key, value) VALUES ('approval_threshold_cents_x', 1)",
    "CREATE TABLE stash (x int)",
    "SELECT set_config('role', 'payments', false)",                      # switch back to the owner
    "SELECT pg_read_file('/etc/passwd')",
])
def test_runtime_role_is_refused(app_engine, sql):
    with app_engine.connect() as c:
        with pytest.raises(DBAPIError) as e:
            c.execute(text(sql))
        c.rollback()
    assert e.value.orig.sqlstate == "42501", (sql, e.value.orig.sqlstate)   # insufficient_privilege


def test_controls_checks_see_no_extra_privileges(app_engine):
    with app_engine.connect() as c:
        assert audit_log.check_controls(c) == []
        assert recon.check_ledger_controls(c) == []


# ---------------------------------------------------------------- and the app still works through it

def test_money_flows_work_as_ledger_app(owner, app_engine):
    Session = sessionmaker(bind=app_engine, autoflush=False, expire_on_commit=False)
    alice, a = people(owner, cents=500_000_00)
    _, b = people(owner)
    checker, _ = people(owner, role="approver")
    teller, _ = people(owner, role="teller")
    with Session() as db:
        key = ledger.Idempotency.from_request(uuid.uuid4().hex, {"x": 1})
        small = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=10_000, idempotency=key)
        assert small.status == "posted"
        assert ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=10_000,
                                      idempotency=key).replayed
        big = ledger.create_transfer(db, alice, from_account_id=a, to_account_id=b, amount_cents=150_000_00)
        assert big.status == "pending_approval"
        assert ledger.approve(db, checker, request_id=big.id, expected_amount_cents=150_000_00).status == "posted"
        poor, p = people(owner, cents=1_000_00)
        with pytest.raises(ledger.InsufficientFunds):     # the refusal is recorded through record() too
            ledger.create_transfer(db, poor, from_account_id=p, to_account_id=b, amount_cents=2_000_00)
        rid = ledger.request_reversal(db, teller, transfer_request_id=small.id, reason="dispute").id
        assert ledger.approve_reversal(db, checker, reversal_id=rid, expected_amount_cents=10_000).status == "posted"
        run = recon.run(db, started_by=checker.user_id, business_date=datetime.date.today())
        assert run["status"] == "passed", run["mismatches"]


def test_login_logout_and_rate_limits_work_as_ledger_app(owner, app_engine, monkeypatch):
    from fastapi.testclient import TestClient

    from app.db import get_db
    from app.main import app

    Session = sessionmaker(bind=app_engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr("app.db.SessionLocal", Session)   # rate limiter and audit log open their own sessions

    def db_override():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = db_override
    try:
        user, _ = people(owner)
        with owner.connect() as c:
            name = _one(c, "SELECT username FROM users WHERE id = :u", u=user.user_id)
        client = TestClient(app)
        assert client.post("/api/v1/auth/login", json={"username": name, "password": "wrong password!"}).status_code == 401
        r = client.post("/api/v1/auth/login", json={"username": name, "password": "correct horse battery"})
        assert r.status_code == 200
        auth = {"Authorization": f"Bearer {r.json()['access_token']}"}
        assert client.get("/api/v1/accounts", headers=auth).status_code == 200
        assert client.post("/api/v1/auth/logout", headers=auth).status_code == 204
        assert client.get("/api/v1/accounts", headers=auth).status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_setup_falls_back_when_the_user_cannot_create_roles(runtime_url, caplog):
    """Run setup() as ledger_app itself (no CREATEROLE): it must return None, not fail the start."""
    with caplog.at_level("WARNING", logger="app.startup"):
        assert db_roles.setup(runtime_url) is None
    assert "db.least_privilege=unavailable" in caplog.text


def test_login_works_when_a_rehash_is_refused(owner, app_engine, monkeypatch):
    """An old-parameter hash wants a rehash; ledger_app may not write password hashes. Login must still work."""
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient

    from app.db import get_db
    from app.main import app

    old_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("old settings password")
    with owner.connect() as c:
        name = f"r{uuid.uuid4().hex[:12]}"
        c.execute(text("INSERT INTO users (username, role, password_hash) VALUES (:u, 'customer', :h)"),
                  {"u": name, "h": old_hash})
        c.commit()
    Session = sessionmaker(bind=app_engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr("app.db.SessionLocal", Session)

    def db_override():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = db_override
    try:
        r = TestClient(app).post("/api/v1/auth/login", json={"username": name, "password": "old settings password"})
        assert r.status_code == 200
    finally:
        app.dependency_overrides.clear()
    with owner.connect() as c:   # the hash was left as it was: the runtime role could not change it
        assert c.execute(text("SELECT password_hash FROM users WHERE username = :u"), {"u": name}).scalar_one() == old_hash
