"""Login, sessions, lockout, roles and ownership against a real PostgreSQL (docs/DECISIONS.md, Kathy Q1-Q4).

The app is pointed at the per-session test database by replacing app.db.SessionLocal and the get_db
dependency. Every test uses its own usernames and client addresses, so counters never collide.
"""

import itertools
import uuid

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from app import auth, ratelimit
from app import db as appdb
from app.main import app

pytestmark = pytest.mark.db

PASSWORD = "S3cure-test-password!"
_ips = itertools.count(1)


@pytest.fixture(scope="module")
def password_hash():
    return auth.hash_password(PASSWORD)


@pytest.fixture
def factory(db_engine, monkeypatch):
    maker = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(appdb, "SessionLocal", maker)

    def get_db():
        with maker() as session:
            yield session

    app.dependency_overrides[appdb.get_db] = get_db
    yield maker
    app.dependency_overrides.clear()


def new_client():
    n = next(_ips)
    return TestClient(app, client=(f"10.20.{n // 250}.{n % 250 + 1}", 5000))


@pytest.fixture
def make_user(factory, password_hash):
    def make(role="customer", active=True, password_hash_value=None):
        name = f"t{uuid.uuid4().hex[:12]}"
        with factory() as s:
            uid = s.execute(
                text("INSERT INTO users (username, password_hash, role, is_active) VALUES (:u, :h, :r, :a) RETURNING id"),
                {"u": name, "h": password_hash_value or password_hash, "r": role, "a": active},
            ).scalar_one()
            s.commit()
        return name, uid

    return make


def login(client, username, password=PASSWORD):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def bearer(resp):
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def sql(factory, statement, **params):
    with factory() as s:
        result = s.execute(text(statement), params)
        rows = result.all() if result.returns_rows else None
        s.commit()
        return rows


# -------------------------------------------------------------------------------- login
def test_login_me_and_audit(factory, make_user):
    name, uid = make_user("teller")
    c = new_client()
    r = login(c, name.upper() + " ")  # case and trailing space fold to the same user
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["expires_in"] == 1800
    me = c.get("/api/v1/me", headers=bearer(r))
    assert me.status_code == 200 and me.json() == {"user_id": str(uid), "username": name, "role": "teller"}
    actions = [x.action for x in sql(factory, "SELECT action FROM audit_log WHERE user_id = :u ORDER BY seq", u=str(uid))]
    assert actions == ["login.ok"]


def test_only_the_token_hash_is_stored(factory, make_user):
    name, uid = make_user()
    r = login(new_client(), name)
    token = r.json()["access_token"]
    rows = sql(factory, "SELECT token_hash FROM sessions WHERE user_id = :u", u=uid)
    assert len(rows) == 1 and token.encode() not in bytes(rows[0].token_hash)
    assert bytes(rows[0].token_hash) == auth.token_digest(token)


def test_unknown_user_wrong_password_inactive_and_odd_names_look_identical(make_user):
    name, _ = make_user()
    off, _ = make_user(active=False)
    nopw, _ = make_user(password_hash_value="!")
    c = new_client()
    attempts = [
        (name, "wrong"), ("nosuchuser" + uuid.uuid4().hex[:6], PASSWORD), (off, PASSWORD), (nopw, PASSWORD),
        ("adımin", PASSWORD), ("x", PASSWORD), ("a" * 100, PASSWORD), (name + "​", PASSWORD),
    ]
    seen = set()
    for user, pw in attempts:
        r = login(c, user, pw)
        seen.add((r.status_code, r.text))
    assert seen == {(401, '{"error":"invalid_credentials"}')}


def test_login_rejects_extra_fields_and_giant_passwords(make_user):
    name, _ = make_user()
    c = new_client()
    assert c.post("/api/v1/auth/login", json={"username": name, "password": PASSWORD, "role": "admin"}).status_code == 422
    assert login(c, name, "x" * 257).status_code == 422
    assert c.post("/api/v1/auth/login", json={"username": name}).status_code == 422


# ----------------------------------------------------------------------------- lockout
def test_five_failures_lock_the_pair_even_for_the_right_password(factory, make_user):
    name, uid = make_user()
    c = new_client()
    for _ in range(5):
        assert login(c, name, "wrong").status_code == 401
    locked = login(c, name)  # correct password, still refused
    assert locked.status_code == 429 and 1 <= int(locked.headers["Retry-After"]) <= 30
    # Another address is not locked out by it (T6: nobody can lock a real customer out from elsewhere).
    assert login(new_client(), name).status_code == 200
    # The lock ends: age the attempts and the right password works again.
    sql(factory, "UPDATE login_attempts SET created_at = created_at - interval '1 hour' WHERE succeeded = false")
    assert login(c, name).status_code == 200
    actions = {x.action for x in sql(factory, "SELECT action FROM audit_log WHERE action LIKE 'login.%'")}
    assert {"login.failed", "login.locked", "login.ok"} <= actions


def test_lock_doubles_and_is_capped(factory):
    key = ratelimit.username_key("doubling")
    ip = "10.99.0.1"
    with factory() as s:
        for _ in range(5):
            ratelimit.record_login_attempt(s, key, ip, False)
        s.commit()
    assert 28 <= ratelimit.login_lock_remaining(key, ip) <= 30
    with factory() as s:
        ratelimit.record_login_attempt(s, key, ip, False)
        s.commit()
    assert 58 <= ratelimit.login_lock_remaining(key, ip) <= 60
    with factory() as s:
        for _ in range(40):
            ratelimit.record_login_attempt(s, key, ip, False)
        s.commit()
    assert ratelimit.login_lock_remaining(key, ip) <= ratelimit.PAIR_MAX_LOCK_S


def test_success_resets_the_pair(factory):
    key = ratelimit.username_key("resetting")
    ip = "10.99.0.2"
    with factory() as s:
        for _ in range(5):
            ratelimit.record_login_attempt(s, key, ip, False)
        ratelimit.record_login_attempt(s, key, ip, True)
        s.commit()
    assert ratelimit.login_lock_remaining(key, ip) == 0


def test_username_wide_pause_is_short_and_flat(factory, make_user):
    name, _ = make_user()
    key = ratelimit.username_key(name)
    with factory() as s:
        for i in range(ratelimit.USER_FAILURES_BEFORE_PAUSE):
            ratelimit.record_login_attempt(s, key, f"10.98.0.{i}", False)  # spread over 30 addresses
        s.commit()
    r = login(new_client(), name)
    assert r.status_code == 429 and int(r.headers["Retry-After"]) <= ratelimit.USER_PAUSE_S


def test_unknown_names_are_locked_like_real_ones(factory):
    c = new_client()
    ghost = "ghost" + uuid.uuid4().hex[:8]
    codes = [login(c, ghost, "wrong").status_code for _ in range(6)]
    assert codes == [401] * 5 + [429]


def test_per_ip_login_throttle(factory):
    c = new_client()
    codes = {login(c, "u" + uuid.uuid4().hex[:8], "wrong").status_code for _ in range(ratelimit.LOGIN_PER_IP_PER_MIN + 3)}
    assert 429 in codes


# ------------------------------------------------------------------------------ sessions
def test_no_bad_expired_or_revoked_token_gets_in(factory, make_user):
    name, uid = make_user()
    c = new_client()
    assert c.get("/api/v1/me").status_code == 401
    assert c.get("/api/v1/me", headers={"Authorization": "Bearer nonsense"}).status_code == 401
    assert c.get("/api/v1/me", headers={"Authorization": "Basic abc"}).status_code == 401
    assert c.get("/api/v1/me?access_token=whatever").status_code == 401

    r = login(c, name)
    h = bearer(r)
    assert c.get("/api/v1/me", headers=h).status_code == 200
    sql(factory, "UPDATE sessions SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' "
                 "WHERE user_id = :u", u=uid)
    expired = c.get("/api/v1/me", headers=h)
    assert expired.status_code == 401 and expired.json() == {"error": "unauthenticated"}


def test_logout_really_revokes(factory, make_user):
    name, uid = make_user()
    c = new_client()
    h = bearer(login(c, name))
    assert c.post("/api/v1/auth/logout", headers=h).status_code == 204
    assert c.get("/api/v1/me", headers=h).status_code == 401
    assert c.post("/api/v1/auth/logout", headers=h).status_code == 401
    assert sql(factory, "SELECT revoked_at IS NOT NULL AS r FROM sessions WHERE user_id = :u", u=uid)[0].r
    actions = [x.action for x in sql(factory, "SELECT action FROM audit_log WHERE user_id = :u ORDER BY seq", u=str(uid))]
    assert actions == ["login.ok", "login.logout"]


def test_role_and_status_are_read_from_the_database_every_time(factory, make_user):
    name, uid = make_user("customer")
    c = new_client()
    h = bearer(login(c, name))
    assert c.get("/api/v1/me", headers=h).json()["role"] == "customer"
    sql(factory, "UPDATE users SET role = 'auditor' WHERE id = :u", u=uid)
    assert c.get("/api/v1/me", headers=h).json()["role"] == "auditor"  # the token carries no role
    sql(factory, "UPDATE users SET is_active = false WHERE id = :u", u=uid)
    assert c.get("/api/v1/me", headers=h).status_code == 401


def test_at_most_five_live_sessions_per_user(factory, make_user):
    name, uid = make_user()
    c = new_client()
    first = bearer(login(c, name))
    for _ in range(5):
        assert login(c, name).status_code == 200
    live = sql(factory, "SELECT count(*) AS n FROM sessions WHERE user_id = :u AND revoked_at IS NULL", u=uid)[0].n
    assert live == auth.MAX_ACTIVE_SESSIONS
    assert c.get("/api/v1/me", headers=first).status_code == 401  # the oldest was revoked


# ------------------------------------------------------------------------------- roles
@pytest.fixture
def role_app(factory):
    """A throw-away app with one route per role, so the real app's routes stay untouched."""
    probe = FastAPI()

    @probe.get("/approver-only")
    def approver_only(user: auth.CurrentUser = Depends(auth.require_role("approver"))):
        return {"role": user.role}

    @probe.get("/staff")
    def staff(user: auth.CurrentUser = Depends(auth.require_role(*auth.STAFF_ROLES))):
        return {"role": user.role}

    def get_db():
        with factory() as session:
            yield session

    probe.dependency_overrides[appdb.get_db] = get_db
    n = next(_ips)
    return TestClient(probe, client=(f"10.30.{n // 250}.{n % 250 + 1}", 5000))


def token_for(factory, user_id):
    token, digest = auth.new_token()
    sql(factory, "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (:u, :h, now() + interval '10 minutes')",
        u=user_id, h=digest)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("role,approver_status,staff_status", [
    ("customer", 403, 403), ("teller", 403, 200), ("approver", 200, 200), ("auditor", 403, 200), ("admin", 403, 200),
])
def test_role_matrix(factory, make_user, role_app, role, approver_status, staff_status):
    _, uid = make_user(role)
    h = token_for(factory, uid)
    assert role_app.get("/approver-only", headers=h).status_code == approver_status
    assert role_app.get("/staff", headers=h).status_code == staff_status


def test_denied_role_is_audited_and_no_token_is_401(factory, make_user, role_app):
    _, uid = make_user("customer")
    assert role_app.get("/staff").status_code == 401
    assert role_app.get("/staff", headers=token_for(factory, uid)).status_code == 403
    rows = sql(factory, "SELECT action, outcome, details FROM audit_log WHERE user_id = :u", u=str(uid))
    assert [(r.action, r.outcome) for r in rows] == [("authz.denied", "denied")]
    assert "teller" in rows[0].details["role_required"]


# --------------------------------------------------------------------------- ownership
# The predicate every account query uses (see the app/auth.py docstring). Written out as a literal.
ACCOUNT_BY_ID = (
    "SELECT a.id FROM accounts a WHERE a.id = :id "
    "AND (:staff OR a.owner_id = :me) AND (a.owner_id IS NOT NULL OR :system_ok)"
)


def make_account(factory, owner, kind="customer"):
    return sql(factory, "INSERT INTO accounts (owner_id, kind, name, min_balance) VALUES (:o, :k, 'test', :m) RETURNING id",
               o=owner, k=kind, m=0 if kind == "customer" else -(10**12))[0].id


def visible(factory, user, account_id) -> bool:
    return bool(sql(factory, ACCOUNT_BY_ID, id=account_id, **auth.scope_params(user)))


def as_user(role, uid):
    return auth.CurrentUser(id=uid, username="t", role=role, session_id=uuid.uuid4(), src_ip=None)


def test_customers_see_only_their_own_accounts(factory, make_user):
    _, alice = make_user()
    _, bob = make_user()
    a, b = make_account(factory, alice), make_account(factory, bob)
    assert visible(factory, as_user("customer", alice), a)
    assert not visible(factory, as_user("customer", alice), b)  # someone else's: no row, so 404
    assert not visible(factory, as_user("customer", alice), uuid.uuid4())  # missing: the same empty answer


def test_staff_see_customer_accounts_but_only_auditor_and_admin_see_system_ones(factory, make_user):
    _, alice = make_user()
    _, staff = make_user("teller")
    a, system = make_account(factory, alice), make_account(factory, None, "system")
    for role in auth.STAFF_ROLES:
        assert visible(factory, as_user(role, staff), a)
    assert not visible(factory, as_user("customer", alice), system)
    for role in ("teller", "approver"):
        assert not visible(factory, as_user(role, staff), system)
    for role in ("auditor", "admin"):
        assert visible(factory, as_user(role, staff), system)


# ------------------------------------------------------------------- rate limits & schema
def test_api_rate_limit_per_user(factory, make_user, monkeypatch):
    monkeypatch.setattr(ratelimit, "API_PER_USER_PER_MIN", 5)
    _, uid = make_user()
    h = token_for(factory, uid)
    c = new_client()
    codes = [c.get("/api/v1/me", headers=h).status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and 429 in codes[5:]


def test_anonymous_flood_per_ip_gets_429(factory, monkeypatch):
    monkeypatch.setattr(ratelimit, "ANON_PER_IP_PER_MIN", 3)
    c = new_client()
    codes = [c.get("/api/v1/me").status_code for _ in range(6)]
    assert codes[:3] == [401] * 3 and 429 in codes[3:]


def test_schema_refuses_bad_roles_and_blank_defaults_cannot_log_in(factory):
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        sql(factory, "INSERT INTO users (username, role) VALUES ('badrole1', 'superuser')")
    row = sql(factory, "INSERT INTO users (username) VALUES (:u) RETURNING role, password_hash, is_active",
              u=f"d{uuid.uuid4().hex[:10]}")[0]
    assert (row.role, row.password_hash, row.is_active) == ("customer", "!", True)
    assert not auth.verify_password(row.password_hash, "!")
