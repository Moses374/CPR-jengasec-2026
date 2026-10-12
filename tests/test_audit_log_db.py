"""The audit log against a real PostgreSQL: every protection layer proven to fire (docs/DECISIONS.md, E1).

Tampering tests unlock the table inside a transaction that is always rolled back, so they never
change the shared test database. Amounts are cents.
"""

import logging
import os
import secrets
import threading
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app import audit_log, observability

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.db


# ---------------------------------------------------------------- helpers

def sqlstate(exc: DBAPIError) -> str | None:
    return getattr(exc.orig, "sqlstate", None)


def expect(conn, codes, sql, **params):
    with pytest.raises(DBAPIError) as e:
        conn.execute(text(sql), params)
    conn.rollback()
    assert sqlstate(e.value) in codes, str(e.value.orig)


def add(conn, n=1, **kw):
    """n committed rows; returns the last AuditRow."""
    row = None
    for _ in range(n):
        args = dict(action="transfer.created", outcome="ok", user_id="u1", role="customer", src_ip="10.0.0.9",
                    object_type="transfer_request", object_id="r1",
                    details={"amount_cents": 12_345, "reason": "café ✓", "checks": ["a", {"b": 1}]})
        args.update(kw)
        row = audit_log.append(conn, **args)
        conn.commit()
    return row


def head(conn):
    return conn.execute(text("SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1")).first()


def unlock(conn):
    """What an attacker with owner rights would do first. Inside a transaction we roll back."""
    conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER USER"))
    conn.execute(text("GRANT UPDATE, DELETE, TRUNCATE ON audit_log TO CURRENT_USER"))


def raw_insert(conn, **override):
    h = head(conn)
    values = {"seq": (h.seq if h else 0) + 1, "prev": bytes(h.row_hash) if h else bytes(32), "action": "login.ok",
              "outcome": "ok", "details": "{}", "row_hash": secrets.token_bytes(32), "ts_offset": "0 seconds"}
    values.update(override)
    conn.execute(
        text(
            "INSERT INTO audit_log (seq, ts, action, outcome, details, prev_hash, row_hash) "
            "VALUES (:seq, clock_timestamp() + CAST(:ts_offset AS interval), :action, :outcome, "
            "CAST(:details AS jsonb), :prev, :row_hash)"
        ),
        values,
    )


@pytest.fixture
def conn(db_engine):
    with db_engine.connect() as c:
        yield c
        c.rollback()


# ---------------------------------------------------------------- writing and the chain

def test_rows_chain_together_and_verify(conn):
    first = add(conn, 3)
    result = audit_log.verify_chain(conn)
    assert result.ok and result.checked >= 3
    assert result.head_seq >= first.seq and result.first_bad_seq is None


def test_what_goes_in_comes_out_and_still_verifies(conn):
    row = add(conn, action="login.failed", outcome="denied", user_id="probe-1", role=None, src_ip="2001:db8::1",
              object_type=None, object_id=None, details={"reason": "bad_password", "attempts": 3, "password": "x"})
    stored = audit_log.list_events(conn, user_id="probe-1")[0]
    assert stored["seq"] == row.seq and stored["action"] == "login.failed" and stored["outcome"] == "denied"
    assert stored["details"] == {"reason": "bad_password", "attempts": 3, "dropped_keys": ["password"]}
    assert audit_log.verify_chain(conn).ok


def test_a_rolled_back_write_leaves_no_gap(conn):
    h = head(conn)
    base = h.seq if h else 0
    lost = audit_log.append(conn, action="transfer.created", outcome="ok")
    conn.rollback()
    kept = add(conn)
    assert lost.seq == kept.seq == base + 1
    assert audit_log.verify_chain(conn).ok


def test_concurrent_writers_never_fork_or_skip(db_engine):
    n = 20
    barrier = threading.Barrier(n)
    seqs, errors = [], []

    def worker(i):
        try:
            with Session(db_engine) as s:
                barrier.wait()
                seqs.append(audit_log.append(s, action="transfer.created", outcome="ok", user_id=f"t{i}").seq)
                s.commit()
        except Exception as e:  # pragma: no cover - the assertion below reports it
            errors.append(repr(e))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert sorted(seqs) == list(range(min(seqs), min(seqs) + n))
    with db_engine.connect() as c:
        assert audit_log.verify_chain(c).ok


def test_append_sets_the_action_on_the_request_log_line(conn):
    holder: dict = {}
    token = observability._audit.set(holder)
    try:
        audit_log.append(conn, action="approval.self_denied", outcome="denied")
    finally:
        observability._audit.reset(token)
        conn.rollback()
    assert holder["action"] == "approval.self_denied"


def test_record_uses_its_own_transaction(db_engine):
    seq = audit_log.record(action="transfer.denied", outcome="denied", user_id="rec-1",
                           details={"reason": "limit_daily"}, session_factory=lambda: Session(db_engine))
    assert seq is not None
    with db_engine.connect() as c:
        assert audit_log.list_events(c, user_id="rec-1")[0]["seq"] == seq


def test_record_survives_a_database_failure_and_logs_without_leaking(caplog):
    def broken():
        raise RuntimeError("password=hunter2 host=db")

    caplog.set_level(logging.INFO, logger="app.audit")
    assert audit_log.record(action="transfer.denied", outcome="denied", session_factory=broken) is None
    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "auditlog.write_failed action=transfer.denied error=RuntimeError" in messages
    assert "hunter2" not in messages


def test_record_still_refuses_a_bad_call():
    with pytest.raises(audit_log.AuditError):
        audit_log.record(action="Not An Action", outcome="ok")


def test_anchor_writes_the_committed_head_to_the_log(conn, caplog):
    row = add(conn)
    caplog.set_level(logging.INFO, logger="app.audit")
    anchored = audit_log.anchor(conn)
    assert anchored["seq"] >= row.seq
    line = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("auditlog.anchor"))
    assert f"seq={anchored['seq']} row_hash={anchored['row_hash']}" in line


def test_list_events_pages_newest_first(conn):
    uid = f"page-{secrets.token_hex(4)}"
    rows = [add(conn, user_id=uid, action="login.ok") for _ in range(5)]
    first = audit_log.list_events(conn, user_id=uid, limit=2)
    assert [e["seq"] for e in first] == [rows[4].seq, rows[3].seq]
    rest = audit_log.list_events(conn, user_id=uid, before_seq=first[-1]["seq"])
    assert [e["seq"] for e in rest] == [rows[2].seq, rows[1].seq, rows[0].seq]
    assert audit_log.list_events(conn, user_id=uid, action="login.failed") == []


# ---------------------------------------------------------------- the database refuses

@pytest.mark.parametrize("sql", ["UPDATE audit_log SET role = 'admin'", "DELETE FROM audit_log", "TRUNCATE audit_log"])
def test_no_edit_delete_or_truncate(conn, sql):
    add(conn)
    expect(conn, ("LG002", "42501"), sql)  # trigger, or privilege when the user is not a superuser


@pytest.mark.parametrize("override,code", [
    ({"seq": 1}, "AU001"),                                      # fork the chain
    ({"seq_plus": 2}, "AU001"),                                 # leave a gap
    ({"prev": b"\x07" * 32}, "AU001"),                          # link to nothing
    ({"ts_offset": "-1 hour"}, "AU002"),                        # backdate
    ({"ts_offset": "1 hour"}, "AU002"),                         # post-date
    ({"action": "Bad Action"}, "23514"),                        # shape of the action name
    ({"outcome": "success"}, "23514"),
    ({"details": "[1, 2]"}, "23514"),                           # details must be an object
    ({"row_hash": b"short"}, "23514"),
])
def test_the_chain_trigger_and_constraints_refuse_bad_rows(conn, override, code):
    add(conn)
    override = dict(override)
    if "seq_plus" in override:
        override["seq"] = head(conn).seq + override.pop("seq_plus")
    with pytest.raises(DBAPIError) as e:
        raw_insert(conn, **override)
    conn.rollback()
    assert sqlstate(e.value) == code, str(e.value.orig)


def test_the_controls_report_healthy_then_notice_tampering(conn):
    assert audit_log.check_controls(conn) == []
    conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_chain"))
    conn.execute(text("DROP TRIGGER audit_log_no_truncate ON audit_log"))
    problems = audit_log.check_controls(conn)
    conn.rollback()
    assert "trigger audit_log_chain is disabled" in problems
    assert "trigger audit_log_no_truncate is missing" in problems


def test_the_migration_took_update_delete_truncate_from_the_owner(conn):
    granted = conn.execute(text(
        "SELECT DISTINCT a.privilege_type FROM pg_class c, aclexplode(c.relacl) a "
        "WHERE c.relname = 'audit_log' AND a.grantee = c.relowner"
    )).scalars().all()
    assert "INSERT" in granted and "SELECT" in granted
    assert not {"UPDATE", "DELETE", "TRUNCATE"} & set(granted)


# ---------------------------------------------------------------- what verification catches

def test_an_edited_row_is_found(conn):
    rows = [add(conn) for _ in range(5)]
    target = rows[2].seq
    unlock(conn)
    conn.execute(text("UPDATE audit_log SET outcome = 'denied' WHERE seq = :s"), {"s": target})
    result = audit_log.verify_chain(conn)
    conn.rollback()
    assert not result.ok and result.first_bad_seq == target and "edited" in result.reason


def test_a_deleted_row_is_found(conn):
    rows = [add(conn) for _ in range(5)]
    target = rows[2].seq
    unlock(conn)
    conn.execute(text("DELETE FROM audit_log WHERE seq = :s"), {"s": target})
    result = audit_log.verify_chain(conn)
    conn.rollback()
    assert not result.ok and result.first_bad_seq == target


def test_rows_cut_from_the_end_need_the_anchor(conn):
    add(conn, 3)
    anchored = audit_log.anchor(conn)
    unlock(conn)
    conn.execute(text("DELETE FROM audit_log WHERE seq = :s"), {"s": anchored["seq"]})
    assert audit_log.verify_chain(conn).ok  # a chain cannot show its own missing tail ...
    result = audit_log.verify_chain(conn, expected_head=(anchored["seq"], anchored["row_hash"]))
    conn.rollback()
    assert not result.ok and "no longer exists" in result.reason  # ... the anchor in the platform logs can


def test_a_full_rewrite_with_recomputed_hashes_is_caught_by_the_anchor(conn):
    rows = [add(conn) for _ in range(6)]
    anchored = audit_log.anchor(conn)
    start = rows[2].seq
    unlock(conn)
    # The attacker changes one row and recomputes every hash after it, so the chain is consistent again.
    stored = conn.execute(text(
        "SELECT seq, ts, user_id, role, src_ip, action, outcome, object_type, object_id, details "
        "FROM audit_log WHERE seq >= :s ORDER BY seq"), {"s": start}).all()
    prev = bytes(conn.execute(text("SELECT row_hash FROM audit_log WHERE seq = :s"), {"s": start - 1}).scalar())
    for r in stored:
        details = {"amount_cents": 1} if r.seq == start else dict(r.details)
        h = audit_log.compute_hash(prev, audit_log.canonical_body(
            r.seq, r.ts, r.user_id, r.role, r.src_ip, r.action, r.outcome, r.object_type, r.object_id, details))
        conn.execute(text("UPDATE audit_log SET details = CAST(:d AS jsonb), prev_hash = :p, row_hash = :h WHERE seq = :s"),
                     {"d": audit_log.canonical_json(details), "p": prev, "h": h, "s": r.seq})
        prev = h
    assert audit_log.verify_chain(conn).ok  # consistent on its own ...
    result = audit_log.verify_chain(conn, expected_head=(anchored["seq"], anchored["row_hash"]))
    conn.rollback()
    assert not result.ok and "differs from the anchor" in result.reason  # ... but not against the copy outside the database


# ---------------------------------------------------------------- a non-superuser owner (the realistic platform case)

@pytest.fixture(scope="module")
def owner_engine(db_url):
    """A fresh database owned by an ordinary role, migrated as that role: no superuser shortcuts."""
    admin_url = make_url(db_url).set(database="postgres")
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    suffix, password = secrets.token_hex(5), secrets.token_hex(12)  # test-only credentials, generated here
    role, name = f"audit_owner_{suffix}", f"audit_owner_db_{suffix}"
    with admin.connect() as c:
        c.execute(text(f'CREATE ROLE "{role}" LOGIN PASSWORD \'{password}\''))
        c.execute(text(f'CREATE DATABASE "{name}" OWNER "{role}"'))
    url = make_url(db_url).set(database=name, username=role, password=password).render_as_string(hide_password=False)

    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url
    try:
        command.upgrade(cfg, "head")
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous

    engine = create_engine(url, isolation_level="READ COMMITTED")
    with engine.connect() as c:
        add(c, 2)
    yield engine
    engine.dispose()
    with admin.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        c.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
    admin.dispose()


@pytest.fixture
def oconn(owner_engine):
    with owner_engine.connect() as c:
        yield c
        c.rollback()


def test_the_owner_is_not_a_superuser(oconn):
    assert oconn.execute(text("SELECT current_setting('is_superuser')")).scalar() == "off"


@pytest.mark.parametrize("sql", ["UPDATE audit_log SET role = 'admin'", "DELETE FROM audit_log", "TRUNCATE audit_log"])
def test_layer_1_the_owner_has_no_write_privilege_until_it_grants_itself_one(oconn, sql):
    expect(oconn, ("42501",), sql)


@pytest.mark.parametrize("sql", ["UPDATE audit_log SET role = 'admin'", "DELETE FROM audit_log", "TRUNCATE audit_log"])
def test_layer_2_triggers_hold_even_after_the_owner_grants_itself_the_privilege(oconn, sql):
    oconn.execute(text("GRANT UPDATE, DELETE, TRUNCATE ON audit_log TO CURRENT_USER"))
    expect(oconn, ("LG002",), sql)


def test_the_controls_start_clean_and_notice_a_regrant(oconn):
    assert audit_log.check_controls(oconn) == []
    oconn.execute(text("GRANT UPDATE ON audit_log TO CURRENT_USER"))
    assert "UPDATE is granted on audit_log" in audit_log.check_controls(oconn)


def test_layers_3_and_4_catch_an_owner_who_turns_everything_off(oconn):
    unlock(oconn)
    oconn.execute(text("UPDATE audit_log SET outcome = 'denied' WHERE seq = 1"))
    result = audit_log.verify_chain(oconn)
    problems = audit_log.check_controls(oconn)
    assert not result.ok and result.first_bad_seq == 1
    assert "trigger audit_log_chain is disabled" in problems and "UPDATE is granted on audit_log" in problems
