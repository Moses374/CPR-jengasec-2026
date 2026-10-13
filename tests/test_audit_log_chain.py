"""The audit log's hash chain and input cleaning. No database needed.

The database side (triggers, privileges, concurrency) is in test_audit_log_db.py.
"""

import dataclasses
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from app import audit_log
from app.audit_log import GENESIS_HASH, AuditError, AuditRow, ChainChecker, canonical_body, compute_hash

T0 = datetime(2026, 10, 13, 6, 0, 0, 123456, tzinfo=UTC)


def build_chain(n: int) -> list[AuditRow]:
    rows, prev = [], GENESIS_HASH
    for seq in range(1, n + 1):
        fields = dict(
            seq=seq, ts=T0 + timedelta(seconds=seq), user_id=f"u{seq}", role="customer", src_ip="10.0.0.1",
            action="transfer.created", outcome="ok", object_type="transfer_request", object_id=f"r{seq}",
            details={"amount_cents": seq * 100, "reason": "ünïcode ✓"},
        )
        row_hash = compute_hash(prev, canonical_body(**fields))
        rows.append(AuditRow(prev_hash=prev, row_hash=row_hash, **fields))
        prev = row_hash
    return rows


def check(rows: list[AuditRow]):
    checker = ChainChecker()
    for row in rows:
        bad = checker.feed(row)
        if bad:
            return bad
    return None


def test_a_good_chain_verifies():
    assert check(build_chain(25)) is None


def test_canonical_form_ignores_key_order_and_timezone_spelling():
    a = canonical_body(1, T0, "u", "r", "ip", "login.ok", "ok", None, None, {"reason": "x", "count": 1})
    b = canonical_body(1, T0.astimezone(timezone(timedelta(hours=3))), "u", "r", "ip", "login.ok", "ok", None, None,
                       {"count": 1, "reason": "x"})
    assert a == b


@pytest.mark.parametrize("field,value", [
    ("user_id", "someone-else"), ("role", "admin"), ("src_ip", "1.2.3.4"), ("action", "transfer.blocked"),
    ("outcome", "denied"), ("object_id", "other"), ("details", {"amount_cents": 1}),
    ("ts", T0 + timedelta(days=1)), ("seq", 99),
])
def test_editing_any_field_is_detected(field, value):
    rows = build_chain(10)
    rows[4] = dataclasses.replace(rows[4], **{field: value})
    bad = check(rows)
    assert bad is not None and bad[0] == 5


def test_deleting_a_row_is_detected_at_the_gap():
    rows = build_chain(10)
    del rows[3]  # seq 4
    assert check(rows)[0] == 4


def test_inserting_a_forged_row_is_detected():
    rows = build_chain(10)
    forged = dataclasses.replace(rows[4], seq=5, details={"amount_cents": 1})
    rows.insert(5, forged)
    assert check(rows) is not None


def test_reordering_is_detected():
    rows = build_chain(10)
    rows[3], rows[4] = rows[4], rows[3]
    assert check(rows) is not None


def test_a_rewritten_row_with_a_recomputed_hash_breaks_the_next_link():
    rows = build_chain(10)
    fields = {f.name: getattr(rows[4], f.name) for f in dataclasses.fields(AuditRow) if f.name not in ("row_hash",)}
    fields["details"] = {"amount_cents": 1}
    fields["row_hash"] = compute_hash(fields["prev_hash"], canonical_body(**{k: v for k, v in fields.items()
                                                                              if k not in ("prev_hash", "row_hash")}))
    rows[4] = AuditRow(**fields)
    bad = check(rows)
    assert bad is not None and bad[0] == 6  # row 5 is self-consistent now, row 6 no longer links to it


def test_wrong_start_is_detected():
    rows = build_chain(3)
    assert ChainChecker(next_seq=2).feed(rows[0])[0] == 2
    assert ChainChecker(prev_hash=b"\x01" * 32).feed(rows[0]) is not None


def test_the_trigger_and_the_module_use_the_same_lock_number():
    migration = (Path(__file__).resolve().parent.parent / "migrations" / "versions" / "0003_audit_log.py").read_text()
    assert f"LOCK_KEY = {audit_log.LOCK_KEY}" in migration


# ------------------------------------------------------------------ input cleaning

def test_unknown_detail_keys_are_dropped_and_noted():
    out = audit_log.clean_details({"reason": "limit_daily", "password": "hunter2", "token": "abc", "amount_cents": 5})
    assert out == {"reason": "limit_daily", "amount_cents": 5, "dropped_keys": ["password", "token"]}
    assert "hunter2" not in str(out) and "abc" not in str(out)


def test_detail_values_are_bounded_and_floats_become_text():
    out = audit_log.clean_details({"reason": "x" * 5000 + "\x00", "limit_cents": 1.5, "count": 2**70,
                                   "checks": list(range(100)), "mismatches": {"a": {"b": {"c": {"d": 1}}}}})
    assert len(out["reason"]) == 200 and "\x00" not in out["reason"]
    assert out["limit_cents"] == "1.5"
    assert out["count"] == str(2**70)
    assert len(out["checks"]) == 20
    assert out["mismatches"] == {"a": {"b": {"c": "{'d': 1}"}}}


def test_details_never_contain_floats():
    def has_float(v):
        if isinstance(v, float):
            return True
        if isinstance(v, dict):
            return any(has_float(x) for x in v.values())
        if isinstance(v, list):
            return any(has_float(x) for x in v)
        return False
    assert not has_float(audit_log.clean_details({"limit_cents": 1.5, "checks": [1.5, {"x": 2.5}]}))


@pytest.mark.parametrize("action", ["", "Login.ok", "login", "a.b.c.d", "login ok", "login.ok\n", "x" * 70 + ".y", None])
def test_bad_action_names_are_refused_before_any_sql(action):
    with pytest.raises(AuditError):
        audit_log.append(None, action=action, outcome="ok")


def test_bad_outcome_is_refused():
    with pytest.raises(AuditError):
        audit_log.append(None, action="login.ok", outcome="success")


def test_every_action_in_the_vocabulary_has_a_valid_shape():
    shape = re.compile(r"[a-z0-9_]+(\.[a-z0-9_]+){1,2}")
    assert all(shape.fullmatch(a) for a in audit_log.ACTIONS | audit_log.FALLBACK_ACTIONS)
