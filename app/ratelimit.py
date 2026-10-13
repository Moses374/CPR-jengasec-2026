"""Rate limits and login lockout, all in PostgreSQL (docs/DECISIONS.md, Kathy Q4).

Why the database: there are two workers, so in-memory counters would let an attacker get twice the
attempts, and the snapshot at freeze must not depend on process state.

Every function here uses its own short transaction (app.db.SessionLocal), so a counter survives
even when the request that triggered it is rolled back. All times come from the database clock.

Lockout is computed from login_attempts rows (one row per attempt) instead of a mutable counter,
so two concurrent logins cannot overwrite each other's count. A narrow race can let a few extra
guesses through at the moment a lock starts; the lock still holds afterwards.
"""

import hashlib
import random

from sqlalchemy import text

from app import db as appdb

# ---- limits (named constants, documented in docs/DECISIONS.md Q4) -------------------------------
PAIR_FAILURES_BEFORE_LOCK = 5      # failures per (username, IP) in the window
PAIR_BASE_LOCK_S = 30              # first lock; doubles with each further failure
PAIR_MAX_LOCK_S = 15 * 60
USER_FAILURES_BEFORE_PAUSE = 30    # failures per username from any IP in the window
USER_PAUSE_S = 60                  # flat, never longer: an attacker must not lock a real customer out
FAILURE_WINDOW_S = 15 * 60

LOGIN_PER_IP_PER_MIN = 30
API_PER_USER_PER_MIN = 120
MONEY_PER_USER_PER_MIN = 20
ANON_PER_IP_PER_MIN = 60

_PRUNE_CHANCE = 0.02


def username_key(normalised: str) -> str:
    """Stable key for counters. A hash, so attacker-chosen text is never stored or logged raw."""
    return hashlib.sha256(normalised.encode("utf-8", "replace")).hexdigest()


def hit(key: str, limit: int) -> tuple[bool, int]:
    """Count one request in this key's current one-minute window.

    Returns (allowed, seconds until the window resets). One INSERT ... ON CONFLICT upsert.
    """
    with appdb.SessionLocal() as session:
        row = session.execute(
            text(
                "INSERT INTO rate_counters (key, window_start, hits) "
                "VALUES (:key, date_trunc('minute', clock_timestamp()), 1) "
                "ON CONFLICT (key, window_start) DO UPDATE SET hits = rate_counters.hits + 1 "
                "RETURNING hits, CEIL(60 - EXTRACT(EPOCH FROM (clock_timestamp() - window_start)))::int AS retry"
            ),
            {"key": key[:128]},
        ).one()
        if random.random() < _PRUNE_CHANCE:
            session.execute(text("DELETE FROM rate_counters WHERE window_start < clock_timestamp() - interval '10 minutes'"))
        session.commit()
    return row.hits <= limit, max(1, row.retry)


def login_lock_remaining(key: str, src_ip: str) -> int:
    """Seconds this (username, IP) must still wait, 0 if free. Takes the longer of pair and username locks."""
    with appdb.SessionLocal() as session:
        pair = session.execute(
            text(
                "SELECT count(*) AS n, EXTRACT(EPOCH FROM (clock_timestamp() - max(created_at))) AS age "
                "FROM login_attempts "
                "WHERE username_key = :k AND src_ip = :ip AND NOT succeeded "
                "AND created_at > clock_timestamp() - make_interval(secs => :window) "
                "AND created_at > COALESCE((SELECT max(created_at) FROM login_attempts "
                "                           WHERE username_key = :k AND src_ip = :ip AND succeeded), '-infinity')"
            ),
            {"k": key, "ip": src_ip[:64], "window": FAILURE_WINDOW_S},
        ).one()
        user = session.execute(
            text(
                "SELECT count(*) AS n, EXTRACT(EPOCH FROM (clock_timestamp() - max(created_at))) AS age "
                "FROM login_attempts WHERE username_key = :k AND NOT succeeded "
                "AND created_at > clock_timestamp() - make_interval(secs => :window)"
            ),
            {"k": key, "window": FAILURE_WINDOW_S},
        ).one()

    remaining = 0.0
    if pair.n >= PAIR_FAILURES_BEFORE_LOCK:
        lock = min(PAIR_BASE_LOCK_S * 2 ** min(pair.n - PAIR_FAILURES_BEFORE_LOCK, 10), PAIR_MAX_LOCK_S)
        remaining = max(remaining, lock - float(pair.age))
    if user.n >= USER_FAILURES_BEFORE_PAUSE:
        remaining = max(remaining, USER_PAUSE_S - float(user.age))
    return max(0, int(remaining) + (1 if remaining % 1 else 0))


def record_login_attempt(db, key: str, src_ip: str, succeeded: bool) -> None:
    """Write one attempt inside the caller's transaction. The caller commits."""
    db.execute(
        text("INSERT INTO login_attempts (username_key, src_ip, succeeded) VALUES (:k, :ip, :ok)"),
        {"k": key, "ip": src_ip[:64], "ok": succeeded},
    )
    if random.random() < _PRUNE_CHANCE:
        db.execute(text("DELETE FROM login_attempts WHERE created_at < clock_timestamp() - interval '1 day'"))


def record_failed_login(key: str, src_ip: str) -> None:
    """A failed login has no transaction worth keeping, so it gets its own."""
    with appdb.SessionLocal() as session:
        record_login_attempt(session, key, src_ip, False)
        session.commit()
