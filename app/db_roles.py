"""Least privilege at runtime (docs/DECISIONS.md, Moses Q1 and Q6).

The platform gives us one database user, probably a superuser. Migrations need it; the web app must not
have it: a superuser (or the table owner) can switch off every trigger the ledger relies on.

So at every start, after migrations, run.py calls setup() with the platform's user. It creates or updates
a login role `ledger_app` with a new random password, gives it only the grants below, and the web workers
connect as `ledger_app`. That role owns nothing and is not a superuser, so it cannot disable a trigger,
alter a table, or update or delete outside its grants. The password lives only in the process
environment and changes on every start. Because it is rebuilt at every boot, it also survives the
platform restoring a database snapshot (roles live outside the database).

If the platform user cannot create roles, or `ledger_app` cannot log in, setup() logs it and returns None:
the app then runs as today. A missing permission must never stop the app from starting.
"""

import logging
import secrets

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

log = logging.getLogger("app.startup")

ROLE = "ledger_app"

# What the app does, from an inventory of every statement in app/ (13 Oct). Anything not listed is refused.
SELECT_ONLY = ("ledger_settings", "app_metadata")
SELECT_INSERT = ("accounts", "audit_log", "entries", "idempotency_keys", "ledger_transactions", "login_attempts",
                 "rate_counters", "recon_runs", "reversal_requests", "sessions", "transfer_requests", "users")
UPDATE_COLUMNS = {
    "transfer_requests": "status, checker_id, ledger_transaction_id, failure_reason",
    "reversal_requests": "status, checker_id, ledger_transaction_id, failure_reason",
    "idempotency_keys": "response",
    "sessions": "revoked_at",
    "users": "password_hash",          # Kathy: rehash on login when the hash parameters change
    "rate_counters": "hits",
    # SELECT ... FOR NO KEY UPDATE (how accounts are locked) needs UPDATE on at least one column.
    # `name` is the harmless one: granting `status` would let injected SQL unfreeze a frozen account.
    "accounts": "name",
}
DELETE_ALLOWED = ("sessions", "rate_counters", "login_attempts")   # housekeeping of expired rows only

# Every statement is a constant: table and column names come from the lists above, never from input.
_GRANTS = (
    [f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {ROLE}",
     f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {ROLE}",
     f"REVOKE CREATE ON SCHEMA public FROM {ROLE}",
     f"GRANT USAGE ON SCHEMA public TO {ROLE}",
     f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {ROLE}"]
    + [f"GRANT SELECT ON {t} TO {ROLE}" for t in SELECT_ONLY]
    + [f"GRANT SELECT, INSERT ON {t} TO {ROLE}" for t in SELECT_INSERT]
    + [f"GRANT UPDATE ({cols}) ON {t} TO {ROLE}" for t, cols in UPDATE_COLUMNS.items()]
    + [f"GRANT DELETE ON {t} TO {ROLE}" for t in DELETE_ALLOWED]
)

# The password is passed as a bound parameter and quoted by the server (format %L), never built into SQL.
_CREATE_OR_RESET = f"""
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}') THEN
        CREATE ROLE {ROLE} LOGIN;
    END IF;
    EXECUTE format('ALTER ROLE {ROLE} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION '
                   'NOBYPASSRLS NOINHERIT CONNECTION LIMIT 60 PASSWORD %L',
                   current_setting('ledger.runtime_password'));
END $$
"""


def setup(admin_url: str) -> str | None:
    """Create or refresh the runtime role and return a database URL for it, or None to keep admin_url."""
    # One real transaction: set_config(..., true) lasts only until it ends, and the DO block must see it.
    # (With autocommit each statement is its own transaction and the role would get an empty password.)
    engine = create_engine(admin_url)
    try:
        with engine.begin() as c:
            can = c.execute(text(
                "SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user")).scalar()
            if not can:
                log.warning("db.least_privilege=unavailable reason=no_createrole")
                return None
            password = secrets.token_urlsafe(32)
            c.execute(text("SELECT set_config('ledger.runtime_password', :p, true)"), {"p": password})
            c.execute(text(_CREATE_OR_RESET))
            for statement in _GRANTS:
                c.execute(text(statement))
    except Exception as e:
        log.warning("db.least_privilege=unavailable reason=%s", type(e).__name__)
        return None
    finally:
        engine.dispose()

    runtime_url = make_url(admin_url).set(username=ROLE, password=password).render_as_string(hide_password=False)
    probe = create_engine(runtime_url)
    try:
        with probe.connect() as c:
            if c.execute(text("SELECT current_setting('is_superuser')")).scalar() != "off":
                log.warning("db.least_privilege=unavailable reason=runtime_role_is_superuser")
                return None
    except Exception as e:   # for example pg_hba refuses the new role: run as before, say so loudly
        log.warning("db.least_privilege=unavailable reason=%s", type(e).__name__)
        return None
    finally:
        probe.dispose()
    log.info("db.least_privilege=on role=%s", ROLE)
    return runtime_url
