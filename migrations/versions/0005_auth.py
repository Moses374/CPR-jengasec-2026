"""Authentication and access control (Kathy): roles, sessions, login attempts, rate counters.

Design and reasons: docs/DECISIONS.md, Kathy section (Q1 roles, Q2 login, Q3 ownership, Q4 lockout).

- users gains password_hash, role and is_active. Both defaults are fail-closed on purpose:
  '!' is not a valid argon2 hash, so a user inserted without a password can never log in, and
  'customer' is the least privileged role. The seed migration (Moses, last) sets real values.
- sessions: opaque tokens. Only the SHA-256 of the token is stored. Shared by both workers,
  survives the snapshot, and logout is a revoked_at stamp (the row stays as evidence).
- login_attempts: one row per login attempt, keyed by a hash of the username (never the raw text).
  Lockout is computed from these rows with the database clock (no mutable counter to race on).
- rate_counters: fixed one-minute windows for the API limits, written with one upsert.
- Trigger: a transfer request can only get a checker who is an active approver. This is the
  database half of "checker role verified in code and by trigger" (docs/DECISIONS.md, Moses Q1);
  the code half is app/approvals.py. checker <> maker is already a CHECK from 0002.

Errors raised here use SQLSTATE class AC:  AC001 checker is not an active approver

Revision ID: 0005
Revises: 0004
"""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

ROLES = ("customer", "teller", "approver", "auditor", "admin")
ROLE_LIST = ", ".join(f"'{r}'" for r in ROLES)  # constants above, never input

STATEMENTS = [
    # ------------------------------------------------------------------ users
    f"""
    ALTER TABLE users
        ADD COLUMN password_hash TEXT    NOT NULL DEFAULT '!',
        ADD COLUMN role          TEXT    NOT NULL DEFAULT 'customer' CONSTRAINT users_role_check CHECK (role IN ({ROLE_LIST})),
        ADD COLUMN is_active     BOOLEAN NOT NULL DEFAULT true
    """,
    # --------------------------------------------------------------- sessions
    """
    CREATE TABLE sessions (
        id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id    UUID NOT NULL REFERENCES users(id),
        token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ,
        CHECK (expires_at > created_at)
    )
    """,
    "CREATE INDEX sessions_active_by_user ON sessions (user_id, created_at) WHERE revoked_at IS NULL",
    # --------------------------------------------------------- login attempts
    """
    CREATE TABLE login_attempts (
        id           BIGSERIAL PRIMARY KEY,
        username_key TEXT NOT NULL CHECK (length(username_key) = 64),
        src_ip       TEXT NOT NULL CHECK (length(src_ip) <= 64),
        succeeded    BOOLEAN NOT NULL,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
    )
    """,
    "CREATE INDEX login_attempts_by_pair ON login_attempts (username_key, src_ip, created_at)",
    "CREATE INDEX login_attempts_by_name ON login_attempts (username_key, created_at)",
    "CREATE INDEX login_attempts_by_time ON login_attempts (created_at)",
    # ---------------------------------------------------------- rate counters
    """
    CREATE TABLE rate_counters (
        key          TEXT NOT NULL CHECK (length(key) <= 128),
        window_start TIMESTAMPTZ NOT NULL,
        hits         INTEGER NOT NULL CHECK (hits > 0),
        PRIMARY KEY (key, window_start)
    )
    """,
    # ---------------------------------------------- checker must be an approver
    """
    CREATE FUNCTION require_approver_checker() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.checker_id IS NOT NULL AND (TG_OP = 'INSERT' OR NEW.checker_id IS DISTINCT FROM OLD.checker_id) THEN
            IF NOT EXISTS (
                SELECT 1 FROM users WHERE id = NEW.checker_id AND role = 'approver' AND is_active
            ) THEN
                RAISE EXCEPTION USING ERRCODE = 'AC001', MESSAGE = 'checker must be an active approver';
            END IF;
        END IF;
        RETURN NEW;
    END $$
    """,
    """
    CREATE TRIGGER transfer_requests_checker_is_approver
        BEFORE INSERT OR UPDATE ON transfer_requests
        FOR EACH ROW EXECUTE FUNCTION require_approver_checker()
    """,
    # Reversals (0004) take money back out of a customer's account: same rule for their checker.
    """
    CREATE TRIGGER reversal_requests_checker_is_approver
        BEFORE INSERT OR UPDATE ON reversal_requests
        FOR EACH ROW EXECUTE FUNCTION require_approver_checker()
    """,
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS reversal_requests_checker_is_approver ON reversal_requests")
    op.execute("DROP TRIGGER IF EXISTS transfer_requests_checker_is_approver ON transfer_requests")
    op.execute("DROP FUNCTION IF EXISTS require_approver_checker()")
    for table in ("rate_counters", "login_attempts", "sessions"):
        op.execute(f"DROP TABLE IF EXISTS {table}")
    op.execute(
        "ALTER TABLE users DROP COLUMN is_active, DROP COLUMN role, DROP COLUMN password_hash"
    )
