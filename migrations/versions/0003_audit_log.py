"""Audit log: append-only, hash-chained record of security and money events (Ethan).

Design and reasons: docs/DECISIONS.md, Ethan section (E1). Code that writes and checks it: app/audit_log.py.

Layers, each one tested to fire on its own (tests/test_audit_log_db.py):
1. privileges: UPDATE, DELETE and TRUNCATE are revoked from PUBLIC and from the connecting user
   (a speed bump, not a wall: the owner can GRANT them back)
2. triggers: UPDATE, DELETE and TRUNCATE raise (reject_modification() comes from 0002)
3. chain: each row stores the hash of the row before; a BEFORE INSERT trigger refuses a row that
   does not extend the current head, or whose timestamp is not from the database clock
4. verification (app/audit_log.py) recomputes every hash outside the database
5. anchor: the head hash is written to the platform logs, a copy an attacker with database
   access cannot rewrite

Errors raised here use SQLSTATE class AU:  AU001 chain broken   AU002 timestamp not from the DB clock

seq is assigned under the chain lock as head + 1, not from a sequence, so a rolled-back insert
never leaves a gap and a gap can only mean a deleted row.

Revision ID: 0003
Revises: 0002
"""
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

# Same number as LOCK_KEY in app/audit_log.py (ASCII "AUDITLOG"); a test checks they agree.
LOCK_KEY = 4707744067223310151

STATEMENTS = [
    r"""
    CREATE TABLE audit_log (
        seq         BIGINT PRIMARY KEY CHECK (seq >= 1),
        -- database clock, taken under the chain lock; see audit_log_check_chain()
        ts          TIMESTAMPTZ NOT NULL,
        -- text, not a foreign key: the log must be writable for unknown users (failed logins)
        -- and must never block or be changed by a change to users or accounts
        user_id     TEXT NULL CHECK (char_length(user_id) <= 64),
        role        TEXT NULL CHECK (char_length(role) <= 32),
        src_ip      TEXT NULL CHECK (char_length(src_ip) <= 64),
        action      TEXT NOT NULL CHECK (char_length(action) <= 64 AND action ~ '^[a-z0-9_]+(\.[a-z0-9_]+){1,2}$'),
        outcome     TEXT NOT NULL CHECK (outcome IN ('ok', 'denied', 'error')),
        object_type TEXT NULL CHECK (char_length(object_type) <= 32),
        object_id   TEXT NULL CHECK (char_length(object_id) <= 64),
        details     JSONB NOT NULL DEFAULT CAST('{}' AS jsonb)
                    CHECK (jsonb_typeof(details) = 'object' AND pg_column_size(details) <= 4096),
        prev_hash   BYTEA NOT NULL CHECK (octet_length(prev_hash) = 32),
        row_hash    BYTEA NOT NULL UNIQUE CHECK (octet_length(row_hash) = 32)
    )
    """,
    "CREATE INDEX audit_log_action_seq ON audit_log (action, seq DESC)",
    "CREATE INDEX audit_log_user_seq ON audit_log (user_id, seq DESC) WHERE user_id IS NOT NULL",
    # ---------------------------------------------------- layer 2: no edits, no deletes
    "CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log "
    "FOR EACH ROW EXECUTE FUNCTION reject_modification()",
    "CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log "
    "FOR EACH STATEMENT EXECUTE FUNCTION reject_modification()",
    # ---------------------------------------------------- layer 3: the chain
    # Serialises writers on the same advisory lock the app takes, then insists the new row extends
    # the head. So even code that forgot the app-side logic cannot fork or backdate the log.
    # (The lock key is a literal: a trigger body cannot take it as a parameter.)
    f"""
    CREATE FUNCTION audit_log_check_chain() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    DECLARE
        head_seq  BIGINT;
        head_hash BYTEA;
    BEGIN
        PERFORM pg_advisory_xact_lock({LOCK_KEY});
        SELECT seq, row_hash INTO head_seq, head_hash FROM audit_log ORDER BY seq DESC LIMIT 1;
        IF head_seq IS NULL THEN
            head_seq := 0;
            head_hash := decode(repeat('00', 32), 'hex');
        END IF;
        IF NEW.seq <> head_seq + 1 OR NEW.prev_hash <> head_hash THEN
            RAISE EXCEPTION USING ERRCODE = 'AU001',
                MESSAGE = format('audit_log chain broken: next row must be seq %s', head_seq + 1);
        END IF;
        IF NEW.ts < clock_timestamp() - interval '30 seconds' OR NEW.ts > clock_timestamp() + interval '5 seconds' THEN
            RAISE EXCEPTION USING ERRCODE = 'AU002', MESSAGE = 'audit_log ts must come from the database clock';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER audit_log_chain BEFORE INSERT ON audit_log "
    "FOR EACH ROW EXECUTE FUNCTION audit_log_check_chain()",
    # ---------------------------------------------------- layer 1: privileges
    "REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC",
    "REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM CURRENT_USER",
]


def upgrade() -> None:
    # One statement per call: function bodies contain semicolons, and the driver
    # runs a single statement per execute.
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_log CASCADE")
    op.execute("DROP FUNCTION IF EXISTS audit_log_check_chain()")
