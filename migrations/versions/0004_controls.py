"""Controls: idempotency, limits, held reviews with a checker, reversals, reconciliation runs.

Design: docs/DECISIONS.md, Adam's section (agreed 13 Oct, limits at bank scale: minimum KSh 1,
approval threshold KSh 100,000, KSh 250,000 per transfer, KSh 1,000,000 per account per UTC day).
As in 0002, the database enforces each money rule itself; app/ledger.py checks first for clean errors.

New SQLSTATE: LG007 limit exceeded.

Revision ID: 0004
Revises: 0003
"""
from pathlib import Path

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

OPEN = "('pending_approval', 'held_review')"

STATEMENTS = [
    # ------------------------------------------------------------ idempotency
    # One row per (user, scope, key). The raw key is never stored: only its SHA-256.
    # Rows are written in the same transaction as the operation and kept for the whole event
    # (stricter than 24 hours: a replay after a day still cannot pay twice).
    """
    CREATE TABLE idempotency_keys (
        user_id     UUID NOT NULL REFERENCES users(id),
        scope       TEXT NOT NULL CHECK (scope IN ('transfer', 'reversal')),
        key_hash    TEXT NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),
        fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
        response    JSONB NULL CHECK (response IS NULL OR pg_column_size(response) <= 1024),
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (user_id, scope, key_hash)
    )
    """,
    # The stored response is written once, inside the operation's transaction; nothing else changes.
    """
    CREATE FUNCTION idempotency_keys_guard_update() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        IF OLD.response IS NOT NULL
           OR (to_jsonb(NEW) - 'response') IS DISTINCT FROM (to_jsonb(OLD) - 'response') THEN
            RAISE EXCEPTION USING ERRCODE = 'LG002', MESSAGE = 'an idempotency record is written once';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER idempotency_keys_guard_update BEFORE UPDATE ON idempotency_keys "
    "FOR EACH ROW EXECUTE FUNCTION idempotency_keys_guard_update()",
    "CREATE TRIGGER idempotency_keys_no_delete BEFORE DELETE ON idempotency_keys "
    "FOR EACH ROW EXECUTE FUNCTION reject_modification()",
    "CREATE TRIGGER idempotency_keys_no_truncate BEFORE TRUNCATE ON idempotency_keys "
    "FOR EACH STATEMENT EXECUTE FUNCTION reject_modification()",
    "CREATE TRIGGER idempotency_keys_server_time BEFORE INSERT ON idempotency_keys "
    "FOR EACH ROW EXECUTE FUNCTION ledger_server_time()",

    # ----------------------------------------------------------------- limits
    """
    INSERT INTO ledger_settings (key, value) VALUES
        ('max_transfer_cents', 25000000),
        ('max_daily_outgoing_cents', 100000000)
    ON CONFLICT (key) DO NOTHING
    """,
    "CREATE INDEX transfer_requests_by_account_day ON transfer_requests (from_account_id, created_at)",
    # Today's outgoing value (UTC day): posted transfers plus open requests that still hold funds.
    f"""
    CREATE FUNCTION ledger_daily_outgoing(acct UUID, exclude_request UUID) RETURNS BIGINT
    LANGUAGE sql STABLE SET search_path = public, pg_temp AS $$
        SELECT COALESCE(SUM(amount), 0)::BIGINT FROM transfer_requests
        WHERE from_account_id = acct
          AND id IS DISTINCT FROM exclude_request
          AND created_at >= date_trunc('day', now(), 'UTC')
          AND (status = 'posted' OR (status IN {OPEN} AND expires_at > now()))
    $$
    """,
    # Runs after the guard triggers (alphabetical), which have already locked the source account
    # on insert; on approval it takes the same lock itself (request row, then account).
    """
    CREATE FUNCTION transfer_requests_limits() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        IF NEW.status NOT IN ('posted', 'pending_approval', 'held_review') THEN
            RETURN NEW;
        END IF;
        IF TG_OP = 'UPDATE' AND NOT (NEW.status = 'posted' AND OLD.status <> 'posted') THEN
            RETURN NEW;   -- only a release to posted is re-checked; open requests were checked when created
        END IF;
        PERFORM 1 FROM accounts WHERE id = NEW.from_account_id FOR NO KEY UPDATE;
        IF NEW.amount > ledger_setting('max_transfer_cents') THEN
            RAISE EXCEPTION USING ERRCODE = 'LG007', MESSAGE = 'per_transfer_limit';
        END IF;
        IF ledger_daily_outgoing(NEW.from_account_id, NEW.id) + NEW.amount > ledger_setting('max_daily_outgoing_cents') THEN
            RAISE EXCEPTION USING ERRCODE = 'LG007', MESSAGE = 'daily_limit';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER transfer_requests_limits BEFORE INSERT OR UPDATE ON transfer_requests "
    "FOR EACH ROW EXECUTE FUNCTION transfer_requests_limits()",

    # ------------------------------------------------- fraud and held reviews
    # Fraud reasons are fixed at creation (not a workflow column, so the update guard keeps them immutable).
    "ALTER TABLE transfer_requests ADD COLUMN fraud_reasons TEXT[] NULL "
    "CHECK (fraud_reasons IS NULL OR cardinality(fraud_reasons) <= 10)",
    # Same as 0002 except: a held review is released or blocked only by a checker who is not the
    # maker, and nothing posts from an open state without a checker.
    """
    CREATE OR REPLACE FUNCTION transfer_requests_guard_update() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    DECLARE
        workflow CONSTANT TEXT[] := ARRAY['status', 'checker_id', 'decided_at', 'failure_reason', 'ledger_transaction_id'];
    BEGIN
        IF OLD.status NOT IN ('held_review', 'pending_approval') THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = format('request %s is final (%s)', OLD.id, OLD.status);
        END IF;
        IF (to_jsonb(NEW) - workflow) IS DISTINCT FROM (to_jsonb(OLD) - workflow) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG002', MESSAGE = 'amount, accounts and maker of a request cannot change';
        END IF;
        IF NOT (
            (OLD.status = 'held_review' AND NEW.status IN ('pending_approval', 'posted', 'blocked', 'expired', 'failed'))
            OR (OLD.status = 'pending_approval' AND NEW.status IN ('posted', 'rejected', 'expired', 'failed'))
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005',
                MESSAGE = format('illegal transition %s -> %s', OLD.status, NEW.status);
        END IF;

        IF NEW.status = 'expired' THEN
            IF OLD.expires_at > now() THEN
                RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = 'request has not expired yet';
            END IF;
        ELSIF OLD.expires_at <= now() THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = 'request has expired';
        END IF;

        IF NEW.checker_id IS DISTINCT FROM OLD.checker_id
           AND NOT ((OLD.status = 'pending_approval' AND NEW.status IN ('posted', 'rejected'))
                 OR (OLD.status = 'held_review' AND NEW.status IN ('posted', 'blocked'))) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'checker is only set when approving, rejecting or blocking';
        END IF;

        IF NEW.status = 'posted' THEN
            IF NEW.checker_id IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'posting a pending approval or held review needs a checker';
            END IF;
            IF (SELECT status FROM accounts WHERE id = NEW.from_account_id) <> 'active' THEN
                RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'source account is not active';
            END IF;
        END IF;

        NEW.decided_at := now();
        RETURN NEW;
    END $$
    """,

    # -------------------------------------------------------------- reversals
    # A teller requests, a different approver approves; the amount and accounts always come
    # from the original transfer. At most one live (pending or posted) reversal per transfer.
    """
    CREATE TABLE reversal_requests (
        id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        transfer_request_id     UUID NOT NULL REFERENCES transfer_requests(id),
        original_transaction_id UUID NOT NULL REFERENCES ledger_transactions(id),
        amount                  BIGINT NOT NULL CHECK (amount >= 100),
        maker_id                UUID NOT NULL REFERENCES users(id),
        checker_id              UUID NULL REFERENCES users(id),
        reason                  TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 200),
        status                  TEXT NOT NULL CHECK (status IN ('pending_approval', 'posted', 'rejected', 'expired', 'failed')),
        failure_reason          TEXT NULL CHECK (char_length(failure_reason) <= 200),
        decided_at              TIMESTAMPTZ NULL,
        expires_at              TIMESTAMPTZ NOT NULL DEFAULT now() + interval '24 hours',
        ledger_transaction_id   UUID NULL UNIQUE REFERENCES ledger_transactions(id),
        created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
        CHECK (checker_id IS NULL OR checker_id <> maker_id),
        CHECK ((status = 'posted') = (ledger_transaction_id IS NOT NULL)),
        CHECK (status NOT IN ('posted', 'rejected') OR checker_id IS NOT NULL),
        CHECK (expires_at > created_at)
    )
    """,
    "CREATE UNIQUE INDEX reversal_requests_one_live ON reversal_requests (transfer_request_id) "
    "WHERE status IN ('pending_approval', 'posted')",
    """
    CREATE FUNCTION reversal_requests_guard_insert() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    DECLARE
        orig transfer_requests%ROWTYPE;
    BEGIN
        IF NEW.status <> 'pending_approval' OR NEW.checker_id IS NOT NULL OR NEW.decided_at IS NOT NULL
           OR NEW.ledger_transaction_id IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = 'a reversal request starts as pending_approval';
        END IF;
        IF NEW.expires_at > now() + make_interval(hours => ledger_setting('max_request_lifetime_hours')::INT) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'request expiry too far in the future';
        END IF;
        SELECT * INTO orig FROM transfer_requests WHERE id = NEW.transfer_request_id;
        IF orig.status IS DISTINCT FROM 'posted'
           OR NEW.original_transaction_id IS DISTINCT FROM orig.ledger_transaction_id
           OR NEW.amount IS DISTINCT FROM orig.amount THEN
            RAISE EXCEPTION USING ERRCODE = 'LG003', MESSAGE = 'a reversal must match a posted transfer exactly';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER reversal_requests_guard_insert BEFORE INSERT ON reversal_requests "
    "FOR EACH ROW EXECUTE FUNCTION reversal_requests_guard_insert()",
    """
    CREATE FUNCTION reversal_requests_guard_update() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    DECLARE
        workflow CONSTANT TEXT[] := ARRAY['status', 'checker_id', 'decided_at', 'failure_reason', 'ledger_transaction_id'];
    BEGIN
        IF OLD.status <> 'pending_approval' THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = format('reversal %s is final (%s)', OLD.id, OLD.status);
        END IF;
        IF (to_jsonb(NEW) - workflow) IS DISTINCT FROM (to_jsonb(OLD) - workflow) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG002', MESSAGE = 'a reversal request cannot change';
        END IF;
        IF NEW.status NOT IN ('posted', 'rejected', 'expired', 'failed') THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = format('illegal transition %s -> %s', OLD.status, NEW.status);
        END IF;
        IF NEW.status = 'expired' THEN
            IF OLD.expires_at > now() THEN
                RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = 'request has not expired yet';
            END IF;
        ELSIF OLD.expires_at <= now() THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = 'request has expired';
        END IF;
        IF NEW.checker_id IS DISTINCT FROM OLD.checker_id AND NEW.status NOT IN ('posted', 'rejected') THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'checker is only set when approving or rejecting';
        END IF;
        NEW.decided_at := now();
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER reversal_requests_guard_update BEFORE UPDATE ON reversal_requests "
    "FOR EACH ROW EXECUTE FUNCTION reversal_requests_guard_update()",
    "CREATE TRIGGER reversal_requests_no_delete BEFORE DELETE ON reversal_requests "
    "FOR EACH ROW EXECUTE FUNCTION reject_modification()",
    "CREATE TRIGGER reversal_requests_no_truncate BEFORE TRUNCATE ON reversal_requests "
    "FOR EACH STATEMENT EXECUTE FUNCTION reject_modification()",
    # Replaces the fail-closed version from 0002: a reversal must be exactly the opposite of a
    # transfer (never of a reversal) and match one posted reversal request.
    """
    CREATE OR REPLACE FUNCTION ledger_assert_reversal_valid(txn UUID) RETURNS void
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    DECLARE
        t  ledger_transactions%ROWTYPE;
        rr reversal_requests%ROWTYPE;
    BEGIN
        SELECT * INTO t FROM ledger_transactions WHERE id = txn;
        SELECT * INTO rr FROM reversal_requests WHERE ledger_transaction_id = txn;
        IF NOT FOUND OR rr.status <> 'posted' OR rr.original_transaction_id IS DISTINCT FROM t.reverses_id THEN
            RAISE EXCEPTION USING ERRCODE = 'LG003', MESSAGE = format('reversal %s has no posted reversal request', txn);
        END IF;
        IF (SELECT kind FROM ledger_transactions WHERE id = t.reverses_id) <> 'transfer' THEN
            RAISE EXCEPTION USING ERRCODE = 'LG003', MESSAGE = 'only a transfer can be reversed';
        END IF;
        IF (SELECT count(*) FROM entries WHERE transaction_id = txn)
               <> (SELECT count(*) FROM entries WHERE transaction_id = t.reverses_id)
           OR EXISTS (SELECT 1 FROM entries o WHERE o.transaction_id = t.reverses_id AND NOT EXISTS (
                  SELECT 1 FROM entries r WHERE r.transaction_id = txn
                  AND r.account_id = o.account_id AND r.amount = -o.amount)) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG003', MESSAGE = format('reversal %s is not the exact opposite of %s', txn, t.reverses_id);
        END IF;
    END $$
    """,
    """
    CREATE FUNCTION reversal_requests_check_posted() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        IF (SELECT kind FROM ledger_transactions WHERE id = NEW.ledger_transaction_id) <> 'reversal' THEN
            RAISE EXCEPTION USING ERRCODE = 'LG003', MESSAGE = 'a posted reversal must point at a reversal transaction';
        END IF;
        PERFORM ledger_assert_transaction_valid(NEW.ledger_transaction_id);
        RETURN NULL;
    END $$
    """,
    """
    CREATE CONSTRAINT TRIGGER reversal_requests_check_posted AFTER UPDATE ON reversal_requests
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.status = 'posted')
        EXECUTE FUNCTION reversal_requests_check_posted()
    """,

    # --------------------------------------------------------- reconciliation
    # Append-only record of every run; a run is computed and stored in one transaction.
    """
    CREATE TABLE recon_runs (
        id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        business_date DATE NOT NULL,
        started_by    UUID NOT NULL REFERENCES users(id),
        status        TEXT NOT NULL CHECK (status IN ('passed', 'mismatch')),
        checks        JSONB NOT NULL CHECK (jsonb_typeof(checks) = 'object'),
        mismatches    JSONB NOT NULL CHECK (jsonb_typeof(mismatches) = 'array' AND pg_column_size(mismatches) <= 65536),
        created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
        CHECK ((status = 'passed') = (jsonb_array_length(mismatches) = 0))
    )
    """,
    "CREATE INDEX recon_runs_by_date ON recon_runs (business_date, created_at DESC)",
    "CREATE TRIGGER recon_runs_append_only BEFORE UPDATE OR DELETE ON recon_runs "
    "FOR EACH ROW EXECUTE FUNCTION reject_modification()",
    "CREATE TRIGGER recon_runs_no_truncate BEFORE TRUNCATE ON recon_runs "
    "FOR EACH STATEMENT EXECUTE FUNCTION reject_modification()",
    "CREATE TRIGGER recon_runs_server_time BEFORE INSERT ON recon_runs "
    "FOR EACH ROW EXECUTE FUNCTION ledger_server_time()",
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def _original_guard_update() -> str:
    """The 0002 version of transfer_requests_guard_update(), restored on downgrade."""
    source = (Path(__file__).parent / "0002_ledger_core.py").read_text(encoding="utf-8")
    namespace: dict = {}
    exec(compile(source, "0002_ledger_core.py", "exec"), namespace)  # noqa: S102 (our own migration file)
    [body] = [s for s in namespace["STATEMENTS"] if "CREATE FUNCTION transfer_requests_guard_update" in s]
    return body.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS recon_runs")
    op.execute("DROP TABLE IF EXISTS reversal_requests")
    op.execute("DROP FUNCTION IF EXISTS reversal_requests_check_posted()")
    op.execute("DROP FUNCTION IF EXISTS reversal_requests_guard_update()")
    op.execute("DROP FUNCTION IF EXISTS reversal_requests_guard_insert()")
    op.execute("""
        CREATE OR REPLACE FUNCTION ledger_assert_reversal_valid(txn UUID) RETURNS void
        LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
        BEGIN
            RAISE EXCEPTION USING ERRCODE = 'LG003', MESSAGE = 'reversals are not enabled yet';
        END $$
    """)
    op.execute(_original_guard_update())
    op.execute("ALTER TABLE transfer_requests DROP COLUMN IF EXISTS fraud_reasons")
    op.execute("DROP TRIGGER IF EXISTS transfer_requests_limits ON transfer_requests")
    op.execute("DROP FUNCTION IF EXISTS transfer_requests_limits()")
    op.execute("DROP FUNCTION IF EXISTS ledger_daily_outgoing(UUID, UUID)")
    op.execute("DROP INDEX IF EXISTS transfer_requests_by_account_day")
    op.execute("DROP TABLE IF EXISTS idempotency_keys")
    op.execute("DROP FUNCTION IF EXISTS idempotency_keys_guard_update()")
    # ledger_settings is append-only: the two limit rows stay (harmless without the trigger).
