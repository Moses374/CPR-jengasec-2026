"""Adam's durable idempotency, transfer-policy, reversal, and reconciliation records.

Design: docs/DECISIONS.md, Adam's answers and API draft.

Revision ID: 0004
Revises: 0003
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

STATEMENTS = [
    # Preserve the current candidate settings in the DB, not in request input. Moses must
    # replace the provisional caps with values that clear the approval threshold before release.
    """
    INSERT INTO ledger_settings (key, value) VALUES
        ('min_transfer_cents', 100),
        ('max_transfer_cents', 250000),
        ('max_daily_outgoing_cents', 1000000)
    """,
    # The client key itself is never retained; the key and canonical request are SHA-256 hex.
    """
    CREATE TABLE idempotency_keys (
        id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        user_id         UUID NOT NULL REFERENCES users(id),
        key_hash        CHAR(64) NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),
        request_hash    CHAR(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
        response_status SMALLINT NULL CHECK (response_status BETWEEN 100 AND 599),
        response_body   JSONB NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at      TIMESTAMPTZ NOT NULL DEFAULT now() + interval '24 hours',
        UNIQUE (user_id, key_hash),
        CHECK ((response_status IS NULL) = (response_body IS NULL)),
        CHECK (expires_at > created_at)
    )
    """,
    "CREATE INDEX idempotency_keys_expiry ON idempotency_keys (expires_at)",
    """
    CREATE FUNCTION idempotency_keys_guard_update() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        IF NEW.user_id <> OLD.user_id OR NEW.key_hash <> OLD.key_hash THEN
            RAISE EXCEPTION USING ERRCODE = 'LG002', MESSAGE = 'idempotency key identity is immutable';
        END IF;
        IF OLD.expires_at <= now() THEN
            IF NEW.response_status IS NOT NULL OR NEW.response_body IS NOT NULL
               OR NEW.created_at <= OLD.created_at OR NEW.expires_at <= now() THEN
                RAISE EXCEPTION USING ERRCODE = 'LG002', MESSAGE = 'expired idempotency key must be freshly claimed';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.request_hash <> OLD.request_hash
           OR NEW.created_at <> OLD.created_at OR NEW.expires_at <> OLD.expires_at
           OR OLD.response_status IS NOT NULL
           OR NEW.response_status IS NULL OR NEW.response_body IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'LG002', MESSAGE = 'idempotency response may be written once';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER idempotency_keys_guard_update BEFORE UPDATE ON idempotency_keys "
    "FOR EACH ROW EXECUTE FUNCTION idempotency_keys_guard_update()",
    """
    CREATE FUNCTION idempotency_keys_guard_delete() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        IF OLD.expires_at > now() THEN
            RAISE EXCEPTION USING ERRCODE = 'LG002', MESSAGE = 'unexpired idempotency keys cannot be deleted';
        END IF;
        RETURN OLD;
    END $$
    """,
    "CREATE TRIGGER idempotency_keys_guard_delete BEFORE DELETE ON idempotency_keys "
    "FOR EACH ROW EXECUTE FUNCTION idempotency_keys_guard_delete()",
    "CREATE TRIGGER idempotency_keys_no_truncate BEFORE TRUNCATE ON idempotency_keys "
    "FOR EACH STATEMENT EXECUTE FUNCTION reject_modification()",
    """
    CREATE FUNCTION idempotency_keys_require_response() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM idempotency_keys
            WHERE id = NEW.id AND response_status IS NULL AND expires_at > now()
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG002', MESSAGE = 'idempotency claim must store a response before commit';
        END IF;
        RETURN NULL;
    END $$
    """,
    "CREATE CONSTRAINT TRIGGER idempotency_keys_require_response AFTER INSERT OR UPDATE ON idempotency_keys "
    "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION idempotency_keys_require_response()",
    # Enforce the shared open-request ceiling across transfers and reversals. Limit values
    # themselves remain provisional until Moses confirms the maker-checker-compatible caps.
    """
    CREATE FUNCTION transfer_requests_open_request_limit() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    DECLARE
        open_count INT;
    BEGIN
        IF NEW.status NOT IN ('pending_approval', 'held_review') THEN
            RETURN NEW;
        END IF;

        PERFORM id FROM accounts WHERE id = NEW.from_account_id FOR NO KEY UPDATE;
        SELECT
            (SELECT count(*) FROM transfer_requests tr
             WHERE tr.from_account_id = NEW.from_account_id
               AND tr.status IN ('pending_approval', 'held_review') AND tr.expires_at > now()
               AND tr.id <> NEW.id)
            +
            (SELECT count(*) FROM reversal_requests rr
             JOIN transfer_requests original ON original.id = rr.original_request_id
             WHERE original.to_account_id = NEW.from_account_id
               AND rr.status = 'pending_approval' AND rr.expires_at > now())
        INTO open_count;
        IF open_count >= ledger_setting('max_open_requests_per_account') THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'too many open requests on source account';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER zz_transfer_requests_open_limit BEFORE INSERT OR UPDATE OF status ON transfer_requests "
    "FOR EACH ROW EXECUTE FUNCTION transfer_requests_open_request_limit()",
    # A reversal request is the maker-checker record paired with the reversal ledger transaction.
    """
    CREATE TABLE reversal_requests (
        id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        -- Checked by reversal_requests_guard_insert; omitting an FK lets the existing
        -- transfer_requests TRUNCATE guard report its own append-only SQLSTATE.
        original_request_id      UUID NOT NULL UNIQUE,
        requester_id             UUID NOT NULL REFERENCES users(id),
        checker_id               UUID NULL REFERENCES users(id),
        reason                   TEXT NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 140),
        status                   TEXT NOT NULL DEFAULT 'pending_approval'
                                 CHECK (status IN ('pending_approval', 'posted', 'rejected', 'expired', 'failed')),
        reversal_transaction_id  UUID NULL UNIQUE REFERENCES ledger_transactions(id),
        failure_reason           TEXT NULL CHECK (char_length(failure_reason) <= 200),
        created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at               TIMESTAMPTZ NOT NULL DEFAULT now() + interval '24 hours',
        decided_at               TIMESTAMPTZ NULL,
        CHECK (checker_id IS NULL OR checker_id <> requester_id),
        CHECK ((status = 'posted') = (reversal_transaction_id IS NOT NULL)),
        CHECK (status NOT IN ('posted', 'rejected') OR checker_id IS NOT NULL),
        CHECK ((status IN ('posted', 'rejected', 'expired', 'failed')) = (decided_at IS NOT NULL)),
        CHECK (expires_at > created_at)
    )
    """,
    "CREATE INDEX reversal_requests_pending ON reversal_requests (created_at) WHERE status = 'pending_approval'",
    # Reversal approvals reserve the recipient's funds just like transfer holds do.
    """
    CREATE OR REPLACE FUNCTION ledger_held_amount(acct UUID) RETURNS BIGINT
    LANGUAGE sql STABLE SET search_path = public, pg_temp AS $$
        SELECT (
            COALESCE((
                SELECT SUM(amount) FROM transfer_requests
                WHERE from_account_id = acct AND status IN ('pending_approval', 'held_review') AND expires_at > now()
            ), 0)
            + COALESCE((
                SELECT SUM(tr.amount) FROM reversal_requests rr
                JOIN transfer_requests tr ON tr.id = rr.original_request_id
                WHERE tr.to_account_id = acct AND rr.status = 'pending_approval' AND rr.expires_at > now()
            ), 0)
        )::BIGINT
    $$
    """,
    """
    CREATE FUNCTION reversal_requests_guard_insert() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    DECLARE
        original transfer_requests%ROWTYPE;
        source_status TEXT;
        open_count INT;
    BEGIN
        IF NEW.status <> 'pending_approval' OR NEW.checker_id IS NOT NULL
           OR NEW.reversal_transaction_id IS NOT NULL OR NEW.decided_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'a reversal request must start pending approval';
        END IF;
        IF NEW.expires_at > now() + interval '24 hours' THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'reversal expiry may not exceed 24 hours';
        END IF;
        SELECT tr.* INTO original FROM transfer_requests tr
        JOIN ledger_transactions lt ON lt.id = tr.ledger_transaction_id
        WHERE tr.id = NEW.original_request_id AND tr.status = 'posted' AND lt.kind = 'transfer';
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'only a posted transfer can be reversed';
        END IF;
        IF NEW.requester_id = original.maker_id THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'the transfer maker cannot request its own reversal';
        END IF;
        SELECT status INTO source_status FROM accounts WHERE id = original.to_account_id FOR NO KEY UPDATE;
        IF source_status <> 'active' THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'reversal source account is not active';
        END IF;
        SELECT
            (SELECT count(*) FROM transfer_requests tr
             WHERE tr.from_account_id = original.to_account_id
               AND tr.status IN ('pending_approval', 'held_review') AND tr.expires_at > now())
            +
            (SELECT count(*) FROM reversal_requests rr
             JOIN transfer_requests tr ON tr.id = rr.original_request_id
             WHERE tr.to_account_id = original.to_account_id
               AND rr.status = 'pending_approval' AND rr.expires_at > now())
        INTO open_count;
        IF open_count >= ledger_setting('max_open_requests_per_account') THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'too many open requests on reversal source account';
        END IF;
        IF ledger_available_balance(original.to_account_id) - original.amount <
           (SELECT min_balance FROM accounts WHERE id = original.to_account_id) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG004', MESSAGE = 'insufficient funds to reserve this reversal';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER reversal_requests_guard_insert BEFORE INSERT ON reversal_requests "
    "FOR EACH ROW EXECUTE FUNCTION reversal_requests_guard_insert()",
    """
    CREATE FUNCTION reversal_requests_guard_update() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        IF OLD.status <> 'pending_approval' THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = 'reversal request is final';
        END IF;
        IF (to_jsonb(NEW) - ARRAY['status', 'checker_id', 'reversal_transaction_id', 'failure_reason', 'decided_at'])
           IS DISTINCT FROM
           (to_jsonb(OLD) - ARRAY['status', 'checker_id', 'reversal_transaction_id', 'failure_reason', 'decided_at']) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG002', MESSAGE = 'reversal request details are immutable';
        END IF;
        IF NEW.status NOT IN ('posted', 'rejected', 'expired', 'failed') THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = 'illegal reversal request transition';
        END IF;
        IF NEW.status = 'expired' THEN
            IF OLD.expires_at > now() THEN
                RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = 'reversal request has not expired';
            END IF;
        ELSIF OLD.expires_at <= now() THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = 'reversal request has expired';
        END IF;
        IF NEW.status IN ('posted', 'rejected', 'failed') THEN
            IF NEW.checker_id IS NULL OR NEW.checker_id = NEW.requester_id THEN
                RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'a different checker is required';
            END IF;
        END IF;
        IF NEW.status = 'posted' THEN
            PERFORM a.id FROM accounts a JOIN transfer_requests tr ON tr.to_account_id = a.id
            WHERE tr.id = NEW.original_request_id AND a.status = 'active' FOR NO KEY UPDATE OF a;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'reversal source account is not active';
            END IF;
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
    # Replace the migration-0002 fail-closed placeholder. A reversal exactly cancels a posted transfer.
    """
    CREATE OR REPLACE FUNCTION ledger_assert_reversal_valid(txn UUID) RETURNS void
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    DECLARE
        original UUID;
        original_count BIGINT;
        reversal_count BIGINT;
    BEGIN
        SELECT reverses_id INTO original FROM ledger_transactions WHERE id = txn AND kind = 'reversal';
        IF original IS NULL OR NOT EXISTS (
            SELECT 1 FROM ledger_transactions WHERE id = original AND kind = 'transfer'
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG003', MESSAGE = 'a reversal must reference an original transfer';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM reversal_requests rr
            JOIN transfer_requests tr ON tr.id = rr.original_request_id
            WHERE rr.status = 'posted' AND rr.reversal_transaction_id = txn
              AND tr.status = 'posted' AND tr.ledger_transaction_id = original
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG003', MESSAGE = 'reversal has no matching posted reversal request';
        END IF;

        SELECT count(*) INTO original_count FROM entries WHERE transaction_id = original;
        SELECT count(*) INTO reversal_count FROM entries WHERE transaction_id = txn;
        IF original_count < 2 OR original_count <> reversal_count
           OR EXISTS (
               SELECT 1 FROM entries old_entry
               LEFT JOIN entries new_entry
                 ON new_entry.transaction_id = txn AND new_entry.account_id = old_entry.account_id
               WHERE old_entry.transaction_id = original
                 AND (new_entry.account_id IS NULL OR new_entry.amount <> -old_entry.amount)
           ) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG003', MESSAGE = 'reversal entries do not exactly negate the original transfer';
        END IF;
    END $$
    """,
    """
    CREATE FUNCTION reversal_requests_check_posted() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        IF NEW.status = 'posted' THEN
            IF (SELECT kind FROM ledger_transactions WHERE id = NEW.reversal_transaction_id) <> 'reversal' THEN
                RAISE EXCEPTION USING ERRCODE = 'LG003', MESSAGE = 'reversal request must point to a reversal transaction';
            END IF;
            PERFORM ledger_assert_reversal_valid(NEW.reversal_transaction_id);
        END IF;
        RETURN NULL;
    END $$
    """,
    "CREATE CONSTRAINT TRIGGER reversal_requests_check_posted AFTER INSERT OR UPDATE ON reversal_requests "
    "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.status = 'posted') "
    "EXECUTE FUNCTION reversal_requests_check_posted()",
    # Results are historical records; at most one run may be active at a time.
    """
    CREATE TABLE recon_runs (
        id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        business_date      DATE NOT NULL,
        status             TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'passed', 'mismatch', 'failed')),
        started_by         UUID NOT NULL REFERENCES users(id),
        started_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
        finished_at        TIMESTAMPTZ NULL,
        checks             JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(checks) = 'object'),
        mismatches         JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(mismatches) = 'array'),
        transaction_count  BIGINT NOT NULL DEFAULT 0 CHECK (transaction_count >= 0),
        entry_count        BIGINT NOT NULL DEFAULT 0 CHECK (entry_count >= 0),
        audit_head_seq     BIGINT NULL CHECK (audit_head_seq IS NULL OR audit_head_seq >= 1),
        audit_head_hash    CHAR(64) NULL CHECK (audit_head_hash IS NULL OR audit_head_hash ~ '^[0-9a-f]{64}$'),
        CHECK ((status = 'running') = (finished_at IS NULL))
    )
    """,
    "CREATE INDEX recon_runs_business_date ON recon_runs (business_date, started_at DESC)",
    "CREATE UNIQUE INDEX recon_runs_one_active ON recon_runs ((true)) WHERE status = 'running'",
    """
    CREATE FUNCTION recon_runs_guard_insert() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        IF NEW.status <> 'running' OR NEW.finished_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'a reconciliation run must start running';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER recon_runs_guard_insert BEFORE INSERT ON recon_runs "
    "FOR EACH ROW EXECUTE FUNCTION recon_runs_guard_insert()",
    """
    CREATE FUNCTION recon_runs_guard_update() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        IF OLD.status <> 'running' THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = 'completed reconciliation runs are immutable';
        END IF;
        IF (to_jsonb(NEW) - ARRAY['status', 'finished_at', 'checks', 'mismatches', 'transaction_count',
                                 'entry_count', 'audit_head_seq', 'audit_head_hash'])
           IS DISTINCT FROM
           (to_jsonb(OLD) - ARRAY['status', 'finished_at', 'checks', 'mismatches', 'transaction_count',
                                 'entry_count', 'audit_head_seq', 'audit_head_hash']) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG002', MESSAGE = 'reconciliation run identity is immutable';
        END IF;
        IF NEW.status NOT IN ('passed', 'mismatch', 'failed') OR NEW.finished_at IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = 'a run may only transition to a final status';
        END IF;
        NEW.finished_at := now();
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER recon_runs_guard_update BEFORE UPDATE ON recon_runs "
    "FOR EACH ROW EXECUTE FUNCTION recon_runs_guard_update()",
    "CREATE TRIGGER recon_runs_no_delete BEFORE DELETE ON recon_runs "
    "FOR EACH ROW EXECUTE FUNCTION reject_modification()",
    "CREATE TRIGGER recon_runs_no_truncate BEFORE TRUNCATE ON recon_runs "
    "FOR EACH STATEMENT EXECUTE FUNCTION reject_modification()",
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    for table in ("recon_runs", "reversal_requests", "idempotency_keys"):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    for function in (
        "recon_runs_guard_insert()",
        "recon_runs_guard_update()",
        "reversal_requests_guard_insert()",
        "reversal_requests_guard_update()",
        "reversal_requests_check_posted()",
        "idempotency_keys_guard_update()",
        "idempotency_keys_guard_delete()",
        "idempotency_keys_require_response()",
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {function}")
    op.execute("DROP TRIGGER IF EXISTS zz_transfer_requests_open_limit ON transfer_requests")
    op.execute("DROP FUNCTION IF EXISTS transfer_requests_open_request_limit()")
    op.execute("""
        CREATE OR REPLACE FUNCTION ledger_held_amount(acct UUID) RETURNS BIGINT
        LANGUAGE sql STABLE SET search_path = public, pg_temp AS $$
            SELECT COALESCE(SUM(amount), 0)::BIGINT FROM transfer_requests
            WHERE from_account_id = acct AND status IN ('pending_approval', 'held_review') AND expires_at > now()
        $$
    """)
    op.execute("""
        CREATE OR REPLACE FUNCTION ledger_assert_reversal_valid(txn UUID) RETURNS void
        LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
        BEGIN
            RAISE EXCEPTION USING ERRCODE = 'LG003', MESSAGE = 'reversals are not enabled yet';
        END $$
    """)
    op.execute("DROP TRIGGER IF EXISTS ledger_settings_append_only ON ledger_settings")
    op.execute("DELETE FROM ledger_settings WHERE key IN ('min_transfer_cents', 'max_transfer_cents', 'max_daily_outgoing_cents')")
    op.execute("CREATE TRIGGER ledger_settings_append_only BEFORE UPDATE OR DELETE ON ledger_settings "
               "FOR EACH ROW EXECUTE FUNCTION reject_modification()")
