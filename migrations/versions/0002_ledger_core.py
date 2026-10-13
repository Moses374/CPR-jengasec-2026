"""Ledger core: users (minimal), accounts, ledger transactions, entries, transfer requests.

Design and reasons: docs/DECISIONS.md, Moses section (Q1-Q4).

The database itself guarantees the money rules, so a bug or a forgotten check in
application code cannot break them:
- entries and ledger transactions are append-only
- every ledger transaction balances (entries sum to zero, at least two entries)
- every transfer in the ledger matches exactly one posted transfer request
- no debit takes an account below its minimum, counting open holds
- a transfer request's amount and accounts never change; its status follows the
  state machine; above the approval threshold it cannot post without a checker

Errors raised here use SQLSTATE class LG (see app/ledger.py):
  LG001 unbalanced transaction   LG002 append-only / immutable field
  LG003 ledger and request disagree   LG004 insufficient funds
  LG005 illegal status transition     LG006 request rule violated

Not here yet, on purpose:
- checker role check: needs Kathy's users.role (her revision adds it)
- reversals: blocked until Adam's revision replaces ledger_assert_reversal_valid()
- "no new opening balances" trigger: added at the end of the seed migration
- least-privilege table owner: waits for #3 to show what the platform DB user may do

Revision ID: 0002
Revises: 0001
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

OPEN = "('pending_approval', 'held_review')"

STATEMENTS = [
    # ---------------------------------------------------------------- tables
    """
    CREATE TABLE users (
        id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        -- lowercase only, so "Admin" and "admin" can never be two different users
        username   TEXT NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9._-]{3,32}$'),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE accounts (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        owner_id    UUID NULL REFERENCES users(id),
        kind        TEXT NOT NULL CHECK (kind IN ('customer', 'system')),
        name        TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
        currency    CHAR(3) NOT NULL DEFAULT 'KES' CHECK (currency = 'KES'),
        min_balance BIGINT NOT NULL DEFAULT 0,
        status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'frozen', 'closed')),
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        CHECK ((kind = 'system') = (owner_id IS NULL)),
        CHECK (kind = 'system' OR min_balance >= 0)
    )
    """,
    # No balance column anywhere: balances are derived from entries.
    """
    CREATE TABLE ledger_transactions (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        kind        TEXT NOT NULL CHECK (kind IN ('opening', 'transfer', 'reversal')),
        reverses_id UUID NULL UNIQUE REFERENCES ledger_transactions(id),
        created_by  UUID NULL REFERENCES users(id),
        memo        TEXT NULL CHECK (char_length(memo) <= 140),
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        CHECK ((kind = 'reversal') = (reverses_id IS NOT NULL)),
        CHECK (reverses_id IS DISTINCT FROM id)
    )
    """,
    """
    CREATE TABLE entries (
        id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        transaction_id UUID NOT NULL REFERENCES ledger_transactions(id),
        account_id     UUID NOT NULL REFERENCES accounts(id),
        -- signed minor units (cents): + raises the balance, - lowers it
        amount         BIGINT NOT NULL CHECK (amount <> 0 AND amount BETWEEN -1000000000000 AND 1000000000000),
        created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (transaction_id, account_id)
    )
    """,
    "CREATE INDEX entries_account_amount ON entries (account_id) INCLUDE (amount)",
    """
    CREATE TABLE transfer_requests (
        id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        maker_id              UUID NOT NULL REFERENCES users(id),
        from_account_id       UUID NOT NULL REFERENCES accounts(id),
        to_account_id         UUID NOT NULL REFERENCES accounts(id),
        amount                BIGINT NOT NULL CHECK (amount >= 100 AND amount <= 1000000000000),
        memo                  TEXT NULL CHECK (char_length(memo) <= 140),
        status                TEXT NOT NULL CHECK (status IN ('held_review', 'pending_approval', 'posted',
                                                              'rejected', 'blocked', 'expired', 'failed')),
        checker_id            UUID NULL REFERENCES users(id),
        decided_at            TIMESTAMPTZ NULL,
        failure_reason        TEXT NULL CHECK (char_length(failure_reason) <= 200),
        expires_at            TIMESTAMPTZ NOT NULL DEFAULT now() + interval '24 hours',
        ledger_transaction_id UUID NULL UNIQUE REFERENCES ledger_transactions(id),
        created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
        CHECK (from_account_id <> to_account_id),
        CHECK (checker_id IS NULL OR checker_id <> maker_id),
        CHECK ((status = 'posted') = (ledger_transaction_id IS NOT NULL)),
        CHECK (expires_at > created_at)
    )
    """,
    f"""
    CREATE INDEX transfer_requests_open_by_account ON transfer_requests (from_account_id)
        INCLUDE (amount, expires_at) WHERE status IN {OPEN}
    """,
    # Changed only by a migration (the table is append-only), so a SQL injection
    # cannot quietly raise the threshold. Placeholder values; Kathy sets the real threshold.
    """
    CREATE TABLE ledger_settings (
        key   TEXT PRIMARY KEY,
        value BIGINT NOT NULL
    )
    """,
    """
    INSERT INTO ledger_settings (key, value) VALUES
        ('approval_threshold_cents', 10000000),
        ('max_open_requests_per_account', 5),
        ('max_request_lifetime_hours', 168)
    """,
    # -------------------------------------------------------------- balances
    # One definition, used by the triggers below and by app/ledger.py.
    # Casting the sum to bigint fails closed on overflow instead of wrapping.
    """
    CREATE FUNCTION ledger_setting(k TEXT) RETURNS BIGINT
    LANGUAGE plpgsql STABLE SET search_path = public, pg_temp AS $$
    DECLARE v BIGINT;
    BEGIN
        SELECT value INTO v FROM ledger_settings WHERE key = k;
        IF v IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = format('missing ledger setting %s', k);
        END IF;
        RETURN v;
    END $$
    """,
    """
    CREATE FUNCTION ledger_posted_balance(acct UUID) RETURNS BIGINT
    LANGUAGE sql STABLE SET search_path = public, pg_temp AS $$
        SELECT COALESCE(SUM(amount), 0)::BIGINT FROM entries WHERE account_id = acct
    $$
    """,
    f"""
    CREATE FUNCTION ledger_held_amount(acct UUID) RETURNS BIGINT
    LANGUAGE sql STABLE SET search_path = public, pg_temp AS $$
        SELECT COALESCE(SUM(amount), 0)::BIGINT FROM transfer_requests
        WHERE from_account_id = acct AND status IN {OPEN} AND expires_at > now()
    $$
    """,
    """
    CREATE FUNCTION ledger_available_balance(acct UUID) RETURNS BIGINT
    LANGUAGE sql STABLE SET search_path = public, pg_temp AS $$
        SELECT ledger_posted_balance(acct) - ledger_held_amount(acct)
    $$
    """,
    # ------------------------------------------------- append-only / immutable
    # Shared with the audit log (Ethan): one function rejects UPDATE, DELETE and TRUNCATE.
    """
    CREATE FUNCTION reject_modification() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        RAISE EXCEPTION USING ERRCODE = 'LG002',
            MESSAGE = format('%s is append-only: %s rejected', TG_TABLE_NAME, TG_OP);
    END $$
    """,
    *[
        stmt
        for table in ("entries", "ledger_transactions", "ledger_settings")
        for stmt in (
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION reject_modification()",
            f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
            f"FOR EACH STATEMENT EXECUTE FUNCTION reject_modification()",
        )
    ],
    *[
        stmt
        for table in ("accounts", "transfer_requests")
        for stmt in (
            f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION reject_modification()",
            f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
            f"FOR EACH STATEMENT EXECUTE FUNCTION reject_modification()",
        )
    ],
    # Accounts: only name and status may change (no takeover by changing owner_id,
    # no overdraft by lowering min_balance).
    """
    CREATE FUNCTION accounts_guard_update() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        IF (to_jsonb(NEW) - ARRAY['name', 'status']) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['name', 'status']) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG002', MESSAGE = 'only name and status of an account can change';
        END IF;
        IF OLD.status = 'closed' AND NEW.status <> 'closed' THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = 'a closed account cannot be reopened';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER accounts_guard_update BEFORE UPDATE ON accounts "
    "FOR EACH ROW EXECUTE FUNCTION accounts_guard_update()",
    # Timestamps come from the database clock, never from the caller,
    # so nobody can backdate a transfer to slip under a daily limit.
    # (The seed migration disables only this trigger while it writes history.)
    """
    CREATE FUNCTION ledger_server_time() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        NEW.created_at := now();
        RETURN NEW;
    END $$
    """,
    *[
        f"CREATE TRIGGER {table}_server_time BEFORE INSERT ON {table} "
        f"FOR EACH ROW EXECUTE FUNCTION ledger_server_time()"
        for table in ("entries", "ledger_transactions", "transfer_requests")
    ],
    # ------------------------------------------------- transaction invariants
    # Replaced by Adam's revision. Until then a reversal cannot be posted at all (fails closed).
    """
    CREATE FUNCTION ledger_assert_reversal_valid(txn UUID) RETURNS void
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        RAISE EXCEPTION USING ERRCODE = 'LG003', MESSAGE = 'reversals are not enabled yet';
    END $$
    """,
    """
    CREATE FUNCTION ledger_assert_transaction_valid(txn UUID) RETURNS void
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    DECLARE
        t     ledger_transactions%ROWTYPE;
        r     transfer_requests%ROWTYPE;
        n     INT;
        total NUMERIC;
    BEGIN
        SELECT * INTO t FROM ledger_transactions WHERE id = txn;
        SELECT count(*), COALESCE(SUM(amount), 0) INTO n, total FROM entries WHERE transaction_id = txn;

        IF n < 2 OR total <> 0 THEN
            RAISE EXCEPTION USING ERRCODE = 'LG001',
                MESSAGE = format('ledger transaction %s is unbalanced (%s entries, sum %s)', txn, n, total);
        END IF;

        IF t.kind = 'transfer' THEN
            SELECT * INTO r FROM transfer_requests WHERE ledger_transaction_id = txn;
            IF NOT FOUND OR r.status <> 'posted' THEN
                RAISE EXCEPTION USING ERRCODE = 'LG003',
                    MESSAGE = format('transfer %s has no posted transfer request', txn);
            END IF;
            IF n <> 2
               OR NOT EXISTS (SELECT 1 FROM entries WHERE transaction_id = txn
                              AND account_id = r.from_account_id AND amount = -r.amount)
               OR NOT EXISTS (SELECT 1 FROM entries WHERE transaction_id = txn
                              AND account_id = r.to_account_id AND amount = r.amount) THEN
                RAISE EXCEPTION USING ERRCODE = 'LG003',
                    MESSAGE = format('transfer %s does not match request %s', txn, r.id);
            END IF;
        ELSIF t.kind = 'reversal' THEN
            PERFORM ledger_assert_reversal_valid(txn);
        ELSIF t.kind = 'opening' THEN
            -- money is only ever issued from a system account
            IF EXISTS (SELECT 1 FROM entries e JOIN accounts a ON a.id = e.account_id
                       WHERE e.transaction_id = txn AND e.amount < 0 AND a.kind <> 'system') THEN
                RAISE EXCEPTION USING ERRCODE = 'LG003',
                    MESSAGE = format('opening %s debits a non-system account', txn);
            END IF;
        END IF;
    END $$
    """,
    """
    CREATE FUNCTION entries_check_transaction() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        PERFORM ledger_assert_transaction_valid(NEW.transaction_id);
        RETURN NULL;
    END $$
    """,
    """
    CREATE CONSTRAINT TRIGGER entries_check_transaction AFTER INSERT ON entries
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION entries_check_transaction()
    """,
    # Catches a ledger transaction with no entries at all (the entries trigger never fires for it).
    """
    CREATE FUNCTION ledger_transactions_validate() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        PERFORM ledger_assert_transaction_valid(NEW.id);
        RETURN NULL;
    END $$
    """,
    """
    CREATE CONSTRAINT TRIGGER ledger_transactions_validate AFTER INSERT ON ledger_transactions
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ledger_transactions_validate()
    """,
    # Overdraft backstop: lock the debited account, then require it to stay at or above its
    # minimum after counting open holds. Holds even in a code path that forgot to lock.
    """
    CREATE FUNCTION entries_check_funds() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    DECLARE floor BIGINT;
    BEGIN
        SELECT min_balance INTO floor FROM accounts WHERE id = NEW.account_id FOR NO KEY UPDATE;
        IF ledger_available_balance(NEW.account_id) < floor THEN
            RAISE EXCEPTION USING ERRCODE = 'LG004',
                MESSAGE = format('insufficient funds in account %s', NEW.account_id);
        END IF;
        RETURN NULL;
    END $$
    """,
    """
    CREATE CONSTRAINT TRIGGER entries_check_funds AFTER INSERT ON entries
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.amount < 0)
        EXECUTE FUNCTION entries_check_funds()
    """,
    # ------------------------------------------------------ transfer requests
    f"""
    CREATE FUNCTION transfer_requests_guard_insert() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    DECLARE
        src accounts%ROWTYPE;
        dst accounts%ROWTYPE;
        open_count INT;
    BEGIN
        IF NEW.status NOT IN ('held_review', 'pending_approval', 'posted', 'blocked') THEN
            RAISE EXCEPTION USING ERRCODE = 'LG005', MESSAGE = format('a request cannot start as %s', NEW.status);
        END IF;
        IF NEW.checker_id IS NOT NULL OR NEW.decided_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'a new request cannot already be approved';
        END IF;
        IF NEW.expires_at > now() + make_interval(hours => ledger_setting('max_request_lifetime_hours')::INT) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'request expiry too far in the future';
        END IF;

        -- lock the source account: holds are checked and placed one request at a time
        SELECT * INTO src FROM accounts WHERE id = NEW.from_account_id FOR NO KEY UPDATE;
        SELECT * INTO dst FROM accounts WHERE id = NEW.to_account_id;
        IF src.kind <> 'customer' OR dst.kind <> 'customer' THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'transfers are only between customer accounts';
        END IF;
        IF src.status <> 'active' THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'source account is not active';
        END IF;
        IF dst.status = 'closed' THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'destination account is closed';
        END IF;

        IF NEW.status = 'posted' AND NEW.amount > ledger_setting('approval_threshold_cents') THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'amount above approval threshold needs a checker';
        END IF;

        IF NEW.status IN {OPEN} THEN
            SELECT count(*) INTO open_count FROM transfer_requests
            WHERE from_account_id = NEW.from_account_id AND status IN {OPEN} AND expires_at > now();
            IF open_count >= ledger_setting('max_open_requests_per_account') THEN
                RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'too many open requests on this account';
            END IF;
            IF ledger_available_balance(NEW.from_account_id) - NEW.amount < src.min_balance THEN
                RAISE EXCEPTION USING ERRCODE = 'LG004',
                    MESSAGE = format('insufficient funds in account %s', NEW.from_account_id);
            END IF;
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER transfer_requests_guard_insert BEFORE INSERT ON transfer_requests "
    "FOR EACH ROW EXECUTE FUNCTION transfer_requests_guard_insert()",
    # Only the workflow columns may change, only along the state machine, never after a
    # terminal status. Columns added later are immutable unless added to this list (fails closed).
    """
    CREATE FUNCTION transfer_requests_guard_update() RETURNS trigger
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
           AND NOT (OLD.status = 'pending_approval' AND NEW.status IN ('posted', 'rejected')) THEN
            RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'checker is only set when approving or rejecting';
        END IF;

        IF NEW.status = 'posted' THEN
            IF OLD.status = 'pending_approval' AND NEW.checker_id IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'posting a pending approval needs a checker';
            END IF;
            IF NEW.checker_id IS NULL AND NEW.amount > ledger_setting('approval_threshold_cents') THEN
                RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'amount above approval threshold needs a checker';
            END IF;
            IF (SELECT status FROM accounts WHERE id = NEW.from_account_id) <> 'active' THEN
                RAISE EXCEPTION USING ERRCODE = 'LG006', MESSAGE = 'source account is not active';
            END IF;
        END IF;

        NEW.decided_at := now();
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER transfer_requests_guard_update BEFORE UPDATE ON transfer_requests "
    "FOR EACH ROW EXECUTE FUNCTION transfer_requests_guard_update()",
    # A posted request must point at a transfer whose entries match it exactly.
    """
    CREATE FUNCTION transfer_requests_check_posted() RETURNS trigger
    LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
    BEGIN
        IF (SELECT kind FROM ledger_transactions WHERE id = NEW.ledger_transaction_id) <> 'transfer' THEN
            RAISE EXCEPTION USING ERRCODE = 'LG003',
                MESSAGE = format('request %s points at a non-transfer ledger transaction', NEW.id);
        END IF;
        PERFORM ledger_assert_transaction_valid(NEW.ledger_transaction_id);
        RETURN NULL;
    END $$
    """,
    """
    CREATE CONSTRAINT TRIGGER transfer_requests_check_posted AFTER INSERT OR UPDATE ON transfer_requests
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.status = 'posted')
        EXECUTE FUNCTION transfer_requests_check_posted()
    """,
]


def upgrade() -> None:
    # One statement per call: function bodies contain semicolons, and the driver
    # runs a single statement per execute.
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    for table in ("transfer_requests", "entries", "ledger_transactions", "ledger_settings", "accounts", "users"):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    for fn in (
        "transfer_requests_check_posted()", "transfer_requests_guard_update()", "transfer_requests_guard_insert()",
        "entries_check_funds()", "ledger_transactions_validate()", "entries_check_transaction()",
        "ledger_assert_transaction_valid(UUID)", "ledger_assert_reversal_valid(UUID)", "ledger_server_time()",
        "accounts_guard_update()", "reject_modification()", "ledger_available_balance(UUID)",
        "ledger_held_amount(UUID)", "ledger_posted_balance(UUID)", "ledger_setting(TEXT)",
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {fn}")
