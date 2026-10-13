"""Helpers shared by the database tests."""

from sqlalchemy import text

NO_NEW_OPENINGS = "ledger_transactions_no_new_openings"   # trigger created at the end of the seed (0006)

_DISABLE = text(f"ALTER TABLE ledger_transactions DISABLE TRIGGER {NO_NEW_OPENINGS}")
_ENABLE = text(f"ALTER TABLE ledger_transactions ENABLE TRIGGER {NO_NEW_OPENINGS}")


def fund(conn, funding_account, account, cents: int):
    """Give `account` an opening balance of `cents` from `funding_account` and return the transaction id.

    In production, opening balances only come from the seed migration: after it, a trigger refuses every
    new opening. Tests fund their own accounts, so this lifts that one trigger for this one opening in the
    caller's transaction, runs the ledger's checks on it at once (it must balance, and only a system
    account may be debited), and switches the trigger straight back on. Postgres refuses to re-enable a
    trigger while checks are still queued, which is why the checks run immediately here.
    """
    conn.execute(_DISABLE)
    txn = conn.execute(text("INSERT INTO ledger_transactions (kind) VALUES ('opening') RETURNING id")).scalar_one()
    conn.execute(text("INSERT INTO entries (transaction_id, account_id, amount) VALUES (:t, :f, :n), (:t, :a, :c)"),
                 {"t": txn, "f": funding_account, "a": account, "n": -cents, "c": cents})
    conn.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
    conn.execute(_ENABLE)
    conn.execute(text("SET CONSTRAINTS ALL DEFERRED"))
    return txn


def raw_opening(conn, created_at: str | None = None):
    """An 'opening' transaction with no entries yet, for tests that check the ledger refuses a bad one.
    Only for tests that end in a rollback: the rollback also switches the lock back on
    (the conn fixture in test_ledger_schema.py checks lock_is_on() after every test)."""
    conn.execute(_DISABLE)
    if created_at is None:
        return conn.execute(text("INSERT INTO ledger_transactions (kind) VALUES ('opening') RETURNING id")).scalar_one()
    return conn.execute(text("INSERT INTO ledger_transactions (kind, created_at) VALUES ('opening', :c) RETURNING id"),
                        {"c": created_at}).scalar_one()


def lock_is_on(conn) -> bool:
    return conn.execute(text("SELECT tgenabled = 'O' FROM pg_trigger WHERE tgname = :n"),
                        {"n": NO_NEW_OPENINGS}).scalar_one()
