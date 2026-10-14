"""Seed history (made-up): 28 posted transfers over the 14 days before the migration runs.

Why: the fraud rules compare a transfer with the sender's history ("5x the usual amount", "new payee").
With no history, every first transfer looks unusual. Here Amina usually pays Brian about KSh 10,000 to
13,000, so a sudden KSh 60,000+ payment from her is held for review, as it should be.

Every transfer takes the full path (request, ledger transaction, two entries, audit row), so the ledger's
own triggers check the history and reconciliation finds an audit row for each one. To backdate them, the
"server sets the time" triggers are switched off for this migration only; every ledger check runs before
they are switched back on (Postgres will not re-enable a trigger while checks are queued).

Revision ID: 0007
Revises: 0006
"""
from alembic import op
from sqlalchemy import text

from app import audit_log

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

TIME_TRIGGERS = ("entries_server_time", "ledger_transactions_server_time", "transfer_requests_server_time")
TABLE_OF = {"entries_server_time": "entries", "ledger_transactions_server_time": "ledger_transactions",
            "transfer_requests_server_time": "transfer_requests"}

# (from user, from account, to user, to account, KSh, days ago, hour of day)
HISTORY = [
    ("amina.wekesa", "Current", "brian.otieno", "Current", 12_500, 13, 9),
    ("brian.otieno", "Current", "cynthia.mwangi", "Current", 2_000, 13, 14),
    ("amina.wekesa", "Current", "amina.wekesa", "Savings", 50_000, 12, 10),
    ("cynthia.mwangi", "Current", "brian.otieno", "Current", 800, 12, 17),
    ("brian.otieno", "Current", "amina.wekesa", "Current", 4_500, 11, 11),
    ("amina.wekesa", "Current", "cynthia.mwangi", "Current", 3_000, 10, 9),
    ("brian.otieno", "Current", "cynthia.mwangi", "Current", 1_500, 10, 16),
    ("amina.wekesa", "Current", "brian.otieno", "Current", 9_800, 9, 10),
    ("cynthia.mwangi", "Current", "amina.wekesa", "Current", 1_200, 9, 13),
    ("amina.wekesa", "Savings", "amina.wekesa", "Current", 20_000, 8, 8),
    ("brian.otieno", "Current", "esther.njeri", "Current", 2_500, 8, 15),
    ("amina.wekesa", "Current", "brian.otieno", "Current", 11_000, 7, 9),
    ("cynthia.mwangi", "Current", "brian.otieno", "Current", 600, 7, 18),
    ("brian.otieno", "Current", "cynthia.mwangi", "Current", 2_200, 6, 12),
    ("amina.wekesa", "Current", "cynthia.mwangi", "Current", 2_500, 6, 15),
    ("amina.wekesa", "Current", "brian.otieno", "Current", 13_200, 5, 10),
    ("brian.otieno", "Current", "amina.wekesa", "Current", 3_800, 5, 16),
    ("cynthia.mwangi", "Current", "brian.otieno", "Current", 900, 4, 11),
    ("amina.wekesa", "Current", "amina.wekesa", "Savings", 40_000, 4, 14),
    ("brian.otieno", "Current", "cynthia.mwangi", "Current", 1_800, 3, 9),
    ("amina.wekesa", "Current", "brian.otieno", "Current", 10_500, 3, 13),
    ("cynthia.mwangi", "Current", "amina.wekesa", "Current", 700, 2, 10),
    ("brian.otieno", "Current", "esther.njeri", "Current", 1_000, 2, 12),
    ("amina.wekesa", "Current", "cynthia.mwangi", "Current", 2_800, 2, 17),
    ("amina.wekesa", "Current", "brian.otieno", "Current", 12_000, 1, 9),
    ("brian.otieno", "Current", "cynthia.mwangi", "Current", 2_100, 1, 11),
    ("cynthia.mwangi", "Current", "brian.otieno", "Current", 1_100, 1, 15),
    ("amina.wekesa", "Current", "brian.otieno", "Current", 9_500, 1, 16),
]


def _account(db, username: str, name: str):
    return db.execute(text(
        "SELECT a.id, u.id AS owner FROM accounts a JOIN users u ON u.id = a.owner_id "
        "WHERE u.username = :u AND a.name = :n AND a.kind = 'customer'"
    ), {"u": username, "n": name}).one()


def upgrade() -> None:
    db = op.get_bind()
    # Alembic runs every pending migration in one transaction, and 0006 ends with its ledger checks set
    # to IMMEDIATE. Put them back to DEFERRED (their declared mode) so a transaction row can be inserted
    # before its entries. Any later migration that writes ledger rows should do the same.
    db.execute(text("SET CONSTRAINTS ALL DEFERRED"))
    for trigger in TIME_TRIGGERS:
        db.execute(text(f"ALTER TABLE {TABLE_OF[trigger]} DISABLE TRIGGER {trigger}"))  # constant names only

    posted = []
    for from_user, from_name, to_user, to_name, ksh, days_ago, hour in HISTORY:
        src, dst = _account(db, from_user, from_name), _account(db, to_user, to_name)
        cents = ksh * 100
        when = {"d": days_ago, "h": hour}
        at = "date_trunc('day', now()) - make_interval(days => :d) + make_interval(hours => :h)"
        txn = db.execute(text(
            f"INSERT INTO ledger_transactions (kind, created_by, created_at) VALUES ('transfer', :u, {at}) RETURNING id"
        ), {"u": src.owner, **when}).scalar_one()
        db.execute(text(
            f"INSERT INTO entries (transaction_id, account_id, amount, created_at) "
            f"VALUES (:t, :s, :neg, {at}), (:t, :r, :pos, {at})"
        ), {"t": txn, "s": src.id, "r": dst.id, "neg": -cents, "pos": cents, **when})
        req = db.execute(text(
            f"INSERT INTO transfer_requests (maker_id, from_account_id, to_account_id, amount, status, "
            f"ledger_transaction_id, created_at) VALUES (:m, :s, :r, :a, 'posted', :t, {at}) RETURNING id"
        ), {"m": src.owner, "s": src.id, "r": dst.id, "a": cents, "t": txn, **when}).scalar_one()
        posted.append((req, txn, src, dst, cents))

    db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))   # every ledger check runs on the history now
    for trigger in TIME_TRIGGERS:
        db.execute(text(f"ALTER TABLE {TABLE_OF[trigger]} ENABLE TRIGGER {trigger}"))
    db.execute(text("SET CONSTRAINTS ALL DEFERRED"))

    # One audit row per transfer, as the app writes them, so reconciliation sees every one covered.
    for req, txn, src, dst, cents in posted:
        audit_log.append(db, action="transfer.created", outcome="ok", user_id=src.owner, role="customer",
                         object_type="transfer_request", object_id=req,
                         details={"amount_cents": cents, "from_account_id": src.id, "to_account_id": dst.id,
                                  "ledger_transaction_id": txn, "kind": "seed_history"})


def downgrade() -> None:
    raise RuntimeError("seed history is part of an append-only ledger; restore a fresh database instead")
