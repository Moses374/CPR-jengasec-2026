"""Seed data (made-up only): customers, staff, accounts and opening balances.

Design: docs/DECISIONS.md, Moses Q5. Generated once by a local script: every id is a random UUID,
every password random; only argon2 hashes (app.auth settings) are here. Plaintext passwords were
written to a file outside the repository and belong in the team password manager.

Opening balances come from the system account 'JengaBank Funding' (the only source of new money),
so the ledger balances from the first entry. One audit row (seed.loaded) records what was issued.

Revision ID: 0006
Revises: 0005
"""
from alembic import op
from sqlalchemy import text

from app import audit_log

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

FUNDING = "7b90168c-3837-49a9-bc44-d9866c425b89"

# (id, username, role, argon2 hash)
USERS = [
    ("8eb29b54-6234-48e9-89da-5971865dccc0", "amina.wekesa", "customer", "$argon2id$v=19$m=19456,t=2,p=1$gJTxaMGnlJWYZ5HwNspgbg$4DbuandN4xhyOXg4k0WEj54iPmqYG5wUYG+19EDlXJk"),
    ("18424fda-52a8-4c5f-b363-d942df49be20", "brian.otieno", "customer", "$argon2id$v=19$m=19456,t=2,p=1$46fuwn4mIUTPcQF5ldppvg$CqYIR8UZa2Bri4OuAbL0IjvoH566MkFiJ+mCl/KJG3w"),
    ("f953872f-226b-4591-ad59-965fb5c16de0", "cynthia.mwangi", "customer", "$argon2id$v=19$m=19456,t=2,p=1$ScYJMrG+ZdyDKl7O+Pog9g$W+IlcZrk1y82kUuhcM7mjOpk9LkpuG7RwVL1j5xi9cA"),
    ("264e119f-3cef-47ee-96cd-9db9b738aca5", "david.kiprop", "customer", "$argon2id$v=19$m=19456,t=2,p=1$qosukHGIS0RJLPPBhdXFMg$SEYRVnFf97okyiKZHQwBZbUEkMraiPxEmIfRkBsXj3o"),
    ("5c41b970-67c2-4289-af8b-24bfc359df30", "esther.njeri", "customer", "$argon2id$v=19$m=19456,t=2,p=1$CkRRgQ5KtUdPFyWDBWgOcg$1tqyS+2Cpzuc6iZE8PEni+c7vmimB1y6hic+LYuKVYI"),
    ("08896c6c-3f88-4493-81d8-d5409782f9ee", "teller.achieng", "teller", "$argon2id$v=19$m=19456,t=2,p=1$WP57tlRt+oO0MDCTzavStQ$Ad7s8NePLvXzmBG8Y6PcPTH//TQKHMBV0Q32oq7b2DE"),
    ("aad06ebe-0cd0-4345-84d3-07c77b7921de", "approver.mutua", "approver", "$argon2id$v=19$m=19456,t=2,p=1$gEKtd9ce9rgmWsmdA6nU6Q$721sT7VBpsZFQ7mUFeDNnqRHc0QHoJBQj+/pdvXiP7s"),
    ("61e71e8b-0df9-4cf7-8202-a1c345ae1979", "approver.chebet", "approver", "$argon2id$v=19$m=19456,t=2,p=1$F6/F3VqMrxFD1EEoyEOMkQ$te23FDNYqa+vRuk35cUNA7mG9dHu6OFa81u7a1g9kcE"),
    ("35685b9e-b0ae-41d7-a857-9f30504c3b7f", "auditor.kamau", "auditor", "$argon2id$v=19$m=19456,t=2,p=1$SD+T6x8CxaOzTtScarr0pg$b+V4cE+2FPqJ5mC2QOQ/Az61Tuao0eEu4VcBg+VMVpQ"),
    ("c71fda61-f7dc-426f-b486-6e8500a4ded6", "admin.nyambura", "admin", "$argon2id$v=19$m=19456,t=2,p=1$Kfor41VVIzs4JD9kX9eXCQ$hYkCwERHk9VkXGQGx/Pu6BWQHYdAXXbNmAl28xlU99w"),
]

# (id, owner id, name, opening balance in cents, status, age in days)
ACCOUNTS = [
    ("b774fc96-8669-4524-b83e-3491852471c5", "8eb29b54-6234-48e9-89da-5971865dccc0", "Current", 250000000, "active", 400),
    ("012e6e0f-c6d1-4df0-88fd-cf259bb69daa", "8eb29b54-6234-48e9-89da-5971865dccc0", "Savings", 80000000, "active", 400),
    ("ea157aef-7f16-453d-bb4e-53eb277131d3", "18424fda-52a8-4c5f-b363-d942df49be20", "Current", 15000000, "active", 200),
    ("7078989a-f929-4142-a3ef-de65f419e663", "f953872f-226b-4591-ad59-965fb5c16de0", "Current", 500000, "active", 90),
    ("9b019e62-3869-4f99-b583-d53d76f79eaa", "264e119f-3cef-47ee-96cd-9db9b738aca5", "Current", 0, "active", 0),
    ("1c79a2fa-7f82-484a-8dca-3f3a53b1979b", "5c41b970-67c2-4289-af8b-24bfc359df30", "Current", 2000000, "frozen", 300),
]


def upgrade() -> None:
    db = op.get_bind()
    for uid, username, role, password_hash in USERS:
        db.execute(text("INSERT INTO users (id, username, role, password_hash) VALUES (:i, :u, :r, :h)"),
                   {"i": uid, "u": username, "r": role, "h": password_hash})
    db.execute(text("INSERT INTO accounts (id, kind, name, min_balance) "
                    "VALUES (:i, 'system', 'JengaBank Funding', -1000000000000000)"), {"i": FUNDING})
    issued = 0
    for acct, owner, name, cents, status, age in ACCOUNTS:
        db.execute(text("INSERT INTO accounts (id, owner_id, kind, name, created_at) "
                        "VALUES (:i, :o, 'customer', :n, now() - make_interval(days => :d))"),
                   {"i": acct, "o": owner, "n": name, "d": age})
        if cents:
            txn = db.execute(text("INSERT INTO ledger_transactions (kind, memo) VALUES ('opening', 'Opening balance') "
                                  "RETURNING id")).scalar_one()
            db.execute(text("INSERT INTO entries (transaction_id, account_id, amount) VALUES (:t, :f, :neg), (:t, :a, :pos)"),
                       {"t": txn, "f": FUNDING, "a": acct, "neg": -cents, "pos": cents})
            issued += cents
    db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))   # the ledger's own checks run on the seed
    for acct, _owner, _name, _cents, status, _age in ACCOUNTS:
        if status != 'active':
            db.execute(text("UPDATE accounts SET status = :s WHERE id = :i"), {"s": status, "i": acct})
    audit_log.append(db, action="seed.loaded", outcome="ok", object_type="seed", object_id="0006",
                     details={"count": len(ACCOUNTS), "amount_cents": issued})
    # From now on, no new money can be issued: opening balances exist only from this migration.
    db.execute(text("""
        CREATE FUNCTION ledger_no_new_openings() RETURNS trigger
        LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
        BEGIN
            RAISE EXCEPTION USING ERRCODE = 'LG006',
                MESSAGE = 'opening balances are created only by the seed migration';
        END $$
    """))
    db.execute(text("CREATE TRIGGER ledger_transactions_no_new_openings BEFORE INSERT ON ledger_transactions "
                    "FOR EACH ROW WHEN (NEW.kind = 'opening') EXECUTE FUNCTION ledger_no_new_openings()"))


def downgrade() -> None:
    raise RuntimeError("seed data is part of an append-only ledger; restore a fresh database instead")
