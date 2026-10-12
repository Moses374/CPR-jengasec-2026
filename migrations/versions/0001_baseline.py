"""Baseline. Add the team's schema as 0002_..., 0003_... (never edit a migration once pushed).

Seed data (made-up only) also goes in migrations so a fresh database is complete on first start.

Revision ID: 0001
Revises:
"""
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS app_metadata (
            key   VARCHAR(64) PRIMARY KEY,
            value VARCHAR(256) NOT NULL
        )
    """)
    op.execute("INSERT INTO app_metadata (key, value) VALUES ('service', 'APP04 payments') ON CONFLICT DO NOTHING")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS app_metadata")
