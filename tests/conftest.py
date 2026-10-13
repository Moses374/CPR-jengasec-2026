"""Shared fixtures. Database tests run against a real PostgreSQL:

    docker compose up -d db
    .venv/Scripts/python -m pytest

Each session creates a fresh database, runs every migration on it, and drops it at the end.
Without a reachable database the db tests are skipped locally, but fail when REQUIRE_DB=1 (CI).
"""

import os
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parent.parent
SERVER_URL = os.environ.get("TEST_DATABASE_URL", "postgresql+psycopg://payments:payments@localhost:5432/payments")


def pytest_configure(config):
    config.addinivalue_line("markers", "db: needs a real PostgreSQL (docker compose up -d db)")


@pytest.fixture(scope="session")
def db_url():
    server = create_engine(SERVER_URL, isolation_level="AUTOCOMMIT")
    try:
        with server.connect():
            pass
    except Exception as e:
        server.dispose()
        if os.environ.get("REQUIRE_DB") == "1":
            pytest.fail(f"REQUIRE_DB=1 but PostgreSQL is unreachable: {type(e).__name__}")
        pytest.skip("PostgreSQL not reachable; run: docker compose up -d db")

    name = f"ledger_test_{uuid.uuid4().hex[:12]}"  # generated here, never from input
    with server.connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(SERVER_URL).set(database=name).render_as_string(hide_password=False)

    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url
    try:
        command.upgrade(cfg, "head")
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous

    yield url

    with server.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    server.dispose()


@pytest.fixture(scope="session")
def db_engine(db_url):
    # Same isolation as the app, but enough connections for the parallel tests (one per thread).
    engine = create_engine(db_url, isolation_level="READ COMMITTED", pool_size=60, max_overflow=0)
    yield engine
    engine.dispose()
