from collections.abc import Iterator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import database_url


def make_engine(url: str) -> Engine:
    # Synchronous engine on purpose: money paths stay simple to reason about
    # (one request = one thread = one transaction).
    return create_engine(
        url,
        # Pinned, not left to the server default: the ledger's row locks rely on each
        # statement seeing what the previous lock holder committed (docs/DECISIONS.md, Q3).
        isolation_level="READ COMMITTED",
        pool_size=10,
        max_overflow=5,
        pool_timeout=5,  # a flood fails fast instead of queueing for 30 s
        pool_pre_ping=True,
    )


engine = make_engine(database_url())
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, rolled back unless the handler commits."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
