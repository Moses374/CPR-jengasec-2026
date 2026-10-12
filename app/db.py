from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import database_url

# Synchronous engine on purpose: money paths stay simple to reason about
# (one request = one thread = one transaction).
engine = create_engine(database_url(), pool_size=10, max_overflow=5, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, rolled back unless the handler commits."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
