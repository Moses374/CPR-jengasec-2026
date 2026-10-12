import os


def database_url() -> str:
    """SQLAlchemy URL for PostgreSQL.

    Uses DATABASE_URL if set, otherwise the standard PG* variables.
    TODO: confirm which variables JengaSec injects for its PostgreSQL 16 (Image Submission Guide).
    """
    url = os.environ.get("DATABASE_URL")
    if url:
        for prefix in ("postgres://", "postgresql://"):
            if url.startswith(prefix):
                return "postgresql+psycopg://" + url[len(prefix):]
        return url

    host = os.environ.get("PGHOST", "localhost")
    port = os.environ.get("PGPORT", "5432")
    user = os.environ.get("PGUSER", "payments")
    password = os.environ.get("PGPASSWORD", "payments")
    name = os.environ.get("PGDATABASE", "payments")
    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{name}"


PORT = int(os.environ.get("PORT", "8080"))
WORKERS = int(os.environ.get("WEB_CONCURRENCY", "2"))
