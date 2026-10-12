"""Container entrypoint: migrate the database once, then start the web server."""

import logging
import time

import uvicorn
from alembic import command
from alembic.config import Config

from app import config
from app.observability import LOGGING, configure_logging

log = logging.getLogger("app.startup")


def migrate() -> None:
    # The database may still be starting when the app boots; retry for up to ~60 s.
    cfg = Config("alembic.ini")
    for attempt in range(1, 31):
        try:
            command.upgrade(cfg, "head")
            return
        except Exception as e:
            log.warning("migration attempt %d failed: %s", attempt, type(e).__name__)
            time.sleep(2)
    raise SystemExit("database unavailable, giving up")


if __name__ == "__main__":
    configure_logging()
    migrate()
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=config.PORT,
        workers=config.WORKERS,
        log_config=LOGGING,
        access_log=False,      # the contract line from RequestLogMiddleware replaces it
        server_header=False,
        date_header=False,
    )
