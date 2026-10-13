"""Container entrypoint: migrate the database once, then start the web server."""

import logging
import time

import uvicorn
from alembic import command
from alembic.config import Config

from app import config
from app.observability import LOGGING, configure_logging

log = logging.getLogger("app.startup")

# Shared with tests/test_attack_ledger.py so the tests exercise the production settings.
SERVER_OPTIONS = {
    "log_config": LOGGING,
    "access_log": False,      # the contract line from RequestLogMiddleware replaces it
    "server_header": False,
    "date_header": False,
    # Trust no X-Forwarded-For / Forwarded header: src_ip is the direct peer and cannot be forged.
    # Revisit once the organisers say what sits in front of us (DECISIONS Q6, question O3).
    "proxy_headers": False,
}


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


def check_controls() -> None:
    """Startup check (DECISIONS Q1): every ledger and audit-log trigger exists and is enabled.
    A problem is logged loudly and recorded, but never stops the app: refusing to start is an outage too."""
    from app import audit_log, recon
    from app.db import SessionLocal

    try:
        with SessionLocal() as session:
            problems = recon.check_ledger_controls(session) + audit_log.check_controls(session)
    except Exception as e:
        log.error("controls check failed: %s", type(e).__name__)
        return
    if problems:
        log.critical("ledger.controls_disabled problems=%s", "; ".join(problems))
        audit_log.record(action="ledger.controls_disabled", outcome="error", details={"checks": problems})


if __name__ == "__main__":
    configure_logging()
    migrate()
    check_controls()
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=config.PORT,
        workers=config.WORKERS,
        **SERVER_OPTIONS,
    )
