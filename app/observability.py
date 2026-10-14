"""JengaSec logging contract: one JSON line per request on stdout.

Fields: ts, src_ip, method, path, status, user, action.

Name the security outcome wherever it is decided:

    from app import observability as audit
    audit.user(user_id)                 # once authentication succeeds
    audit.action("transfer.denied")

Without an explicit action, a default is derived from the status code.
The query string is never logged, so tokens in URLs never reach the logs.
json.dumps escapes every value, so attacker-controlled text cannot break the line format.
"""

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime

security_log = logging.getLogger("security")

# Holds a mutable dict per request. Sync endpoints run in a worker thread with a *copy* of the
# context, so handlers mutate the shared dict rather than setting the ContextVar themselves.
_audit: ContextVar[dict | None] = ContextVar("audit", default=None)


def action(name: str) -> None:
    holder = _audit.get()
    if holder is not None:
        holder["action"] = name


def user(user_id: str) -> None:
    holder = _audit.get()
    if holder is not None:
        holder["user"] = user_id


def _default_action(path: str, status: int) -> str:
    if path in ("/healthz", "/readyz"):
        return "health.check"
    return {
        401: "auth.unauthenticated",
        403: "authz.denied",
        404: "http.not_found",
        405: "http.method_not_allowed",
        422: "input.rejected",
        429: "ratelimit.hit",
    }.get(status, "http.error" if status >= 500 else "input.rejected" if status >= 400 else "http.request")


class RequestLogMiddleware:
    """Pure ASGI middleware, registered last so it wraps every other middleware and route."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        holder: dict = {}
        token = _audit.set(holder)
        status = 500  # if the app raises before sending a response, the server returns 500

        async def send_wrapper(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            _audit.reset(token)
            client = scope.get("client")
            path = scope.get("path", "")
            security_log.info(json.dumps({
                "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "src_ip": client[0] if client else "",
                "method": scope.get("method", ""),
                "path": path,
                "status": status,
                "user": holder.get("user", ""),
                "action": holder.get("action") or _default_action(path, status),
            }, separators=(",", ":")))


MAX_BODY_BYTES = 16 * 1024  # largest legitimate request is a transfer: well under 1 KB


class BodySizeLimit:
    """Refuse request bodies over MAX_BODY_BYTES with 413 before any route reads them.

    Checks Content-Length first, then counts the bytes actually received, so a missing or
    lying Content-Length (chunked upload) cannot get a bigger body through.
    """

    def __init__(self, app, max_bytes: int = MAX_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def _refuse(self, send):
        action("input.rejected")
        body = b'{"error":"payload_too_large"}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > self.max_bytes
                except ValueError:
                    too_big = True
                if too_big:
                    await self._refuse(send)
                    return

        # Read the whole body up front (it is small by now) and replay it to the app.
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            size += len(message.get("body", b""))
            if size > self.max_bytes:
                await self._refuse(send)
                return
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


class JsonFormatter(logging.Formatter):
    """Every non-contract log line is JSON too, so stdout stays one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, separators=(",", ":"))


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "raw": {"format": "%(message)s"},
        "json": {"()": "app.observability.JsonFormatter"},
    },
    "handlers": {
        "security": {"class": "logging.StreamHandler", "formatter": "raw", "stream": "ext://sys.stdout"},
        "app": {"class": "logging.StreamHandler", "formatter": "json", "stream": "ext://sys.stdout"},
    },
    "loggers": {
        "security": {"handlers": ["security"], "level": "INFO", "propagate": False},
        "uvicorn": {"handlers": ["app"], "level": "INFO", "propagate": False},
        "uvicorn.error": {"handlers": ["app"], "level": "INFO", "propagate": False},
        "uvicorn.access": {"handlers": [], "level": "WARNING", "propagate": False},
        "alembic": {"handlers": ["app"], "level": "INFO", "propagate": False},
        # Our own operational lines (db.least_privilege=on, auditlog.anchor, recon results) are INFO and
        # must reach the platform logs; without this they fell under root's WARNING and were dropped.
        "app": {"level": "INFO"},   # no handler of its own: propagates to root's handler (no duplicates)
    },
    "root": {"handlers": ["app"], "level": "WARNING"},
}


def configure_logging() -> None:
    import logging.config

    logging.config.dictConfig(LOGGING)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
