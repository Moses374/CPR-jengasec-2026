"""Authentication, roles and ownership (Kathy). Design: docs/DECISIONS.md, Kathy Q1-Q4.

What other modules use:

    from app.auth import CurrentUser, current_user, require_role, scope_params

    @router.get("/accounts/{account_id}")
    def read_account(account_id: UUID, user: CurrentUser = Depends(require_role("customer", "teller")), ...):
        ...

    # Ownership is part of the SQL, never "fetch, then compare". scope_params gives the bind values for
    # this predicate, which you write as a literal in your query (SQL is never built from strings):
    #
    #   WHERE a.id = :id
    #     AND (:staff OR a.owner_id = :me)              -- customers see only their own
    #     AND (a.owner_id IS NOT NULL OR :system_ok)    -- system accounts: auditor and admin only
    #
    # No row means 404 for "missing" and "not yours" alike (T8).
    db.execute(text(...), {"id": account_id, **scope_params(user)})

Rules this module keeps:
- Default deny: every route except the public ones depends on current_user (tests/test_authz_coverage.py).
- The role comes from the database on every request, never from the token.
- Tokens are opaque; only their SHA-256 is stored. Unknown, expired, revoked and malformed tokens all
  give the same 401. Passwords and tokens are never logged.
"""

import hashlib
import secrets
import threading
import unicodedata
from dataclasses import dataclass
from uuid import UUID

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import audit_log, ratelimit
from app import observability
from app.db import get_db

ROLES = ("customer", "teller", "approver", "auditor", "admin")
STAFF_ROLES = ("teller", "approver", "auditor", "admin")
SYSTEM_ACCOUNT_ROLES = ("auditor", "admin")

SESSION_SECONDS = 30 * 60
MAX_ACTIVE_SESSIONS = 5
MAX_TOKEN_CHARS = 128
USERNAME_MAX = 32

# argon2id, OWASP minimum (docs/DECISIONS.md Q2). Memory is the constraint (3 GB, two workers),
# so only a few hashes run at once per worker; the rest wait briefly, then get 429.
_HASHER = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
_HASH_SLOTS = threading.BoundedSemaphore(4)
_HASH_WAIT_S = 5

_dummy_hash: str | None = None
_dummy_lock = threading.Lock()


def too_many(retry_after: int) -> HTTPException:
    return HTTPException(429, "too_many_requests", headers={"Retry-After": str(max(1, retry_after))})


def unauthenticated() -> HTTPException:
    return HTTPException(401, "unauthenticated", headers={"WWW-Authenticate": "Bearer"})


# ------------------------------------------------------------------------------ passwords
def hash_password(password: str) -> str:
    with _slot():
        return _HASHER.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """True only for a match. A malformed stored hash (such as the '!' default) is simply False."""
    with _slot():
        try:
            return _HASHER.verify(stored_hash, password)
        except (VerifyMismatchError, InvalidHashError, VerificationError):
            return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _HASHER.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return False


def verify_dummy(password: str) -> None:
    """Spend the same time as a real check, for unknown or inactive users (T5)."""
    global _dummy_hash
    if _dummy_hash is None:
        with _dummy_lock:
            if _dummy_hash is None:
                _dummy_hash = _HASHER.hash(secrets.token_urlsafe(16))
    verify_password(_dummy_hash, password)


class _slot:
    def __enter__(self):
        if not _HASH_SLOTS.acquire(timeout=_HASH_WAIT_S):
            raise too_many(5)

    def __exit__(self, *exc):
        _HASH_SLOTS.release()


# ---------------------------------------------------------------------------------- tokens
def new_token() -> tuple[str, bytes]:
    """(token to give the client once, digest to store)."""
    token = secrets.token_urlsafe(32)
    return token, token_digest(token)


def token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


def bearer_token(request: Request) -> str | None:
    """The token from 'Authorization: Bearer <token>', or None for anything else (never a URL or cookie)."""
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value or len(value) > MAX_TOKEN_CHARS or not value.isascii():
        return None
    if " " in value or not value.isprintable():
        return None
    return value


# --------------------------------------------------------------------------------- usernames
def normalise_username(raw: str) -> str:
    """Trim, fold width/compatibility forms and lowercase. 'Admin ' and 'admin' are the same name.

    Anything outside the allowed pattern later fails the lookup like an unknown user, so look-alike
    unicode never matches a real account (A17).
    """
    return unicodedata.normalize("NFKC", raw).strip().lower()[:64]


# ------------------------------------------------------------------------------ current user
@dataclass(frozen=True)
class CurrentUser:
    id: UUID
    username: str
    role: str
    session_id: UUID
    src_ip: str | None

    @property
    def is_staff(self) -> bool:
        return self.role in STAFF_ROLES


def client_ip(request: Request) -> str | None:
    # request.client.host only. X-Forwarded-For is not trusted until question O3 is answered.
    return request.client.host if request.client else None


def current_user(request: Request, db: Session = Depends(get_db)) -> CurrentUser:
    """Who is calling. 401 for no, bad, expired or revoked token; role and status are read now."""
    ip = client_ip(request) or "unknown"
    token = bearer_token(request)

    row = None
    if token is not None:
        row = db.execute(
            text(
                "SELECT s.id AS session_id, u.id AS user_id, u.username, u.role "
                "FROM sessions s JOIN users u ON u.id = s.user_id "
                "WHERE s.token_hash = :h AND s.revoked_at IS NULL AND s.expires_at > now() AND u.is_active"
            ),
            {"h": token_digest(token)},
        ).first()

    if row is None:
        allowed, retry = ratelimit.hit(f"anon:{ip}", ratelimit.ANON_PER_IP_PER_MIN)
        if not allowed:
            raise too_many(retry)
        if token is not None:
            observability.action("token.invalid")
        raise unauthenticated()

    user = CurrentUser(row.user_id, row.username, row.role, row.session_id, client_ip(request))
    observability.user(str(user.id))
    allowed, retry = ratelimit.hit(f"user:{user.id}", ratelimit.API_PER_USER_PER_MIN)
    if not allowed:
        raise too_many(retry)
    return user


def require_role(*roles: str):
    """Dependency factory: the caller must hold one of these roles, otherwise 403."""
    unknown = set(roles) - set(ROLES)
    if unknown or not roles:
        raise ValueError(f"require_role needs known roles, got {roles!r}")

    def dependency(user: CurrentUser = Depends(current_user)) -> CurrentUser:
        if user.role not in roles:
            audit_log.record(
                action="authz.denied", outcome="denied", user_id=str(user.id), role=user.role,
                src_ip=user.src_ip, details={"role_required": ",".join(roles)},
            )
            raise HTTPException(403, "forbidden")
        return user

    return dependency


# ------------------------------------------------------------------------------ ownership
def scope_params(user: CurrentUser) -> dict:
    """Bind values for the ownership predicate in the module docstring."""
    return {
        "me": str(user.id),
        "staff": user.is_staff,
        "system_ok": user.role in SYSTEM_ACCOUNT_ROLES,
    }


def not_found() -> HTTPException:
    """The one answer for 'does not exist' and 'not yours' (T8)."""
    return HTTPException(404, "not_found")
