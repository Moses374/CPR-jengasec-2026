"""POST /api/v1/auth/login, POST /api/v1/auth/logout, GET /api/v1/me (docs/DECISIONS.md, Kathy Q2 and Q4).

Login order matters:
1. per-IP throttle, 2. lockout check (before the password, so a correct guess while locked reveals
nothing), 3. password check that costs the same for unknown, inactive and wrong, 4. one generic 401.
"""

import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app import audit_log, auth, ratelimit
from app import observability
from app.db import get_db

router = APIRouter(prefix="/api/v1")

_USERNAME_RE = re.compile(r"[a-z0-9._-]{3,32}")  # same pattern as the CHECK on users.username


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(max_length=128)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class MeResponse(BaseModel):
    user_id: UUID
    username: str
    role: str


def _invalid_credentials() -> HTTPException:
    return HTTPException(401, "invalid_credentials")


@router.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> LoginResponse:
    ip = auth.client_ip(request) or "unknown"
    name = auth.normalise_username(body.username)
    key = ratelimit.username_key(name)

    allowed, retry = ratelimit.hit(f"login-ip:{ip}", ratelimit.LOGIN_PER_IP_PER_MIN)
    if not allowed:
        raise auth.too_many(retry)

    wait = ratelimit.login_lock_remaining(key, ip)
    if wait > 0:
        audit_log.record(
            action="login.locked", outcome="denied", src_ip=ip,
            details={"username_hash": key, "retry_after_s": wait},
        )
        raise auth.too_many(wait)

    user = None
    if _USERNAME_RE.fullmatch(name):
        user = db.execute(
            text("SELECT id, username, role, password_hash, is_active FROM users WHERE username = :u"),
            {"u": name},
        ).first()

    if user is not None and user.is_active:
        ok = auth.verify_password(user.password_hash, body.password)
    else:
        auth.verify_dummy(body.password)  # same cost as a real check (T5)
        ok = False

    if not ok:
        ratelimit.record_failed_login(key, ip)
        audit_log.record(action="login.failed", outcome="denied", src_ip=ip, details={"username_hash": key})
        if ratelimit.login_lock_remaining(key, ip) > 0:
            audit_log.record(action="login.locked", outcome="denied", src_ip=ip, details={"username_hash": key})
        raise _invalid_credentials()

    if auth.needs_rehash(user.password_hash):
        # Best effort: the runtime database role may not update password hashes (app/db_roles.py). A savepoint
        # keeps a refusal from aborting the login; the old hash still verifies.
        try:
            with db.begin_nested():
                db.execute(
                    text("UPDATE users SET password_hash = :h WHERE id = :id"),
                    {"h": auth.hash_password(body.password), "id": user.id},
                )
        except DBAPIError:
            pass

    # At most MAX_ACTIVE_SESSIONS live sessions per user: revoke the oldest beyond the limit.
    db.execute(
        text(
            "UPDATE sessions SET revoked_at = now() WHERE id IN ("
            "  SELECT id FROM sessions WHERE user_id = :u AND revoked_at IS NULL AND expires_at > now() "
            "  ORDER BY created_at DESC OFFSET :keep)"
        ),
        {"u": user.id, "keep": auth.MAX_ACTIVE_SESSIONS - 1},
    )
    token, digest = auth.new_token()
    db.execute(
        text(
            "INSERT INTO sessions (user_id, token_hash, expires_at) "
            "VALUES (:u, :h, now() + make_interval(secs => :ttl))"
        ),
        {"u": user.id, "h": digest, "ttl": auth.SESSION_SECONDS},
    )
    # Housekeeping: sessions that ended more than a day ago.
    db.execute(
        text("DELETE FROM sessions WHERE expires_at < now() - interval '1 day' "
             "OR revoked_at < now() - interval '1 day'")
    )
    ratelimit.record_login_attempt(db, key, ip, True)
    observability.user(str(user.id))
    audit_log.append(
        db, action="login.ok", outcome="ok", user_id=str(user.id), role=user.role, src_ip=ip,
        object_type="user", object_id=str(user.id),
    )  # last statement before commit: no audit row, no login
    db.commit()
    return LoginResponse(access_token=token, expires_in=auth.SESSION_SECONDS)


@router.post("/auth/logout", status_code=204)
def logout(user: auth.CurrentUser = Depends(auth.current_user), db: Session = Depends(get_db)) -> Response:
    db.execute(text("UPDATE sessions SET revoked_at = now() WHERE id = :s AND revoked_at IS NULL"), {"s": user.session_id})
    audit_log.append(
        db, action="login.logout", outcome="ok", user_id=str(user.id), role=user.role, src_ip=user.src_ip,
        object_type="session", object_id=str(user.session_id),
    )
    db.commit()
    return Response(status_code=204)


@router.get("/me", response_model=MeResponse)
def me(user: auth.CurrentUser = Depends(auth.current_user)) -> MeResponse:
    return MeResponse(user_id=user.id, username=user.username, role=user.role)
