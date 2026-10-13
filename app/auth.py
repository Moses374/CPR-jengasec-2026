"""Authentication and roles: Kathy (#6). PLACEHOLDER, fails closed.

This file only fixes the interface the routes depend on, so the ledger endpoints can be built and
tested before login exists. Until Kathy replaces the body of current_user(), every protected route
answers 401 to everyone. Keep these names and signatures when replacing it:

    CurrentUser          who is calling: id (users.id), role
    current_user()       FastAPI dependency: the authenticated caller, or 401
    require_role(*roles) dependency factory: the caller if their role is allowed, otherwise 403
"""

import uuid
from dataclasses import dataclass

from fastapi import Depends, HTTPException


@dataclass(frozen=True)
class CurrentUser:
    id: uuid.UUID
    role: str


def current_user() -> CurrentUser:
    # Kathy: verify the bearer token, load the user and role from the database, call audit.user(id).
    raise HTTPException(status_code=401, detail="unauthenticated", headers={"WWW-Authenticate": "Bearer"})


def require_role(*roles: str):
    def check(user: CurrentUser = Depends(current_user)) -> CurrentUser:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="forbidden")
        return user

    return check
