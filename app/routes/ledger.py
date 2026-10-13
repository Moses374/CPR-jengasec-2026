"""Accounts, transfers and approvals (Moses; approvals with Kathy). Money logic lives in app/ledger.py.

Roles are proposals until Kathy fixes the list: "customer" moves money from their own accounts,
"approver" decides pending transfers. Every route needs a logged-in caller (app/auth.py).
"""

import uuid

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import ledger
from app.auth import CurrentUser, current_user, require_role
from app.db import get_db

router = APIRouter(prefix="/api/v1")

MEMO_RE = r"^[^\x00-\x1f\x7f]{1,140}$"           # no control characters (no log or header injection)
IDEMPOTENCY_KEY_RE = r"^[A-Za-z0-9_-]{8,64}$"


class TransferIn(BaseModel):
    model_config = ConfigDict(extra="forbid")      # "balance", "status", "maker_id" ... are rejected

    from_account_id: uuid.UUID
    to_account_id: uuid.UUID
    amount: str = Field(pattern=ledger.AMOUNT_RE, max_length=13, examples=["1500.00"])
    memo: str | None = Field(default=None, pattern=MEMO_RE)


class ApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_amount: str = Field(pattern=ledger.AMOUNT_RE, max_length=13, examples=["150000.00"])


def _actor(user: CurrentUser, request: Request) -> ledger.Actor:
    return ledger.Actor(user_id=user.id, role=user.role, src_ip=request.client.host if request.client else None)


def _refusal(err: ledger.LedgerError) -> JSONResponse:
    ledger.mark(err)  # money paths already logged it; this names input and lookup refusals
    headers = {"Retry-After": "2"} if err.status == 503 else None
    return JSONResponse(status_code=err.status, content={"error": err.code}, headers=headers)


@router.get("/accounts")
def list_accounts(user: CurrentUser = Depends(require_role("customer")), db: Session = Depends(get_db)):
    return {"items": ledger.list_accounts(db, user.id)}


@router.post("/transfers", status_code=201)
def create_transfer(
    body: TransferIn,
    request: Request,
    idempotency_key: str = Header(pattern=IDEMPOTENCY_KEY_RE),
    user: CurrentUser = Depends(require_role("customer")),
    db: Session = Depends(get_db),
):
    # TODO(Adam #9): idempotency_key is required and validated but NOT yet enforced: a replay posts twice
    # until his table is checked here, first in the transaction. Limits and fraud also plug in here.
    try:
        result = ledger.create_transfer(
            db, _actor(user, request),
            from_account_id=body.from_account_id, to_account_id=body.to_account_id,
            amount_cents=ledger.to_cents(body.amount), memo=body.memo,
        )
    except ledger.LedgerError as err:
        return _refusal(err)
    if result.status == "blocked":
        return JSONResponse(status_code=403, content={"error": "declined"})   # generic: never the rule
    return JSONResponse(status_code=201 if result.status == "posted" else 202,
                        content={"id": result.id, "status": result.status})


@router.get("/transfers/{request_id}")
def get_transfer(request_id: uuid.UUID, user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    try:
        return ledger.get_request(db, request_id, user.id)
    except ledger.LedgerError as err:
        return _refusal(err)


@router.post("/approvals/{request_id}/approve")
def approve(
    request_id: uuid.UUID,
    body: ApproveIn,
    request: Request,
    user: CurrentUser = Depends(require_role("approver")),
    db: Session = Depends(get_db),
):
    try:
        result = ledger.approve(db, _actor(user, request), request_id=request_id,
                                expected_amount_cents=ledger.to_cents(body.expected_amount))
    except ledger.LedgerError as err:
        return _refusal(err)
    return {"id": result.id, "status": result.status}


@router.post("/approvals/{request_id}/reject")
def reject(
    request_id: uuid.UUID,
    request: Request,
    user: CurrentUser = Depends(require_role("approver")),
    db: Session = Depends(get_db),
):
    try:
        result = ledger.reject(db, _actor(user, request), request_id=request_id)
    except ledger.LedgerError as err:
        return _refusal(err)
    return {"id": result.id, "status": result.status}
