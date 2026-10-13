"""Accounts, transfers, approvals, reversals and reconciliation (Moses; approvals with Kathy, controls
designed by Adam). Money logic lives in app/ledger.py, reconciliation in app/recon.py.

Roles are proposals until Kathy fixes the list: "customer" moves money from their own accounts,
"approver" decides pending transfers, held reviews and reversals, "teller" requests reversals,
"admin" starts reconciliation, "auditor" and "admin" read it. Every route needs a logged-in caller
(app/auth.py).
"""

import datetime
import uuid

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session, sessionmaker

from app import audit_log, ledger, recon
from app.auth import CurrentUser, current_user, require_role
from app.controls import IDEMPOTENCY_KEY_RE
from app.db import get_db

router = APIRouter(prefix="/api/v1")

MEMO_RE = r"^[^\x00-\x1f\x7f]{1,140}$"           # no control characters (no log or header injection)
REASON_RE = r"^[^\x00-\x1f\x7f]{1,200}$"


class TransferIn(BaseModel):
    model_config = ConfigDict(extra="forbid")      # "balance", "status", "maker_id" ... are rejected

    from_account_id: uuid.UUID
    to_account_id: uuid.UUID
    amount: str = Field(pattern=ledger.AMOUNT_RE, max_length=13, examples=["1500.00"])
    memo: str | None = Field(default=None, pattern=MEMO_RE)


class ApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_amount: str = Field(pattern=ledger.AMOUNT_RE, max_length=13, examples=["150000.00"])


class ReversalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")      # no amount or accounts: they come from the original

    reason: str = Field(pattern=REASON_RE)


class ReconIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    business_date: datetime.date


def _actor(user: CurrentUser, request: Request) -> ledger.Actor:
    return ledger.Actor(user_id=user.id, role=user.role, src_ip=request.client.host if request.client else None)


def _refusal(err: ledger.LedgerError) -> JSONResponse:
    ledger.mark(err)  # money paths already logged it; this names input and lookup refusals
    headers = {"Retry-After": "2"} if err.status == 503 else None
    return JSONResponse(status_code=err.status, content={"error": err.code}, headers=headers)


def _transfer_response(result: ledger.TransferResult) -> JSONResponse:
    # A replay returns exactly what the first request got.
    if result.status == "blocked":
        return JSONResponse(status_code=403, content={"error": "declined"})   # generic: never the rule
    return JSONResponse(status_code=201 if result.status == "posted" else 202,
                        content={"id": result.id, "status": result.status})


# ---------------------------------------------------------------- customers

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
    try:
        result = ledger.create_transfer(
            db, _actor(user, request),
            from_account_id=body.from_account_id, to_account_id=body.to_account_id,
            amount_cents=ledger.to_cents(body.amount), memo=body.memo,
            idempotency=ledger.Idempotency.from_request(idempotency_key, body.model_dump(mode="json")),
        )
    except ledger.LedgerError as err:
        return _refusal(err)
    return _transfer_response(result)


@router.get("/transfers/{request_id}")
def get_transfer(request_id: uuid.UUID, user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    try:
        return ledger.get_request(db, request_id, user.id)
    except ledger.LedgerError as err:
        return _refusal(err)


# ---------------------------------------------------------------- approvals (maker-checker, held reviews)

@router.get("/approvals")
def approvals_queue(user: CurrentUser = Depends(require_role("approver")), db: Session = Depends(get_db)):
    return {"items": ledger.list_approvals(db, user.id)}


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


# ---------------------------------------------------------------- reversals (teller requests, approver approves)

@router.post("/transfers/{request_id}/reversals", status_code=202)
def request_reversal(
    request_id: uuid.UUID,
    body: ReversalIn,
    request: Request,
    idempotency_key: str = Header(pattern=IDEMPOTENCY_KEY_RE),
    user: CurrentUser = Depends(require_role("teller")),
    db: Session = Depends(get_db),
):
    try:
        result = ledger.request_reversal(
            db, _actor(user, request), transfer_request_id=request_id, reason=body.reason,
            idempotency=ledger.Idempotency.from_request(
                idempotency_key, {"transfer_request_id": str(request_id), **body.model_dump(mode="json")}),
        )
    except ledger.LedgerError as err:
        return _refusal(err)
    return JSONResponse(status_code=202, content={"id": result.id, "status": result.status})


@router.post("/reversals/{reversal_id}/approve")
def approve_reversal(
    reversal_id: uuid.UUID,
    body: ApproveIn,
    request: Request,
    user: CurrentUser = Depends(require_role("approver")),
    db: Session = Depends(get_db),
):
    try:
        result = ledger.approve_reversal(db, _actor(user, request), reversal_id=reversal_id,
                                         expected_amount_cents=ledger.to_cents(body.expected_amount))
    except ledger.LedgerError as err:
        return _refusal(err)
    return {"id": result.id, "status": result.status}


@router.post("/reversals/{reversal_id}/reject")
def reject_reversal(
    reversal_id: uuid.UUID,
    request: Request,
    user: CurrentUser = Depends(require_role("approver")),
    db: Session = Depends(get_db),
):
    try:
        result = ledger.reject_reversal(db, _actor(user, request), reversal_id=reversal_id)
    except ledger.LedgerError as err:
        return _refusal(err)
    return {"id": result.id, "status": result.status}


# ---------------------------------------------------------------- reconciliation

@router.post("/reconciliation/runs", status_code=201)
def start_reconciliation(
    body: ReconIn,
    request: Request,
    user: CurrentUser = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    src_ip = request.client.host if request.client else None
    try:
        return JSONResponse(status_code=201, content=recon.run(
            db, started_by=user.id, business_date=body.business_date, src_ip=src_ip, role=user.role))
    except recon.ReconBusy:
        audit_log.record(session_factory=sessionmaker(bind=db.get_bind()), action="recon.started",
                         outcome="denied", user_id=user.id, role=user.role, src_ip=src_ip,
                         details={"reason": "recon_running"})
        return JSONResponse(status_code=409, content={"error": "recon_running"})


@router.get("/reconciliation/runs")
def list_reconciliation_runs(user: CurrentUser = Depends(require_role("auditor", "admin")),
                             db: Session = Depends(get_db)):
    return {"items": recon.list_runs(db)}


@router.get("/reconciliation/runs/{run_id}")
def get_reconciliation_run(run_id: uuid.UUID, user: CurrentUser = Depends(require_role("auditor", "admin")),
                           db: Session = Depends(get_db)):
    run = recon.get_run(db, run_id)
    if run is None:
        return JSONResponse(status_code=404, content={"error": "not_found"})
    return run
