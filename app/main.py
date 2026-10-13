from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

import logging

from app import observability as audit
from app.db import get_db
from app.observability import BodySizeLimit, RequestLogMiddleware, configure_logging
from app.routes import ledger as ledger_routes

configure_logging()

app = FastAPI(
    title="JengaBank Payment Processing Service",
    version="0.1.0",
    openapi_url="/openapi.json",
    docs_url=None,   # no Swagger / ReDoc UI shipped
    redoc_url=None,
    redirect_slashes=False,  # a redirect would echo the attacker's Host header in Location
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


app.add_middleware(BodySizeLimit)
# Added last, so it is outermost and logs every request, including ones other layers reject.
app.add_middleware(RequestLogMiddleware)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # FastAPI's default 422 echoes the submitted input back; return only where and why.
    errors = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", "invalid")} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"error": "invalid_request", "details": errors})


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail}, headers=exc.headers)


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    # Never a stack trace, SQL or version in a response; the log gets the error type only.
    logging.getLogger("app.error").error("app.error type=%s", type(exc).__name__)
    audit.action("app.error")
    return JSONResponse(status_code=500, content={"error": "internal_error"})


app.include_router(ledger_routes.router)


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}


@app.get("/readyz", include_in_schema=False)
def readyz(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse(status_code=503, content={"status": "unavailable"})
    return {"status": "ready"}
