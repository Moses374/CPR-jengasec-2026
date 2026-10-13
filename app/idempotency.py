"""PostgreSQL persistence for user-scoped idempotency records.

Claim the key, perform the money operation, and save its response in the same
transaction. A conflicting INSERT waits for the first transaction; after it
commits, the retry either replays its response or reports a body conflict.
"""

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text

from app.controls import fingerprint_operation, idempotency_key_hash


class IdempotencyConflict(ValueError):
    """The same user reused a key for a different request."""


class IdempotencyResponseMissing(RuntimeError):
    """A committed idempotency row has no response; fail closed rather than execute again."""


@dataclass(frozen=True)
class IdempotencyClaim:
    row_id: int
    key_hash: str
    request_hash: str
    owner: bool
    response_status: int | None = None
    response_body: Any = None

    @property
    def is_replay(self) -> bool:
        return not self.owner


def claim_idempotency_key(db, *, user_id, key: str, request_hash: str) -> IdempotencyClaim:
    """Reserve a key or return its committed response; caller owns the transaction."""
    if len(request_hash) != 64 or any(char not in "0123456789abcdef" for char in request_hash):
        raise ValueError("request_hash must be lowercase SHA-256 hex")
    key_hash = idempotency_key_hash(key)
    inserted = db.execute(
        text(
            "INSERT INTO idempotency_keys (user_id, key_hash, request_hash) "
            "VALUES (:user_id, :key_hash, :request_hash) "
            "ON CONFLICT (user_id, key_hash) DO NOTHING RETURNING id"
        ),
        {"user_id": user_id, "key_hash": key_hash, "request_hash": request_hash},
    ).first()
    if inserted is not None:
        return IdempotencyClaim(inserted.id, key_hash, request_hash, owner=True)

    existing = db.execute(
        text(
            "SELECT id, request_hash, response_status, response_body, expires_at <= now() AS expired "
            "FROM idempotency_keys WHERE user_id = :user_id AND key_hash = :key_hash FOR UPDATE"
        ),
        {"user_id": user_id, "key_hash": key_hash},
    ).first()
    if existing is None:
        raise RuntimeError("idempotency record disappeared during claim")

    if existing.expired:
        renewed = db.execute(
            text(
                "UPDATE idempotency_keys SET request_hash = :request_hash, response_status = NULL, "
                "response_body = NULL, created_at = now(), expires_at = now() + interval '24 hours' "
                "WHERE id = :id RETURNING id"
            ),
            {"request_hash": request_hash, "id": existing.id},
        ).one()
        return IdempotencyClaim(renewed.id, key_hash, request_hash, owner=True)

    if existing.request_hash != request_hash:
        raise IdempotencyConflict("Idempotency-Key was already used for a different request")
    if existing.response_status is None or existing.response_body is None:
        raise IdempotencyResponseMissing("idempotency response is not available")
    return IdempotencyClaim(
        existing.id,
        key_hash,
        request_hash,
        owner=False,
        response_status=int(existing.response_status),
        response_body=existing.response_body,
    )


def save_idempotency_response(
    db,
    claim: IdempotencyClaim,
    *,
    status: int,
    body: dict,
) -> None:
    """Save the original JSON response before committing the associated operation."""
    if not claim.owner:
        raise ValueError("only the transaction that claimed the key can save its response")
    if isinstance(status, bool) or not 100 <= status <= 599:
        raise ValueError("response status must be an HTTP status code")
    if not isinstance(body, dict):
        raise ValueError("idempotent API responses must be JSON objects")
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    saved = db.execute(
        text(
            "UPDATE idempotency_keys SET response_status = :status, response_body = CAST(:body AS jsonb) "
            "WHERE id = :id AND request_hash = :request_hash AND response_status IS NULL "
            "AND expires_at > now() RETURNING id"
        ),
        {"status": status, "body": encoded, "id": claim.row_id, "request_hash": claim.request_hash},
    ).first()
    if saved is None:
        raise RuntimeError("idempotency response could not be stored")


def prune_expired_idempotency_keys(db, *, batch_size: int = 1_000) -> int:
    """Delete an expiry-bounded batch; the database rejects deletion before expiry."""
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= 10_000:
        raise ValueError("batch_size must be between 1 and 10000")
    deleted = db.execute(
        text(
            "WITH expired AS ("
            " SELECT id FROM idempotency_keys WHERE expires_at <= now() "
            " ORDER BY expires_at LIMIT :batch_size FOR UPDATE SKIP LOCKED"
            ") DELETE FROM idempotency_keys k USING expired e WHERE k.id = e.id RETURNING k.id"
        ),
        {"batch_size": batch_size},
    ).all()
    return len(deleted)
