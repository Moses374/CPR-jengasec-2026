"""Deterministic transfer risk policy; the posting flow supplies a locked snapshot."""

from dataclasses import dataclass
from typing import Literal

DecisionName = Literal["allow", "review", "block"]

# All monetary thresholds are integer cents; velocity history excludes the proposed transfer.
REVIEW_VELOCITY_COUNT_10M = 5
BLOCK_VELOCITY_COUNT_10M = 10
REVIEW_VELOCITY_TOTAL_10M_CENTS = 500_000
REVIEW_TYPICAL_MULTIPLE = 5
REVIEW_TYPICAL_MIN_CENTS = 50_000
REVIEW_NEW_PAYEE_CENTS = 100_000
REVIEW_NEW_ACCOUNT_HOURS = 24
REVIEW_NEW_ACCOUNT_CENTS = 50_000
REVIEW_DRAIN_FRACTION_NUMERATOR = 9
REVIEW_DRAIN_FRACTION_DENOMINATOR = 10
REVIEW_DRAIN_MIN_CENTS = 100_000


@dataclass(frozen=True)
class TransferRisk:
    amount_cents: int


@dataclass(frozen=True)
class SenderHistory:
    typical_transfer_cents: int | None
    prior_transfer_count_10m: int
    prior_transfer_total_cents_10m: int
    recipient_previously_paid: bool
    account_age_hours: int
    available_balance_cents: int


@dataclass(frozen=True)
class Assessment:
    decision: DecisionName
    reasons: tuple[str, ...]


def assess(transfer: TransferRisk, sender_history: SenderHistory) -> Assessment:
    """Apply the named policy thresholds to a transaction and its sender snapshot.

    The caller must build ``sender_history`` inside the transfer's locked database
    transaction. Review is preferred for uncertain signals; only extreme velocity
    is an automatic fraud block.
    """
    if transfer.amount_cents <= 0:
        raise ValueError("amount_cents must be positive")
    if sender_history.prior_transfer_count_10m < 0:
        raise ValueError("prior transfer count cannot be negative")
    if sender_history.prior_transfer_total_cents_10m < 0:
        raise ValueError("prior transfer total cannot be negative")
    if sender_history.account_age_hours < 0:
        raise ValueError("account age cannot be negative")
    if sender_history.available_balance_cents < 0:
        raise ValueError("available balance cannot be negative")
    if sender_history.typical_transfer_cents is not None and sender_history.typical_transfer_cents < 0:
        raise ValueError("typical transfer amount cannot be negative")

    reasons: list[str] = []
    if sender_history.prior_transfer_count_10m >= BLOCK_VELOCITY_COUNT_10M:
        return Assessment("block", ("velocity_block_10m",))

    if sender_history.prior_transfer_count_10m >= REVIEW_VELOCITY_COUNT_10M:
        reasons.append("velocity_count_10m")
    if (
        sender_history.prior_transfer_total_cents_10m + transfer.amount_cents
        >= REVIEW_VELOCITY_TOTAL_10M_CENTS
    ):
        reasons.append("velocity_amount_10m")

    typical = sender_history.typical_transfer_cents
    if (
        typical is not None
        and typical > 0
        and transfer.amount_cents >= typical * REVIEW_TYPICAL_MULTIPLE
        and transfer.amount_cents >= REVIEW_TYPICAL_MIN_CENTS
    ):
        reasons.append("amount_vs_typical")

    if (
        not sender_history.recipient_previously_paid
        and transfer.amount_cents >= REVIEW_NEW_PAYEE_CENTS
    ):
        reasons.append("new_payee_amount")
    if (
        sender_history.account_age_hours < REVIEW_NEW_ACCOUNT_HOURS
        and transfer.amount_cents >= REVIEW_NEW_ACCOUNT_CENTS
    ):
        reasons.append("new_account_amount")
    if (
        sender_history.available_balance_cents > 0
        and transfer.amount_cents >= REVIEW_DRAIN_MIN_CENTS
        and transfer.amount_cents * REVIEW_DRAIN_FRACTION_DENOMINATOR
        >= sender_history.available_balance_cents * REVIEW_DRAIN_FRACTION_NUMERATOR
    ):
        reasons.append("rapid_drain")
    if reasons:
        return Assessment("review", tuple(reasons))
    return Assessment("allow", ())
