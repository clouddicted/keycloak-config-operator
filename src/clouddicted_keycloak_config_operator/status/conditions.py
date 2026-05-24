"""Kubernetes-style status condition helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Literal

CONDITION_READY = "Ready"
CONDITION_AUTHENTICATED = "Authenticated"
CONDITION_SECRET_READY = "SecretReady"
CONDITION_DRIFT_DETECTED = "DriftDetected"

CONDITION_TYPE_ORDER = (
    CONDITION_READY,
    CONDITION_AUTHENTICATED,
    CONDITION_SECRET_READY,
    CONDITION_DRIFT_DETECTED,
)

ConditionStatus = Literal["True", "False", "Unknown"]
Condition = dict[str, str]


def ready_condition(
    status: ConditionStatus,
    reason: str,
    message: str,
    *,
    now: datetime | None = None,
) -> Condition:
    """Create a Ready condition."""
    return condition(CONDITION_READY, status, reason, message, now=now)


def authenticated_condition(
    status: ConditionStatus,
    reason: str,
    message: str,
    *,
    now: datetime | None = None,
) -> Condition:
    """Create an Authenticated condition."""
    return condition(CONDITION_AUTHENTICATED, status, reason, message, now=now)


def secret_ready_condition(
    status: ConditionStatus,
    reason: str,
    message: str,
    *,
    now: datetime | None = None,
) -> Condition:
    """Create a SecretReady condition."""
    return condition(CONDITION_SECRET_READY, status, reason, message, now=now)


def drift_detected_condition(
    status: ConditionStatus,
    reason: str,
    message: str,
    *,
    now: datetime | None = None,
) -> Condition:
    """Create a DriftDetected condition."""
    return condition(CONDITION_DRIFT_DETECTED, status, reason, message, now=now)


def condition(
    condition_type: str,
    status: ConditionStatus,
    reason: str,
    message: str,
    *,
    now: datetime | None = None,
) -> Condition:
    """Create a plain condition dictionary suitable for status patching."""
    return {
        "type": condition_type,
        "status": status,
        "reason": reason,
        "message": message,
        "lastTransitionTime": utc_timestamp(now),
    }


def upsert_condition(
    conditions: Sequence[Mapping[str, str]] | None,
    new_condition: Mapping[str, str],
) -> list[Condition]:
    """Insert or replace a condition while preserving transition times when status is stable."""
    conditions_by_type = {
        existing["type"]: dict(existing)
        for existing in conditions or ()
    }

    condition_type = new_condition["type"]
    updated_condition = dict(new_condition)
    existing_condition = conditions_by_type.get(condition_type)

    if (
        existing_condition is not None
        and existing_condition.get("status") == updated_condition.get("status")
    ):
        updated_condition["lastTransitionTime"] = existing_condition["lastTransitionTime"]

    conditions_by_type[condition_type] = updated_condition

    return sorted(conditions_by_type.values(), key=_condition_order_key)


def utc_timestamp(now: datetime | None = None) -> str:
    """Return an RFC 3339 timestamp in UTC."""
    timestamp = now if now is not None else datetime.now(UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)

    timestamp = timestamp.astimezone(UTC).replace(microsecond=0)
    return timestamp.isoformat().replace("+00:00", "Z")


def _condition_order_key(condition_value: Mapping[str, str]) -> tuple[int, str]:
    condition_type = condition_value["type"]
    default_position = len(CONDITION_TYPE_ORDER)
    return (
        CONDITION_TYPE_ORDER.index(condition_type)
        if condition_type in CONDITION_TYPE_ORDER
        else default_position,
        condition_type,
    )
