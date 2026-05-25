"""Shared reconciliation reporting helpers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import kopf

DEFAULT_RETRY_DELAY_SECONDS = 60


@dataclass(frozen=True)
class RetryRequest:
    """A retryable reconciliation failure that has already been reflected in status."""

    reason: str
    message: str
    delay: int = DEFAULT_RETRY_DELAY_SECONDS


def raise_for_retry(
    retry: RetryRequest | None,
    *,
    body: kopf.Body,
) -> None:
    """Emit a Warning Event and raise a delayed Kopf retry when requested."""
    if retry is None:
        return

    kopf.event(body, type="Warning", reason=retry.reason, message=retry.message)
    raise kopf.TemporaryError(retry.message, delay=retry.delay)


def emit_event_for_condition_reasons(
    body: kopf.Body,
    *,
    previous_status: Mapping[str, Any] | None,
    patch: Mapping[str, Any],
    condition_type: str,
    events: Mapping[str, tuple[str, str | None]],
) -> None:
    """Emit an Event when a patched condition enters one of the requested reasons."""
    patched_condition = _condition_by_type(_status_mapping(patch), condition_type)
    if patched_condition is None:
        return

    reason = patched_condition.get("reason")
    if not isinstance(reason, str) or reason not in events:
        return

    previous_condition = _condition_by_type(previous_status, condition_type)
    if (
        previous_condition is not None
        and previous_condition.get("status") == patched_condition.get("status")
        and previous_condition.get("reason") == reason
    ):
        return

    event_type, message = events[reason]
    event_message = message or patched_condition.get("message")
    if not isinstance(event_message, str) or not event_message:
        return

    kopf.event(body, type=event_type, reason=reason, message=event_message)


def _status_mapping(patch: Mapping[str, Any]) -> Mapping[str, Any] | None:
    status = patch.get("status")
    return status if isinstance(status, Mapping) else None


def _condition_by_type(
    status: Mapping[str, Any] | None,
    condition_type: str,
) -> Mapping[str, Any] | None:
    if not isinstance(status, Mapping):
        return None

    conditions = status.get("conditions")
    if not isinstance(conditions, list | tuple):
        return None

    for condition in conditions:
        if isinstance(condition, Mapping) and condition.get("type") == condition_type:
            return condition

    return None
