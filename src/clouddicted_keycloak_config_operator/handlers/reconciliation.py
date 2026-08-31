"""Shared reconciliation reporting helpers."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from functools import partial
from typing import Any, TypeVar

import kopf

DEFAULT_RETRY_DELAY_SECONDS = 60
DEFAULT_RECONCILIATION_INTERVAL_SECONDS = 600
RECONCILIATION_INTERVAL_ENV = "RECONCILIATION_INTERVAL_SECONDS"
_MISSING = object()
_Handler = TypeVar("_Handler", bound=Callable[..., Any])


def configured_reconciliation_interval_seconds(
    environ: Mapping[str, str] | None = None,
) -> int:
    """Read and validate the periodic reconciliation interval."""
    values = os.environ if environ is None else environ
    raw_value = values.get(
        RECONCILIATION_INTERVAL_ENV,
        str(DEFAULT_RECONCILIATION_INTERVAL_SECONDS),
    )
    try:
        interval_seconds = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{RECONCILIATION_INTERVAL_ENV} must be a non-negative integer"
        ) from exc

    if interval_seconds < 0:
        raise ValueError(
            f"{RECONCILIATION_INTERVAL_ENV} must be a non-negative integer"
        )

    return interval_seconds


RECONCILIATION_INTERVAL_SECONDS = configured_reconciliation_interval_seconds()


def reconciliation_initial_delay(
    *,
    uid: str = "",
    namespace: str | None = None,
    name: str | None = None,
    interval_seconds: int = RECONCILIATION_INTERVAL_SECONDS,
    **_: Any,
) -> float:
    """Return a stable per-resource delay that spreads timer startup over one interval."""
    if interval_seconds <= 0:
        return 0.0

    seed = f"{namespace or ''}/{name or ''}/{uid}".encode()
    digest = hashlib.sha256(seed).digest()
    fraction = int.from_bytes(digest[:8], byteorder="big") / 2**64
    return fraction * interval_seconds


def periodic_reconciliation(resource: Mapping[str, str]) -> Callable[[_Handler], _Handler]:
    """Register a per-resource Kopf timer unless periodic reconciliation is disabled."""

    def decorator(fn: _Handler) -> _Handler:
        if RECONCILIATION_INTERVAL_SECONDS == 0:
            return fn

        timer = kopf.timer(
            **resource,
            interval=float(RECONCILIATION_INTERVAL_SECONDS),
            initial_delay=partial(
                reconciliation_initial_delay,
                interval_seconds=RECONCILIATION_INTERVAL_SECONDS,
            ),
        )
        return timer(fn)

    return decorator


def discard_unchanged_status_patch(
    patch: MutableMapping[str, Any],
    status: Mapping[str, Any] | None,
) -> None:
    """Remove status fields whose desired values already match the resource status."""
    patched_status = patch.get("status")
    if not isinstance(patched_status, MutableMapping):
        return

    existing_status = status if isinstance(status, Mapping) else {}
    for field in list(patched_status):
        existing_value = existing_status.get(field, _MISSING)
        patched_value = patched_status[field]
        if patched_value == existing_value or (
            existing_value is _MISSING and patched_value is None
        ):
            del patched_status[field]

    if not patched_status:
        del patch["status"]


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
