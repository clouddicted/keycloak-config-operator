"""Shared reconciliation reporting helpers."""

from __future__ import annotations

import logging
from dataclasses import dataclass

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
    logger: logging.Logger | None,
) -> None:
    """Emit a Warning Event and raise a delayed Kopf retry when requested."""
    if retry is None:
        return

    if logger is not None:
        logger.warning("%s: %s", retry.reason, retry.message)

    kopf.warn(body, reason=retry.reason, message=retry.message)
    raise kopf.TemporaryError(retry.message, delay=retry.delay)
