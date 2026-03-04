"""Helpers for removing secrets from logs, errors, and status payloads."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

REDACTED_VALUE = "<redacted>"

SENSITIVE_KEY_NAMES = frozenset(
    {
        "authorization",
        "clientsecret",
        "credential",
        "credentials",
        "password",
        "refreshtoken",
        "secret",
        "token",
        "accesstoken",
    }
)


def redact_text(
    value: str,
    sensitive_values: Iterable[str | None] | str | None = None,
) -> str:
    """Replace configured non-empty sensitive values wherever they occur in text."""
    redacted = value
    for sensitive_value in _sensitive_values(sensitive_values):
        redacted = redacted.replace(sensitive_value, REDACTED_VALUE)

    return redacted


def redact_data(
    value: Any,
    sensitive_values: Iterable[str | None] | str | None = None,
) -> Any:
    """Return a redacted copy of a nested data structure."""
    return _redact_value(value, _sensitive_values(sensitive_values), force_redact=False)


def _redact_value(value: Any, sensitive_values: tuple[str, ...], *, force_redact: bool) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _redact_value(
                item,
                sensitive_values,
                force_redact=force_redact or _is_sensitive_key(key),
            )
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            _redact_value(item, sensitive_values, force_redact=force_redact)
            for item in value
        ]

    if isinstance(value, tuple):
        return tuple(
            _redact_value(item, sensitive_values, force_redact=force_redact)
            for item in value
        )

    if isinstance(value, frozenset):
        return frozenset(
            _redact_value(item, sensitive_values, force_redact=force_redact)
            for item in value
        )

    if isinstance(value, set):
        return {
            _redact_value(item, sensitive_values, force_redact=force_redact)
            for item in value
        }

    if force_redact:
        return _redact_sensitive_leaf(value)

    if isinstance(value, str):
        return redact_text(value, sensitive_values)

    return value


def _redact_sensitive_leaf(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, str):
        return REDACTED_VALUE if value else value

    return REDACTED_VALUE


def _is_sensitive_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False

    return _normalize_key(key) in SENSITIVE_KEY_NAMES


def _normalize_key(key: str) -> str:
    return "".join(character for character in key.lower() if character.isalnum())


def _sensitive_values(
    sensitive_values: Iterable[str | None] | str | None,
) -> tuple[str, ...]:
    if sensitive_values is None:
        return ()

    if isinstance(sensitive_values, str):
        values = (sensitive_values,)
    else:
        values = sensitive_values

    return tuple(
        dict.fromkeys(
            sorted(
                (value for value in values if value),
                key=len,
                reverse=True,
            )
        )
    )
