"""Small helpers for user-facing spec validation messages."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def enum_field_error(
    spec: Mapping[str, Any],
    field: str,
    allowed_values: set[str],
    *,
    default: str | None = None,
) -> str | None:
    """Return a validation error when a string enum field has an unsupported value."""
    if field not in spec and default is None:
        return None

    value = spec.get(field, default)
    if isinstance(value, str) and value.strip() in allowed_values:
        return None

    return f"{field} must be one of: {_allowed_values(allowed_values)}"


def bool_field_error(spec: Mapping[str, Any], field: str) -> str | None:
    """Return a validation error when an optional field is not a boolean."""
    if field not in spec:
        return None

    if isinstance(spec[field], bool):
        return None

    return f"{field} must be a boolean"


def string_list_field_error(spec: Mapping[str, Any], field: str) -> str | None:
    """Return a validation error when an optional field is not a list of strings."""
    if field not in spec:
        return None

    value = spec[field]
    if (
        isinstance(value, Sequence)
        and not isinstance(value, str | bytes)
        and all(isinstance(item, str) and item.strip() for item in value)
    ):
        return None

    return f"{field} must be a list of non-empty strings"


def unique_string_list_field_error(spec: Mapping[str, Any], field: str) -> str | None:
    """Return a validation error when an optional string list has duplicate entries."""
    list_error = string_list_field_error(spec, field)
    if list_error is not None:
        return list_error

    if field not in spec:
        return None

    value = spec[field]
    if len(set(value)) == len(value):
        return None

    return f"{field} must not contain duplicate values"


def non_empty_string_field_error(spec: Mapping[str, Any], field: str) -> str | None:
    """Return a validation error when an optional field is not a non-empty string."""
    if field not in spec:
        return None

    value = spec[field]
    if isinstance(value, str) and bool(value.strip()):
        return None

    return f"{field} must be a non-empty string"


def invalid_spec_message(resource_kind: str, errors: Sequence[str]) -> str:
    """Build a stable InvalidSpec message from validation errors."""
    details = "; ".join(errors)
    return f"Invalid {resource_kind} spec fields: {details}."


def _allowed_values(values: set[str]) -> str:
    return ", ".join(f"`{value}`" for value in sorted(values))
