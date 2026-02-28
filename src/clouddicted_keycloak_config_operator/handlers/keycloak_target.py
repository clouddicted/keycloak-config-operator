"""Kopf handlers for KeycloakTarget resources."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from datetime import datetime
from typing import Any

import kopf

from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_TARGET_PLURAL,
)
from clouddicted_keycloak_config_operator.status import Condition, ready_condition, upsert_condition

KEYCLOAK_TARGET_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_TARGET_PLURAL,
}

VALIDATION_PENDING_REASON = "ValidationPending"
INVALID_SPEC_REASON = "InvalidSpec"
_CONDITION_FIELDS = ("type", "status", "reason", "message", "lastTransitionTime")


@kopf.on.create(**KEYCLOAK_TARGET_RESOURCE)
@kopf.on.update(**KEYCLOAK_TARGET_RESOURCE)
@kopf.on.resume(**KEYCLOAK_TARGET_RESOURCE)
def reconcile_keycloak_target(
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    **_: Any,
) -> None:
    """Patch placeholder KeycloakTarget status without external calls."""
    patch_keycloak_target_status(spec=spec, status=status, patch=patch)


def patch_keycloak_target_status(
    *,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    now: datetime | None = None,
) -> None:
    """Patch the minimal Ready condition for the current implementation crumb."""
    existing_conditions = _existing_conditions(status)
    ready = _ready_condition_for_spec(spec, now=now)

    status_patch = patch.setdefault("status", {})
    status_patch["conditions"] = upsert_condition(existing_conditions, ready)


def _ready_condition_for_spec(
    spec: Mapping[str, Any] | None,
    *,
    now: datetime | None = None,
) -> Condition:
    missing_fields = _missing_required_fields(spec)
    if missing_fields:
        fields = ", ".join(missing_fields)
        return ready_condition(
            "False",
            INVALID_SPEC_REASON,
            f"Missing required KeycloakTarget spec fields: {fields}.",
            now=now,
        )

    return ready_condition(
        "Unknown",
        VALIDATION_PENDING_REASON,
        "Keycloak connectivity validation is not implemented yet.",
        now=now,
    )


def _missing_required_fields(spec: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(spec, Mapping):
        return ["spec"]

    missing_fields: list[str] = []

    if not _is_non_empty_string(spec.get("url")):
        missing_fields.append("url")

    admin_credentials = spec.get("adminCredentials")
    secret_ref = (
        admin_credentials.get("secretRef")
        if isinstance(admin_credentials, Mapping)
        else None
    )
    secret_name = secret_ref.get("name") if isinstance(secret_ref, Mapping) else None

    if not _is_non_empty_string(secret_name):
        missing_fields.append("adminCredentials.secretRef.name")

    return missing_fields


def _existing_conditions(status: Mapping[str, Any] | None) -> Sequence[Mapping[str, str]]:
    if not isinstance(status, Mapping):
        return []

    conditions = status.get("conditions")
    if not isinstance(conditions, Sequence) or isinstance(conditions, str | bytes):
        return []

    return [
        condition
        for condition in conditions
        if isinstance(condition, Mapping)
        and all(isinstance(condition.get(field), str) for field in _CONDITION_FIELDS)
    ]


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
