"""Kopf handlers for KeycloakGroup resources."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from urllib.parse import quote

import kopf

from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_GROUP_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers.keycloak_realm import (
    KubernetesTargetResolver,
    TargetConnection,
    TargetResolutionError,
    keycloak_client_factory_kwargs,
)
from clouddicted_keycloak_config_operator.handlers.reconciliation import (
    RetryRequest,
    discard_unchanged_status_patch,
    emit_event_for_condition_reasons,
    periodic_reconciliation,
    raise_for_retry,
)
from clouddicted_keycloak_config_operator.handlers.spec_validation import (
    enum_field_error,
    invalid_spec_message,
)
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAdminClient,
    KeycloakAuthenticationError,
    KeycloakClientError,
    KeycloakRequestError,
)
from clouddicted_keycloak_config_operator.status import (
    CONDITION_READY,
    Condition,
    drift_detected_condition,
    drift_unknown_condition,
    ready_condition,
    upsert_condition,
)

KEYCLOAK_GROUP_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_GROUP_PLURAL,
}

AUTHENTICATION_FAILED_REASON = "AuthenticationFailed"
GROUP_CREATED_REASON = "GroupCreated"
GROUP_DRIFT_DETECTED_REASON = "GroupDriftDetected"
GROUP_MISSING_REASON = "GroupMissing"
GROUP_OBSERVED_REASON = "GroupObserved"
GROUP_ORPHANED_REASON = "GroupOrphaned"
GROUP_UPDATED_REASON = "GroupUpdated"
INVALID_SPEC_REASON = "InvalidSpec"
NO_DRIFT_DETECTED_REASON = "NoDriftDetected"
REQUEST_FAILED_REASON = "RequestFailed"
TARGET_UNAVAILABLE_REASON = "TargetUnavailable"
MANAGEMENT_POLICY_OBSERVE_ONLY = "ObserveOnly"
MANAGEMENT_POLICY_RECONCILE = "Reconcile"
DEFAULT_MANAGEMENT_POLICY = MANAGEMENT_POLICY_RECONCILE
DELETION_POLICY_ORPHAN = "Orphan"
DELETION_POLICY_DELETE = "Delete"
DEFAULT_DELETION_POLICY = DELETION_POLICY_ORPHAN
DELETE_RETRY_DELAY_SECONDS = 30
_CONDITION_FIELDS = ("type", "status", "reason", "message", "lastTransitionTime")


class KeycloakGroupClient(Protocol):
    def authenticate(self) -> None:
        """Authenticate to Keycloak."""

    def request(self, method: str, path: str, **kwargs: Any) -> Any | None:
        """Send an authenticated Keycloak Admin API request."""


class KeycloakClientFactory(Protocol):
    def __call__(
        self,
        *,
        base_url: str,
        username: str,
        password: str,
    ) -> KeycloakGroupClient:
        """Create a Keycloak Admin API client."""


class TargetResolver(Protocol):
    def __call__(self, *, target_name: str, namespace: str | None) -> TargetConnection:
        """Resolve Keycloak connection settings for a KeycloakTarget."""


@dataclass(frozen=True)
class GroupSpec:
    target_name: str
    realm: str
    name: str
    management_policy: str
    deletion_policy: str
    attributes: dict[str, list[str]] | None = None


@dataclass(frozen=True)
class GroupReconcileResult:
    ready_status: str
    ready_reason: str
    drift_detected: bool
    remote_id: str | None = None


@kopf.on.create(**KEYCLOAK_GROUP_RESOURCE)
@kopf.on.update(**KEYCLOAK_GROUP_RESOURCE)
@kopf.on.resume(**KEYCLOAK_GROUP_RESOURCE)
@periodic_reconciliation(KEYCLOAK_GROUP_RESOURCE)
def reconcile_keycloak_group(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Observe, create, or update a Keycloak group and patch status."""
    retry = patch_keycloak_group_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )
    discard_unchanged_status_patch(patch, status)
    if retry is None:
        _emit_reconcile_event(body, status=status, patch=patch)
    raise_for_retry(retry, body=body)


@kopf.on.delete(**KEYCLOAK_GROUP_RESOURCE)
def delete_keycloak_group(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Delete the remote Keycloak group when requested by policy."""
    deletion_policy = delete_keycloak_group_resource(spec=spec, namespace=namespace)
    _emit_delete_event(body, deletion_policy)


def delete_keycloak_group_resource(
    *,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
) -> str:
    """Delete the remote Keycloak group when deletionPolicy is Delete."""
    group_spec = _parse_group_spec(spec)
    if group_spec is None:
        raise kopf.PermanentError("KeycloakGroup deletion skipped because spec is invalid.")

    if group_spec.deletion_policy == DELETION_POLICY_ORPHAN:
        return DELETION_POLICY_ORPHAN

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=group_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        raise _delete_temporary_error(
            "KeycloakGroup deletion is waiting for the referenced KeycloakTarget."
        ) from None

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        delete_keycloak_group_if_exists(keycloak_client, group_spec)
        return DELETION_POLICY_DELETE
    except KeycloakAuthenticationError:
        raise _delete_temporary_error(
            "KeycloakGroup deletion failed because Keycloak authentication failed."
        ) from None
    except KeycloakClientError:
        raise _delete_temporary_error(
            "KeycloakGroup deletion failed while calling the Keycloak Admin API."
        ) from None


def patch_keycloak_group_status(
    *,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
    now: datetime | None = None,
) -> RetryRequest | None:
    """Patch KeycloakGroup status after reconciliation."""
    existing_conditions = _existing_conditions(status)
    group_spec = _parse_group_spec(spec)

    if group_spec is None:
        _set_remote_id(patch, None)
        _set_blocked_conditions(
            patch,
            existing_conditions,
            _invalid_spec_condition(spec, now=now),
            "Drift detection was skipped because the KeycloakGroup spec is invalid.",
            now=now,
        )
        return None

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=group_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        retry = RetryRequest(
            TARGET_UNAVAILABLE_REASON,
            "KeycloakGroup is not ready because the referenced KeycloakTarget "
            "could not be resolved.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition("False", retry.reason, retry.message, now=now),
            "Drift detection was skipped because the referenced KeycloakTarget "
            "could not be resolved.",
            now=now,
        )
        _set_remote_id(patch, None)
        return retry

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        reconcile_result = ensure_keycloak_group(keycloak_client, group_spec)
    except KeycloakAuthenticationError:
        retry = RetryRequest(
            AUTHENTICATION_FAILED_REASON,
            "KeycloakGroup is not ready because Keycloak authentication failed.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition("False", retry.reason, retry.message, now=now),
            "Drift detection was skipped because Keycloak authentication failed.",
            now=now,
        )
        _set_remote_id(patch, None)
        return retry
    except KeycloakClientError:
        retry = RetryRequest(
            REQUEST_FAILED_REASON,
            "KeycloakGroup reconciliation failed while calling the Keycloak Admin API.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition("False", retry.reason, retry.message, now=now),
            "Drift detection failed while calling the Keycloak Admin API.",
            now=now,
        )
        _set_remote_id(patch, None)
        return retry

    _set_remote_id(patch, reconcile_result.remote_id)
    _set_conditions(
        patch,
        existing_conditions,
        (
            _group_ready_condition(reconcile_result, now=now),
            _group_drift_condition(reconcile_result, now=now),
        ),
    )
    return None


def ensure_keycloak_group(
    client: KeycloakGroupClient,
    group_spec: GroupSpec,
) -> GroupReconcileResult:
    """Create, update, or observe a Keycloak group and return the result."""
    existing_group = find_keycloak_group(client, group_spec)
    if existing_group is None:
        if group_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
            return GroupReconcileResult("False", GROUP_MISSING_REASON, True)

        client.request(
            "POST",
            _groups_path(group_spec.realm),
            json=_modeled_group_payload(group_spec),
        )
        created_group = find_keycloak_group(client, group_spec)
        if created_group is None:
            raise KeycloakRequestError("Keycloak group was not found after creation")
        return GroupReconcileResult(
            "True",
            GROUP_CREATED_REASON,
            False,
            _remote_id(created_group),
        )

    if not _has_modeled_drift(existing_group, group_spec):
        return GroupReconcileResult(
            "True",
            GROUP_OBSERVED_REASON,
            False,
            _remote_id(existing_group),
        )

    if group_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
        return GroupReconcileResult(
            "True",
            GROUP_DRIFT_DETECTED_REASON,
            True,
            _remote_id(existing_group),
        )

    group_id = _remote_id(existing_group)
    if group_id is None:
        raise KeycloakRequestError("Keycloak group lookup response did not include id")

    client.request(
        "PUT",
        _group_path(group_spec.realm, group_id),
        json=_group_update_payload(existing_group, group_spec),
    )
    return GroupReconcileResult("True", GROUP_UPDATED_REASON, False, group_id)


def delete_keycloak_group_if_exists(
    client: KeycloakGroupClient,
    group_spec: GroupSpec,
) -> None:
    """Delete an existing Keycloak group or no-op when it is already missing."""
    existing_group = find_keycloak_group(client, group_spec)
    if existing_group is None:
        return

    group_id = _remote_id(existing_group)
    if group_id is None:
        raise KeycloakRequestError("Keycloak group lookup response did not include id")

    client.request("DELETE", _group_path(group_spec.realm, group_id))


def find_keycloak_group(
    client: KeycloakGroupClient,
    group_spec: GroupSpec,
) -> Mapping[str, Any] | None:
    """Find the top-level group represented by this spec."""
    groups = client.request(
        "GET",
        _groups_path(group_spec.realm),
        params={"search": group_spec.name, "exact": "true"},
    )
    if not isinstance(groups, list):
        raise KeycloakRequestError("Keycloak group lookup response was not a list")

    return _matching_group(groups, group_spec.name)


def _modeled_group_payload(group_spec: GroupSpec) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": group_spec.name}
    if group_spec.attributes is not None:
        payload["attributes"] = group_spec.attributes

    return payload


def _has_modeled_drift(existing_group: Mapping[str, Any], group_spec: GroupSpec) -> bool:
    if existing_group.get("name") != group_spec.name:
        return True

    if group_spec.attributes is None:
        return False

    return _normalized_attributes(existing_group.get("attributes")) != group_spec.attributes


def _group_update_payload(
    existing_group: Mapping[str, Any],
    group_spec: GroupSpec,
) -> dict[str, Any]:
    payload = dict(existing_group)
    payload.update(_modeled_group_payload(group_spec))
    return payload


def _remote_id(payload: Mapping[str, Any]) -> str | None:
    remote_id = payload.get("id")
    return remote_id.strip() if _is_non_empty_string(remote_id) else None


def _matching_group(groups: Sequence[Any], name: str) -> Mapping[str, Any] | None:
    fallback: Mapping[str, Any] | None = None
    for group in _flatten_groups(groups):
        group_path = group.get("path")
        if group.get("name") != name:
            continue

        if group_path == f"/{name}":
            return group

        if fallback is None:
            fallback = group

    return fallback


def _flatten_groups(groups: Sequence[Any]) -> list[Mapping[str, Any]]:
    flattened: list[Mapping[str, Any]] = []
    for group in groups:
        if not isinstance(group, Mapping):
            continue

        flattened.append(group)
        subgroups = group.get("subGroups")
        if isinstance(subgroups, Sequence) and not isinstance(subgroups, str | bytes):
            flattened.extend(_flatten_groups(subgroups))

    return flattened


def _parse_group_spec(spec: Mapping[str, Any] | None) -> GroupSpec | None:
    if not isinstance(spec, Mapping):
        return None

    target_ref = spec.get("targetRef")
    target_name = target_ref.get("name") if isinstance(target_ref, Mapping) else None
    realm = spec.get("realm")
    name = spec.get("name")
    management_policy = spec.get("managementPolicy", DEFAULT_MANAGEMENT_POLICY)
    deletion_policy = spec.get("deletionPolicy", DEFAULT_DELETION_POLICY)
    attributes = _parse_attributes(spec.get("attributes"))

    if (
        not _is_non_empty_string(target_name)
        or not _is_non_empty_string(realm)
        or not _is_non_empty_string(name)
    ):
        return None

    if "attributes" in spec and attributes is None:
        return None

    if not _is_non_empty_string(management_policy):
        return None

    parsed_management_policy = management_policy.strip()
    if parsed_management_policy not in {
        MANAGEMENT_POLICY_OBSERVE_ONLY,
        MANAGEMENT_POLICY_RECONCILE,
    }:
        return None

    if not _is_non_empty_string(deletion_policy):
        return None

    parsed_deletion_policy = deletion_policy.strip()
    if parsed_deletion_policy not in {DELETION_POLICY_ORPHAN, DELETION_POLICY_DELETE}:
        return None

    return GroupSpec(
        target_name=target_name.strip(),
        realm=realm.strip(),
        name=name.strip(),
        management_policy=parsed_management_policy,
        deletion_policy=parsed_deletion_policy,
        attributes=attributes,
    )


def _parse_attributes(attributes: Any) -> dict[str, list[str]] | None:
    if attributes is None:
        return None

    if not isinstance(attributes, Mapping):
        return None

    parsed: dict[str, list[str]] = {}
    for key, values in attributes.items():
        if not _is_non_empty_string(key):
            return None

        if (
            not isinstance(values, Sequence)
            or isinstance(values, str | bytes)
            or not all(_is_non_empty_string(value) for value in values)
        ):
            return None

        parsed[key.strip()] = [value.strip() for value in values]

    return parsed


def _normalized_attributes(attributes: Any) -> dict[str, list[str]]:
    parsed = _parse_attributes(attributes)
    return parsed if parsed is not None else {}


def _invalid_spec_condition(
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
            f"Missing required KeycloakGroup spec fields: {fields}.",
            now=now,
        )

    invalid_fields = _invalid_spec_fields(spec)
    if invalid_fields:
        return ready_condition(
            "False",
            INVALID_SPEC_REASON,
            invalid_spec_message("KeycloakGroup", invalid_fields),
            now=now,
        )

    return ready_condition(
        "False",
        INVALID_SPEC_REASON,
        "KeycloakGroup spec is invalid.",
        now=now,
    )


def _missing_required_fields(spec: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(spec, Mapping):
        return ["spec"]

    missing_fields: list[str] = []
    target_ref = spec.get("targetRef")
    target_name = target_ref.get("name") if isinstance(target_ref, Mapping) else None

    if not _is_non_empty_string(target_name):
        missing_fields.append("targetRef.name")
    if not _is_non_empty_string(spec.get("realm")):
        missing_fields.append("realm")
    if not _is_non_empty_string(spec.get("name")):
        missing_fields.append("name")

    return missing_fields


def _invalid_spec_fields(spec: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(spec, Mapping):
        return []

    errors = [
        enum_field_error(
            spec,
            "managementPolicy",
            {MANAGEMENT_POLICY_RECONCILE, MANAGEMENT_POLICY_OBSERVE_ONLY},
            default=DEFAULT_MANAGEMENT_POLICY,
        ),
        enum_field_error(
            spec,
            "deletionPolicy",
            {DELETION_POLICY_ORPHAN, DELETION_POLICY_DELETE},
            default=DEFAULT_DELETION_POLICY,
        ),
        _attributes_field_error(spec),
    ]

    return [error for error in errors if error is not None]


def _attributes_field_error(spec: Mapping[str, Any]) -> str | None:
    if "attributes" not in spec:
        return None

    if _parse_attributes(spec.get("attributes")) is not None:
        return None

    return "attributes must be a map of non-empty string keys to lists of non-empty strings"


def _group_ready_condition(
    reconcile_result: GroupReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if reconcile_result.ready_reason == GROUP_CREATED_REASON:
        message = "Keycloak group was created."
    elif reconcile_result.ready_reason == GROUP_UPDATED_REASON:
        message = "Keycloak group was updated."
    elif reconcile_result.ready_reason == GROUP_DRIFT_DETECTED_REASON:
        message = (
            "Keycloak group has modeled drift and was not changed because "
            "managementPolicy is ObserveOnly."
        )
    elif reconcile_result.ready_reason == GROUP_MISSING_REASON:
        message = (
            "Keycloak group is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = "Keycloak group already matches desired state."

    return ready_condition(
        reconcile_result.ready_status,
        reconcile_result.ready_reason,
        message,
        now=now,
    )


def _group_drift_condition(
    reconcile_result: GroupReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if not reconcile_result.drift_detected:
        return drift_detected_condition(
            "False",
            NO_DRIFT_DETECTED_REASON,
            "Keycloak group has no modeled drift.",
            now=now,
        )

    if reconcile_result.ready_reason == GROUP_MISSING_REASON:
        message = (
            "Keycloak group is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = (
            "Keycloak group differs from desired state and was not changed "
            "because managementPolicy is ObserveOnly."
        )

    return drift_detected_condition(
        "True",
        reconcile_result.ready_reason,
        message,
        now=now,
    )


def _delete_temporary_error(message: str) -> kopf.TemporaryError:
    return kopf.TemporaryError(message, delay=DELETE_RETRY_DELAY_SECONDS)


def _set_blocked_conditions(
    patch: MutableMapping[str, Any],
    existing_conditions: Sequence[Mapping[str, str]],
    ready: Mapping[str, str],
    drift_message: str,
    *,
    now: datetime | None = None,
) -> None:
    _set_conditions(
        patch,
        existing_conditions,
        (
            ready,
            drift_unknown_condition(ready["reason"], drift_message, now=now),
        ),
    )


def _set_conditions(
    patch: MutableMapping[str, Any],
    existing_conditions: Sequence[Mapping[str, str]],
    conditions: Sequence[Mapping[str, str]],
) -> None:
    status_patch = patch.setdefault("status", {})
    updated_conditions = list(existing_conditions)
    for condition in conditions:
        updated_conditions = upsert_condition(updated_conditions, condition)

    status_patch["conditions"] = updated_conditions


def _set_remote_id(patch: MutableMapping[str, Any], remote_id: str | None) -> None:
    status_patch = patch.setdefault("status", {})
    status_patch["remoteId"] = remote_id


def _emit_reconcile_event(
    body: kopf.Body,
    *,
    status: Mapping[str, Any] | None,
    patch: Mapping[str, Any],
) -> None:
    emit_event_for_condition_reasons(
        body,
        previous_status=status,
        patch=patch,
        condition_type=CONDITION_READY,
        events={
            GROUP_CREATED_REASON: ("Normal", "Keycloak group was created."),
            GROUP_UPDATED_REASON: ("Normal", "Keycloak group was updated."),
            GROUP_DRIFT_DETECTED_REASON: (
                "Warning",
                "Keycloak group has modeled drift and was left unchanged.",
            ),
            GROUP_MISSING_REASON: (
                "Warning",
                "Keycloak group is missing and was left unchanged.",
            ),
        },
    )


def _emit_delete_event(body: kopf.Body, deletion_policy: str) -> None:
    if deletion_policy == DELETION_POLICY_DELETE:
        kopf.event(
            body,
            type="Normal",
            reason="GroupDeleted",
            message="Keycloak group was deleted because deletionPolicy is Delete.",
        )
        return

    kopf.event(
        body,
        type="Normal",
        reason=GROUP_ORPHANED_REASON,
        message="Keycloak group was left in Keycloak because deletionPolicy is Orphan.",
    )


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


def _groups_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}/groups"


def _group_path(realm: str, group_id: str) -> str:
    return f"{_groups_path(realm)}/{quote(group_id, safe='')}"


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
