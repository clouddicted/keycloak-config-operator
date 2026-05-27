"""Kopf handlers for KeycloakRole resources."""

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
    KEYCLOAK_ROLE_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers.keycloak_realm import (
    KubernetesTargetResolver,
    TargetConnection,
    TargetResolutionError,
    keycloak_client_factory_kwargs,
)
from clouddicted_keycloak_config_operator.handlers.reconciliation import (
    RetryRequest,
    emit_event_for_condition_reasons,
    raise_for_retry,
)
from clouddicted_keycloak_config_operator.handlers.spec_validation import (
    enum_field_error,
    invalid_spec_message,
    non_empty_string_field_error,
)
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAdminClient,
    KeycloakAuthenticationError,
    KeycloakClientError,
    KeycloakRequestError,
    KeycloakResourceNotFoundError,
)
from clouddicted_keycloak_config_operator.status import (
    CONDITION_READY,
    Condition,
    drift_detected_condition,
    drift_unknown_condition,
    ready_condition,
    upsert_condition,
)

KEYCLOAK_ROLE_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_ROLE_PLURAL,
}

AUTHENTICATION_FAILED_REASON = "AuthenticationFailed"
INVALID_SPEC_REASON = "InvalidSpec"
REQUEST_FAILED_REASON = "RequestFailed"
ROLE_CREATED_REASON = "RoleCreated"
ROLE_DRIFT_DETECTED_REASON = "RoleDriftDetected"
ROLE_MISSING_REASON = "RoleMissing"
ROLE_OBSERVED_REASON = "RoleObserved"
ROLE_ORPHANED_REASON = "RoleOrphaned"
ROLE_UPDATED_REASON = "RoleUpdated"
TARGET_UNAVAILABLE_REASON = "TargetUnavailable"
NO_DRIFT_DETECTED_REASON = "NoDriftDetected"
MANAGEMENT_POLICY_OBSERVE_ONLY = "ObserveOnly"
MANAGEMENT_POLICY_RECONCILE = "Reconcile"
DEFAULT_MANAGEMENT_POLICY = MANAGEMENT_POLICY_RECONCILE
DELETION_POLICY_ORPHAN = "Orphan"
DELETION_POLICY_DELETE = "Delete"
DEFAULT_DELETION_POLICY = DELETION_POLICY_ORPHAN
DELETE_RETRY_DELAY_SECONDS = 30
_CONDITION_FIELDS = ("type", "status", "reason", "message", "lastTransitionTime")


class KeycloakRoleClient(Protocol):
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
    ) -> KeycloakRoleClient:
        """Create a Keycloak Admin API client."""


class TargetResolver(Protocol):
    def __call__(self, *, target_name: str, namespace: str | None) -> TargetConnection:
        """Resolve Keycloak connection settings for a KeycloakTarget."""


@dataclass(frozen=True)
class RoleSpec:
    target_name: str
    realm: str
    name: str
    management_policy: str
    deletion_policy: str
    description: str | None = None


@dataclass(frozen=True)
class RoleReconcileResult:
    ready_status: str
    ready_reason: str
    drift_detected: bool
    remote_id: str | None = None


@kopf.on.create(**KEYCLOAK_ROLE_RESOURCE)
@kopf.on.update(**KEYCLOAK_ROLE_RESOURCE)
@kopf.on.resume(**KEYCLOAK_ROLE_RESOURCE)
def reconcile_keycloak_role(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Observe, create, or update a realm role and patch status."""
    retry = patch_keycloak_role_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )
    if retry is None:
        _emit_reconcile_event(body, status=status, patch=patch)
    raise_for_retry(retry, body=body)


@kopf.on.delete(**KEYCLOAK_ROLE_RESOURCE)
def delete_keycloak_role(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Delete the remote Keycloak role when requested by policy."""
    deletion_policy = delete_keycloak_role_resource(spec=spec, namespace=namespace)
    _emit_delete_event(body, deletion_policy)


def delete_keycloak_role_resource(
    *,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
) -> str:
    """Delete the remote Keycloak role when deletionPolicy is Delete."""
    role_spec = _parse_role_spec(spec)
    if role_spec is None:
        raise kopf.PermanentError("KeycloakRole deletion skipped because spec is invalid.")

    if role_spec.deletion_policy == DELETION_POLICY_ORPHAN:
        return DELETION_POLICY_ORPHAN

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=role_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        raise _delete_temporary_error(
            "KeycloakRole deletion is waiting for the referenced KeycloakTarget."
        ) from None

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        delete_keycloak_role_if_exists(keycloak_client, role_spec)
        return DELETION_POLICY_DELETE
    except KeycloakAuthenticationError:
        raise _delete_temporary_error(
            "KeycloakRole deletion failed because Keycloak authentication failed."
        ) from None
    except KeycloakClientError:
        raise _delete_temporary_error(
            "KeycloakRole deletion failed while calling the Keycloak Admin API."
        ) from None


def patch_keycloak_role_status(
    *,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
    now: datetime | None = None,
) -> RetryRequest | None:
    """Patch KeycloakRole status after observing, creating, or updating the role."""
    existing_conditions = _existing_conditions(status)
    role_spec = _parse_role_spec(spec)

    if role_spec is None:
        _set_remote_id(patch, None)
        _set_blocked_conditions(
            patch,
            existing_conditions,
            _invalid_spec_condition(spec, now=now),
            "Drift detection was skipped because the KeycloakRole spec is invalid.",
            now=now,
        )
        return None

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=role_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        retry = RetryRequest(
            TARGET_UNAVAILABLE_REASON,
            "KeycloakRole is not ready because the referenced KeycloakTarget "
            "could not be resolved.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition(
                "False",
                retry.reason,
                retry.message,
                now=now,
            ),
            "Drift detection was skipped because the referenced KeycloakTarget "
            "could not be resolved.",
            now=now,
        )
        _set_remote_id(patch, None)
        return retry

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        reconcile_result = ensure_keycloak_role(keycloak_client, role_spec)
    except KeycloakAuthenticationError:
        retry = RetryRequest(
            AUTHENTICATION_FAILED_REASON,
            "KeycloakRole is not ready because Keycloak authentication failed.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition(
                "False",
                retry.reason,
                retry.message,
                now=now,
            ),
            "Drift detection was skipped because Keycloak authentication failed.",
            now=now,
        )
        _set_remote_id(patch, None)
        return retry
    except KeycloakClientError:
        retry = RetryRequest(
            REQUEST_FAILED_REASON,
            "KeycloakRole reconciliation failed while calling the Keycloak Admin API.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition(
                "False",
                retry.reason,
                retry.message,
                now=now,
            ),
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
            _role_ready_condition(reconcile_result, now=now),
            _role_drift_condition(reconcile_result, now=now),
        ),
    )
    return None


def ensure_keycloak_role(
    client: KeycloakRoleClient,
    role_spec: RoleSpec,
) -> RoleReconcileResult:
    """Create, update, or observe a realm role and return the result."""
    try:
        existing_role = client.request("GET", _role_path(role_spec.realm, role_spec.name))
    except KeycloakResourceNotFoundError:
        if role_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
            return RoleReconcileResult("False", ROLE_MISSING_REASON, True)

        client.request("POST", _roles_path(role_spec.realm), json=_modeled_role_payload(role_spec))
        created_role = client.request("GET", _role_path(role_spec.realm, role_spec.name))
        if not isinstance(created_role, Mapping):
            raise KeycloakRequestError(
                "Keycloak role lookup response was not an object"
            ) from None
        return RoleReconcileResult("True", ROLE_CREATED_REASON, False, _remote_id(created_role))

    if not isinstance(existing_role, Mapping):
        raise KeycloakRequestError("Keycloak role lookup response was not an object")

    if not _has_modeled_drift(existing_role, role_spec):
        return RoleReconcileResult("True", ROLE_OBSERVED_REASON, False, _remote_id(existing_role))

    if role_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
        return RoleReconcileResult(
            "True",
            ROLE_DRIFT_DETECTED_REASON,
            True,
            _remote_id(existing_role),
        )

    client.request(
        "PUT",
        _role_path(role_spec.realm, role_spec.name),
        json=_role_update_payload(existing_role, role_spec),
    )
    return RoleReconcileResult("True", ROLE_UPDATED_REASON, False, _remote_id(existing_role))


def delete_keycloak_role_if_exists(
    client: KeycloakRoleClient,
    role_spec: RoleSpec,
) -> None:
    """Delete an existing Keycloak realm role or no-op when it is already missing."""
    try:
        client.request("GET", _role_path(role_spec.realm, role_spec.name))
    except KeycloakResourceNotFoundError:
        return

    client.request("DELETE", _role_path(role_spec.realm, role_spec.name))


def _modeled_role_payload(role_spec: RoleSpec) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": role_spec.name}
    if role_spec.description is not None:
        payload["description"] = role_spec.description

    return payload


def _has_modeled_drift(existing_role: Mapping[str, Any], role_spec: RoleSpec) -> bool:
    desired_payload = _modeled_role_payload(role_spec)
    return any(
        existing_role.get(field) != desired_value
        for field, desired_value in desired_payload.items()
    )


def _role_update_payload(existing_role: Mapping[str, Any], role_spec: RoleSpec) -> dict[str, Any]:
    payload = dict(existing_role)
    payload.update(_modeled_role_payload(role_spec))
    return payload


def _remote_id(payload: Mapping[str, Any]) -> str | None:
    remote_id = payload.get("id")
    return remote_id.strip() if _is_non_empty_string(remote_id) else None


def _parse_role_spec(spec: Mapping[str, Any] | None) -> RoleSpec | None:
    if not isinstance(spec, Mapping):
        return None

    target_ref = spec.get("targetRef")
    target_name = target_ref.get("name") if isinstance(target_ref, Mapping) else None
    realm = spec.get("realm")
    name = spec.get("name")
    management_policy = spec.get("managementPolicy", DEFAULT_MANAGEMENT_POLICY)
    deletion_policy = spec.get("deletionPolicy", DEFAULT_DELETION_POLICY)
    description = spec.get("description")

    if (
        not _is_non_empty_string(target_name)
        or not _is_non_empty_string(realm)
        or not _is_non_empty_string(name)
    ):
        return None

    if description is not None and not _is_non_empty_string(description):
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

    return RoleSpec(
        target_name=target_name.strip(),
        realm=realm.strip(),
        name=name.strip(),
        management_policy=parsed_management_policy,
        deletion_policy=parsed_deletion_policy,
        description=description.strip() if isinstance(description, str) else None,
    )


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
            f"Missing required KeycloakRole spec fields: {fields}.",
            now=now,
        )

    invalid_fields = _invalid_spec_fields(spec)
    if invalid_fields:
        return ready_condition(
            "False",
            INVALID_SPEC_REASON,
            invalid_spec_message("KeycloakRole", invalid_fields),
            now=now,
        )

    return ready_condition("False", INVALID_SPEC_REASON, "KeycloakRole spec is invalid.", now=now)


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
        non_empty_string_field_error(spec, "description"),
    ]

    return [error for error in errors if error is not None]


def _role_ready_condition(
    reconcile_result: RoleReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if reconcile_result.ready_reason == ROLE_CREATED_REASON:
        message = "Keycloak realm role was created."
    elif reconcile_result.ready_reason == ROLE_UPDATED_REASON:
        message = "Keycloak realm role was updated."
    elif reconcile_result.ready_reason == ROLE_DRIFT_DETECTED_REASON:
        message = (
            "Keycloak realm role has modeled drift and was not changed because "
            "managementPolicy is ObserveOnly."
        )
    elif reconcile_result.ready_reason == ROLE_MISSING_REASON:
        message = (
            "Keycloak realm role is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = "Keycloak realm role already matches desired state."

    return ready_condition(
        reconcile_result.ready_status,
        reconcile_result.ready_reason,
        message,
        now=now,
    )


def _role_drift_condition(
    reconcile_result: RoleReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if not reconcile_result.drift_detected:
        return drift_detected_condition(
            "False",
            NO_DRIFT_DETECTED_REASON,
            "Keycloak realm role has no modeled drift.",
            now=now,
        )

    if reconcile_result.ready_reason == ROLE_MISSING_REASON:
        message = (
            "Keycloak realm role is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = (
            "Keycloak realm role differs from desired state and was not changed "
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
            ROLE_CREATED_REASON: ("Normal", "Keycloak realm role was created."),
            ROLE_UPDATED_REASON: ("Normal", "Keycloak realm role was updated."),
            ROLE_DRIFT_DETECTED_REASON: (
                "Warning",
                "Keycloak realm role has modeled drift and was left unchanged.",
            ),
            ROLE_MISSING_REASON: (
                "Warning",
                "Keycloak realm role is missing and was left unchanged.",
            ),
        },
    )


def _emit_delete_event(body: kopf.Body, deletion_policy: str) -> None:
    if deletion_policy == DELETION_POLICY_DELETE:
        kopf.event(
            body,
            type="Normal",
            reason="RoleDeleted",
            message="Keycloak realm role was deleted because deletionPolicy is Delete.",
        )
        return

    kopf.event(
        body,
        type="Normal",
        reason=ROLE_ORPHANED_REASON,
        message="Keycloak realm role was left in Keycloak because deletionPolicy is Orphan.",
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


def _roles_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}/roles"


def _role_path(realm: str, role_name: str) -> str:
    return f"{_roles_path(realm)}/{quote(role_name, safe='')}"


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
