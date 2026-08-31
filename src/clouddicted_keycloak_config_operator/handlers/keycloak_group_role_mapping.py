"""Kopf handlers for KeycloakGroupRoleMapping resources."""

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
    KEYCLOAK_GROUP_ROLE_MAPPING_PLURAL,
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

KEYCLOAK_GROUP_ROLE_MAPPING_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_GROUP_ROLE_MAPPING_PLURAL,
}

AUTHENTICATION_FAILED_REASON = "AuthenticationFailed"
CLIENT_MISSING_REASON = "ClientMissing"
GROUP_MISSING_REASON = "GroupMissing"
GROUP_ROLE_MAPPING_ASSIGNED_REASON = "GroupRoleMappingAssigned"
GROUP_ROLE_MAPPING_MISSING_REASON = "GroupRoleMappingMissing"
GROUP_ROLE_MAPPING_OBSERVED_REASON = "GroupRoleMappingObserved"
GROUP_ROLE_MAPPING_ORPHANED_REASON = "GroupRoleMappingOrphaned"
INVALID_SPEC_REASON = "InvalidSpec"
NO_DRIFT_DETECTED_REASON = "NoDriftDetected"
REQUEST_FAILED_REASON = "RequestFailed"
ROLE_MISSING_REASON = "RoleMissing"
TARGET_UNAVAILABLE_REASON = "TargetUnavailable"
ROLE_TYPE_REALM_ROLE = "RealmRole"
ROLE_TYPE_CLIENT_ROLE = "ClientRole"
MANAGEMENT_POLICY_OBSERVE_ONLY = "ObserveOnly"
MANAGEMENT_POLICY_RECONCILE = "Reconcile"
DEFAULT_MANAGEMENT_POLICY = MANAGEMENT_POLICY_RECONCILE
DELETION_POLICY_ORPHAN = "Orphan"
DELETION_POLICY_DELETE = "Delete"
DEFAULT_DELETION_POLICY = DELETION_POLICY_ORPHAN
DELETE_RETRY_DELAY_SECONDS = 30
_CONDITION_FIELDS = ("type", "status", "reason", "message", "lastTransitionTime")


class KeycloakGroupRoleMappingClient(Protocol):
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
    ) -> KeycloakGroupRoleMappingClient:
        """Create a Keycloak Admin API client."""


class TargetResolver(Protocol):
    def __call__(self, *, target_name: str, namespace: str | None) -> TargetConnection:
        """Resolve Keycloak connection settings for a KeycloakTarget."""


@dataclass(frozen=True)
class RoleReference:
    type: str
    name: str
    client_id: str | None = None


@dataclass(frozen=True)
class GroupRoleMappingSpec:
    target_name: str
    realm: str
    group_name: str
    role: RoleReference
    management_policy: str
    deletion_policy: str


@dataclass(frozen=True)
class MappingReferences:
    group: Mapping[str, Any]
    role: Mapping[str, Any]
    client: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class GroupRoleMappingReconcileResult:
    ready_status: str
    ready_reason: str
    drift_detected: bool
    group_remote_id: str | None = None
    role_remote_id: str | None = None
    client_remote_id: str | None = None


@dataclass(frozen=True)
class MappingDependencyError(Exception):
    reason: str
    message: str


@kopf.on.create(**KEYCLOAK_GROUP_ROLE_MAPPING_RESOURCE)
@kopf.on.update(**KEYCLOAK_GROUP_ROLE_MAPPING_RESOURCE)
@kopf.on.resume(**KEYCLOAK_GROUP_ROLE_MAPPING_RESOURCE)
@periodic_reconciliation(KEYCLOAK_GROUP_ROLE_MAPPING_RESOURCE)
def reconcile_keycloak_group_role_mapping(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Observe or assign a group role mapping and patch status."""
    retry = patch_keycloak_group_role_mapping_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )
    discard_unchanged_status_patch(patch, status)
    if retry is None:
        _emit_reconcile_event(body, status=status, patch=patch)
    raise_for_retry(retry, body=body)


@kopf.on.delete(**KEYCLOAK_GROUP_ROLE_MAPPING_RESOURCE)
def delete_keycloak_group_role_mapping(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Remove the remote group role mapping when requested by policy."""
    deletion_policy = delete_keycloak_group_role_mapping_resource(
        spec=spec,
        namespace=namespace,
    )
    _emit_delete_event(body, deletion_policy)


def delete_keycloak_group_role_mapping_resource(
    *,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
) -> str:
    """Remove the remote group role mapping when deletionPolicy is Delete."""
    mapping_spec = _parse_group_role_mapping_spec(spec)
    if mapping_spec is None:
        raise kopf.PermanentError(
            "KeycloakGroupRoleMapping deletion skipped because spec is invalid."
        )

    if mapping_spec.deletion_policy == DELETION_POLICY_ORPHAN:
        return DELETION_POLICY_ORPHAN

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=mapping_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        raise _delete_temporary_error(
            "KeycloakGroupRoleMapping deletion is waiting for the referenced "
            "KeycloakTarget."
        ) from None

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        delete_keycloak_group_role_mapping_if_exists(keycloak_client, mapping_spec)
        return DELETION_POLICY_DELETE
    except KeycloakAuthenticationError:
        raise _delete_temporary_error(
            "KeycloakGroupRoleMapping deletion failed because Keycloak authentication "
            "failed."
        ) from None
    except KeycloakClientError:
        raise _delete_temporary_error(
            "KeycloakGroupRoleMapping deletion failed while calling the Keycloak "
            "Admin API."
        ) from None


def patch_keycloak_group_role_mapping_status(
    *,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
    now: datetime | None = None,
) -> RetryRequest | None:
    """Patch KeycloakGroupRoleMapping status after reconciliation."""
    existing_conditions = _existing_conditions(status)
    mapping_spec = _parse_group_role_mapping_spec(spec)

    if mapping_spec is None:
        _set_remote_ids(patch, None, None, None)
        _set_blocked_conditions(
            patch,
            existing_conditions,
            _invalid_spec_condition(spec, now=now),
            "Drift detection was skipped because the KeycloakGroupRoleMapping "
            "spec is invalid.",
            now=now,
        )
        return None

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=mapping_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        retry = RetryRequest(
            TARGET_UNAVAILABLE_REASON,
            "KeycloakGroupRoleMapping is not ready because the referenced "
            "KeycloakTarget could not be resolved.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition("False", retry.reason, retry.message, now=now),
            "Drift detection was skipped because the referenced KeycloakTarget "
            "could not be resolved.",
            now=now,
        )
        _set_remote_ids(patch, None, None, None)
        return retry

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        reconcile_result = ensure_keycloak_group_role_mapping(
            keycloak_client,
            mapping_spec,
        )
    except MappingDependencyError as exc:
        retry = RetryRequest(exc.reason, exc.message)
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition("False", retry.reason, retry.message, now=now),
            "Drift detection was skipped because a referenced Keycloak object is "
            "missing.",
            now=now,
        )
        _set_remote_ids(patch, None, None, None)
        return retry
    except KeycloakAuthenticationError:
        retry = RetryRequest(
            AUTHENTICATION_FAILED_REASON,
            "KeycloakGroupRoleMapping is not ready because Keycloak authentication "
            "failed.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition("False", retry.reason, retry.message, now=now),
            "Drift detection was skipped because Keycloak authentication failed.",
            now=now,
        )
        _set_remote_ids(patch, None, None, None)
        return retry
    except KeycloakClientError:
        retry = RetryRequest(
            REQUEST_FAILED_REASON,
            "KeycloakGroupRoleMapping reconciliation failed while calling the "
            "Keycloak Admin API.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition("False", retry.reason, retry.message, now=now),
            "Drift detection failed while calling the Keycloak Admin API.",
            now=now,
        )
        _set_remote_ids(patch, None, None, None)
        return retry

    _set_remote_ids(
        patch,
        reconcile_result.group_remote_id,
        reconcile_result.role_remote_id,
        reconcile_result.client_remote_id,
    )
    _set_conditions(
        patch,
        existing_conditions,
        (
            _group_role_mapping_ready_condition(reconcile_result, now=now),
            _group_role_mapping_drift_condition(reconcile_result, now=now),
        ),
    )
    return None


def ensure_keycloak_group_role_mapping(
    client: KeycloakGroupRoleMappingClient,
    mapping_spec: GroupRoleMappingSpec,
) -> GroupRoleMappingReconcileResult:
    """Assign or observe a group role mapping and return the result."""
    references = _resolve_mapping_references(client, mapping_spec)
    group_id = _required_remote_id(references.group, "group")
    role_id = _required_remote_id(references.role, "role")
    client_id = _remote_id(references.client) if references.client is not None else None

    if _group_role_mapping_exists(client, mapping_spec, references):
        return GroupRoleMappingReconcileResult(
            "True",
            GROUP_ROLE_MAPPING_OBSERVED_REASON,
            False,
            group_id,
            role_id,
            client_id,
        )

    if mapping_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
        return GroupRoleMappingReconcileResult(
            "False",
            GROUP_ROLE_MAPPING_MISSING_REASON,
            True,
            group_id,
            role_id,
            client_id,
        )

    client.request(
        "POST",
        _role_mapping_path(mapping_spec.realm, references),
        json=[_role_mapping_payload(references.role)],
    )
    return GroupRoleMappingReconcileResult(
        "True",
        GROUP_ROLE_MAPPING_ASSIGNED_REASON,
        False,
        group_id,
        role_id,
        client_id,
    )


def delete_keycloak_group_role_mapping_if_exists(
    client: KeycloakGroupRoleMappingClient,
    mapping_spec: GroupRoleMappingSpec,
) -> None:
    """Remove an existing group role mapping or no-op when it is already absent."""
    try:
        references = _resolve_mapping_references(client, mapping_spec)
    except MappingDependencyError:
        return

    if not _group_role_mapping_exists(client, mapping_spec, references):
        return

    client.request(
        "DELETE",
        _role_mapping_path(mapping_spec.realm, references),
        json=[_role_mapping_payload(references.role)],
    )


def _resolve_mapping_references(
    client: KeycloakGroupRoleMappingClient,
    mapping_spec: GroupRoleMappingSpec,
) -> MappingReferences:
    group = _find_group(client, mapping_spec.realm, mapping_spec.group_name)
    if group is None:
        raise MappingDependencyError(
            GROUP_MISSING_REASON,
            "KeycloakGroupRoleMapping is waiting for the referenced Keycloak group.",
        )

    if mapping_spec.role.type == ROLE_TYPE_REALM_ROLE:
        role = _find_realm_role(client, mapping_spec.realm, mapping_spec.role.name)
        if role is None:
            raise MappingDependencyError(
                ROLE_MISSING_REASON,
                "KeycloakGroupRoleMapping is waiting for the referenced realm role.",
            )
        return MappingReferences(group=group, role=role)

    client_ref = _find_client(client, mapping_spec.realm, mapping_spec.role.client_id or "")
    if client_ref is None:
        raise MappingDependencyError(
            CLIENT_MISSING_REASON,
            "KeycloakGroupRoleMapping is waiting for the referenced client.",
        )

    client_id = _required_remote_id(client_ref, "client")
    role = _find_client_role(
        client,
        mapping_spec.realm,
        client_id,
        mapping_spec.role.name,
    )
    if role is None:
        raise MappingDependencyError(
            ROLE_MISSING_REASON,
            "KeycloakGroupRoleMapping is waiting for the referenced client role.",
        )

    return MappingReferences(group=group, role=role, client=client_ref)


def _group_role_mapping_exists(
    client: KeycloakGroupRoleMappingClient,
    mapping_spec: GroupRoleMappingSpec,
    references: MappingReferences,
) -> bool:
    assigned_roles = client.request(
        "GET",
        _role_mapping_path(mapping_spec.realm, references),
    )
    if not isinstance(assigned_roles, list):
        raise KeycloakRequestError("Keycloak group role mappings response was not a list")

    return _role_present(assigned_roles, references.role)


def _role_mapping_payload(role: Mapping[str, Any]) -> dict[str, Any]:
    role_id = _required_remote_id(role, "role")
    role_name = role.get("name")
    if not _is_non_empty_string(role_name):
        raise KeycloakRequestError("Keycloak role lookup response did not include name")

    return {"id": role_id, "name": role_name.strip()}


def _role_present(assigned_roles: Sequence[Any], role: Mapping[str, Any]) -> bool:
    role_id = _remote_id(role)
    role_name = role.get("name")
    for assigned_role in assigned_roles:
        if not isinstance(assigned_role, Mapping):
            continue

        if role_id is not None and assigned_role.get("id") == role_id:
            return True

        if _is_non_empty_string(role_name) and assigned_role.get("name") == role_name:
            return True

    return False


def _find_group(
    client: KeycloakGroupRoleMappingClient,
    realm: str,
    group_name: str,
) -> Mapping[str, Any] | None:
    groups = client.request(
        "GET",
        _groups_path(realm),
        params={"search": group_name, "exact": "true"},
    )
    if not isinstance(groups, list):
        raise KeycloakRequestError("Keycloak group lookup response was not a list")

    return _matching_group(groups, group_name)


def _find_realm_role(
    client: KeycloakGroupRoleMappingClient,
    realm: str,
    role_name: str,
) -> Mapping[str, Any] | None:
    try:
        role = client.request("GET", _realm_role_path(realm, role_name))
    except KeycloakResourceNotFoundError:
        return None

    if not isinstance(role, Mapping):
        raise KeycloakRequestError("Keycloak realm role lookup response was not an object")

    return role


def _find_client(
    client: KeycloakGroupRoleMappingClient,
    realm: str,
    client_id: str,
) -> Mapping[str, Any] | None:
    clients = client.request(
        "GET",
        _clients_path(realm),
        params={"clientId": client_id},
    )
    if not isinstance(clients, list):
        raise KeycloakRequestError("Keycloak client lookup response was not a list")

    for candidate in clients:
        if isinstance(candidate, Mapping) and candidate.get("clientId") == client_id:
            return candidate

    return None


def _find_client_role(
    client: KeycloakGroupRoleMappingClient,
    realm: str,
    client_internal_id: str,
    role_name: str,
) -> Mapping[str, Any] | None:
    try:
        role = client.request("GET", _client_role_path(realm, client_internal_id, role_name))
    except KeycloakResourceNotFoundError:
        return None

    if not isinstance(role, Mapping):
        raise KeycloakRequestError("Keycloak client role lookup response was not an object")

    return role


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


def _parse_group_role_mapping_spec(
    spec: Mapping[str, Any] | None,
) -> GroupRoleMappingSpec | None:
    if not isinstance(spec, Mapping):
        return None

    target_ref = spec.get("targetRef")
    target_name = target_ref.get("name") if isinstance(target_ref, Mapping) else None
    group_ref = spec.get("groupRef")
    group_name = group_ref.get("name") if isinstance(group_ref, Mapping) else None
    realm = spec.get("realm")
    role = _parse_role_reference(spec.get("role"))
    management_policy = spec.get("managementPolicy", DEFAULT_MANAGEMENT_POLICY)
    deletion_policy = spec.get("deletionPolicy", DEFAULT_DELETION_POLICY)

    if (
        not _is_non_empty_string(target_name)
        or not _is_non_empty_string(realm)
        or not _is_non_empty_string(group_name)
        or role is None
    ):
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

    return GroupRoleMappingSpec(
        target_name=target_name.strip(),
        realm=realm.strip(),
        group_name=group_name.strip(),
        role=role,
        management_policy=parsed_management_policy,
        deletion_policy=parsed_deletion_policy,
    )


def _parse_role_reference(role: Any) -> RoleReference | None:
    if not isinstance(role, Mapping):
        return None

    role_type = role.get("type")
    role_ref = role.get("roleRef")
    role_name = role_ref.get("name") if isinstance(role_ref, Mapping) else None
    client_ref = role.get("clientRef")
    client_id = client_ref.get("name") if isinstance(client_ref, Mapping) else None

    if not _is_non_empty_string(role_type) or not _is_non_empty_string(role_name):
        return None

    parsed_role_type = role_type.strip()
    if parsed_role_type == ROLE_TYPE_REALM_ROLE:
        if client_ref is not None:
            return None
        return RoleReference(parsed_role_type, role_name.strip())

    if parsed_role_type == ROLE_TYPE_CLIENT_ROLE and _is_non_empty_string(client_id):
        return RoleReference(parsed_role_type, role_name.strip(), client_id.strip())

    return None


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
            f"Missing required KeycloakGroupRoleMapping spec fields: {fields}.",
            now=now,
        )

    invalid_fields = _invalid_spec_fields(spec)
    if invalid_fields:
        return ready_condition(
            "False",
            INVALID_SPEC_REASON,
            invalid_spec_message("KeycloakGroupRoleMapping", invalid_fields),
            now=now,
        )

    return ready_condition(
        "False",
        INVALID_SPEC_REASON,
        "KeycloakGroupRoleMapping spec is invalid.",
        now=now,
    )


def _missing_required_fields(spec: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(spec, Mapping):
        return ["spec"]

    missing_fields: list[str] = []
    target_ref = spec.get("targetRef")
    target_name = target_ref.get("name") if isinstance(target_ref, Mapping) else None
    group_ref = spec.get("groupRef")
    group_name = group_ref.get("name") if isinstance(group_ref, Mapping) else None
    role = spec.get("role")
    role_type = role.get("type") if isinstance(role, Mapping) else None
    role_ref = role.get("roleRef") if isinstance(role, Mapping) else None
    role_name = role_ref.get("name") if isinstance(role_ref, Mapping) else None
    client_ref = role.get("clientRef") if isinstance(role, Mapping) else None
    client_name = client_ref.get("name") if isinstance(client_ref, Mapping) else None

    if not _is_non_empty_string(target_name):
        missing_fields.append("targetRef.name")
    if not _is_non_empty_string(spec.get("realm")):
        missing_fields.append("realm")
    if not _is_non_empty_string(group_name):
        missing_fields.append("groupRef.name")
    if not _is_non_empty_string(role_type):
        missing_fields.append("role.type")
    if not _is_non_empty_string(role_name):
        missing_fields.append("role.roleRef.name")
    if role_type == ROLE_TYPE_CLIENT_ROLE and not _is_non_empty_string(client_name):
        missing_fields.append("role.clientRef.name")

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
        _role_type_field_error(spec),
        _realm_role_client_ref_error(spec),
    ]

    return [error for error in errors if error is not None]


def _role_type_field_error(spec: Mapping[str, Any]) -> str | None:
    role = spec.get("role")
    if not isinstance(role, Mapping) or "type" not in role:
        return None

    role_type = role.get("type")
    if isinstance(role_type, str) and role_type.strip() in {
        ROLE_TYPE_REALM_ROLE,
        ROLE_TYPE_CLIENT_ROLE,
    }:
        return None

    return "role.type must be one of: `ClientRole`, `RealmRole`"


def _realm_role_client_ref_error(spec: Mapping[str, Any]) -> str | None:
    role = spec.get("role")
    if not isinstance(role, Mapping):
        return None

    role_type = role.get("type")
    if role_type != ROLE_TYPE_REALM_ROLE or "clientRef" not in role:
        return None

    return "role.clientRef is only supported when role.type is `ClientRole`"


def _group_role_mapping_ready_condition(
    reconcile_result: GroupRoleMappingReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if reconcile_result.ready_reason == GROUP_ROLE_MAPPING_ASSIGNED_REASON:
        message = "Keycloak group role mapping was assigned."
    elif reconcile_result.ready_reason == GROUP_ROLE_MAPPING_MISSING_REASON:
        message = (
            "Keycloak group role mapping is missing and was not assigned because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = "Keycloak group role mapping already exists."

    return ready_condition(
        reconcile_result.ready_status,
        reconcile_result.ready_reason,
        message,
        now=now,
    )


def _group_role_mapping_drift_condition(
    reconcile_result: GroupRoleMappingReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if not reconcile_result.drift_detected:
        return drift_detected_condition(
            "False",
            NO_DRIFT_DETECTED_REASON,
            "Keycloak group role mapping has no modeled drift.",
            now=now,
        )

    return drift_detected_condition(
        "True",
        reconcile_result.ready_reason,
        (
            "Keycloak group role mapping is missing and was not assigned because "
            "managementPolicy is ObserveOnly."
        ),
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


def _set_remote_ids(
    patch: MutableMapping[str, Any],
    group_remote_id: str | None,
    role_remote_id: str | None,
    client_remote_id: str | None,
) -> None:
    status_patch = patch.setdefault("status", {})
    status_patch["groupRemoteId"] = group_remote_id
    status_patch["roleRemoteId"] = role_remote_id
    status_patch["clientRemoteId"] = client_remote_id


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
            GROUP_ROLE_MAPPING_ASSIGNED_REASON: (
                "Normal",
                "Keycloak group role mapping was assigned.",
            ),
            GROUP_ROLE_MAPPING_MISSING_REASON: (
                "Warning",
                "Keycloak group role mapping is missing and was left unchanged.",
            ),
        },
    )


def _emit_delete_event(body: kopf.Body, deletion_policy: str) -> None:
    if deletion_policy == DELETION_POLICY_DELETE:
        kopf.event(
            body,
            type="Normal",
            reason="GroupRoleMappingDeleted",
            message=(
                "Keycloak group role mapping was removed because deletionPolicy is "
                "Delete."
            ),
        )
        return

    kopf.event(
        body,
        type="Normal",
        reason=GROUP_ROLE_MAPPING_ORPHANED_REASON,
        message=(
            "Keycloak group role mapping was left in Keycloak because deletionPolicy "
            "is Orphan."
        ),
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


def _role_mapping_path(
    realm: str,
    references: MappingReferences,
) -> str:
    group_id = _required_remote_id(references.group, "group")
    if references.client is None:
        return f"{_group_role_mappings_path(realm, group_id)}/realm"

    client_id = _required_remote_id(references.client, "client")
    return f"{_group_role_mappings_path(realm, group_id)}/clients/{quote(client_id, safe='')}"


def _group_role_mappings_path(realm: str, group_id: str) -> str:
    return f"{_groups_path(realm)}/{quote(group_id, safe='')}/role-mappings"


def _groups_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}/groups"


def _clients_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}/clients"


def _realm_role_path(realm: str, role_name: str) -> str:
    return f"realms/{quote(realm, safe='')}/roles/{quote(role_name, safe='')}"


def _client_role_path(realm: str, client_internal_id: str, role_name: str) -> str:
    return (
        f"{_clients_path(realm)}/{quote(client_internal_id, safe='')}/roles/"
        f"{quote(role_name, safe='')}"
    )


def _required_remote_id(payload: Mapping[str, Any], label: str) -> str:
    remote_id = _remote_id(payload)
    if remote_id is None:
        raise KeycloakRequestError(f"Keycloak {label} lookup response did not include id")

    return remote_id


def _remote_id(payload: Mapping[str, Any] | None) -> str | None:
    if payload is None:
        return None

    remote_id = payload.get("id")
    return remote_id.strip() if _is_non_empty_string(remote_id) else None


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
