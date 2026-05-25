"""Kopf handlers for KeycloakClientScope resources."""

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
    KEYCLOAK_CLIENT_SCOPE_PLURAL,
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
    ready_condition,
    upsert_condition,
)

KEYCLOAK_CLIENT_SCOPE_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_CLIENT_SCOPE_PLURAL,
}

AUTHENTICATION_FAILED_REASON = "AuthenticationFailed"
CLIENT_SCOPE_CREATED_REASON = "ClientScopeCreated"
CLIENT_SCOPE_DRIFT_DETECTED_REASON = "ClientScopeDriftDetected"
CLIENT_SCOPE_MISSING_REASON = "ClientScopeMissing"
CLIENT_SCOPE_OBSERVED_REASON = "ClientScopeObserved"
CLIENT_SCOPE_ORPHANED_REASON = "ClientScopeOrphaned"
CLIENT_SCOPE_UPDATED_REASON = "ClientScopeUpdated"
DEFAULT_PROTOCOL = "openid-connect"
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


class KeycloakClientScopeClient(Protocol):
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
    ) -> KeycloakClientScopeClient:
        """Create a Keycloak Admin API client."""


class TargetResolver(Protocol):
    def __call__(self, *, target_name: str, namespace: str | None) -> TargetConnection:
        """Resolve Keycloak connection settings for a KeycloakTarget."""


@dataclass(frozen=True)
class ClientScopeSpec:
    target_name: str
    realm: str
    name: str
    management_policy: str
    deletion_policy: str
    protocol: str = DEFAULT_PROTOCOL
    description: str | None = None


@dataclass(frozen=True)
class ClientScopeReconcileResult:
    ready_status: str
    ready_reason: str
    drift_detected: bool
    remote_id: str | None = None


@kopf.on.create(**KEYCLOAK_CLIENT_SCOPE_RESOURCE)
@kopf.on.update(**KEYCLOAK_CLIENT_SCOPE_RESOURCE)
@kopf.on.resume(**KEYCLOAK_CLIENT_SCOPE_RESOURCE)
def reconcile_keycloak_client_scope(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Observe, create, or update a realm client scope and patch status."""
    retry = patch_keycloak_client_scope_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )
    if retry is None:
        _emit_reconcile_event(body, status=status, patch=patch)
    raise_for_retry(retry, body=body)


@kopf.on.delete(**KEYCLOAK_CLIENT_SCOPE_RESOURCE)
def delete_keycloak_client_scope(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Delete the remote Keycloak client scope when requested by policy."""
    deletion_policy = delete_keycloak_client_scope_resource(spec=spec, namespace=namespace)
    _emit_delete_event(body, deletion_policy)


def delete_keycloak_client_scope_resource(
    *,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
) -> str:
    """Delete the remote Keycloak client scope when deletionPolicy is Delete."""
    client_scope_spec = _parse_client_scope_spec(spec)
    if client_scope_spec is None:
        raise kopf.PermanentError(
            "KeycloakClientScope deletion skipped because spec is invalid."
        )

    if client_scope_spec.deletion_policy == DELETION_POLICY_ORPHAN:
        return DELETION_POLICY_ORPHAN

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=client_scope_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        raise _delete_temporary_error(
            "KeycloakClientScope deletion is waiting for the referenced KeycloakTarget."
        ) from None

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        delete_keycloak_client_scope_if_exists(keycloak_client, client_scope_spec)
        return DELETION_POLICY_DELETE
    except KeycloakAuthenticationError:
        raise _delete_temporary_error(
            "KeycloakClientScope deletion failed because Keycloak authentication failed."
        ) from None
    except KeycloakClientError:
        raise _delete_temporary_error(
            "KeycloakClientScope deletion failed while calling the Keycloak Admin API."
        ) from None


def patch_keycloak_client_scope_status(
    *,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
    now: datetime | None = None,
) -> RetryRequest | None:
    """Patch KeycloakClientScope status after observing, creating, or updating it."""
    existing_conditions = _existing_conditions(status)
    client_scope_spec = _parse_client_scope_spec(spec)

    if client_scope_spec is None:
        _set_remote_id(patch, None)
        _set_ready_condition(
            patch,
            existing_conditions,
            _invalid_spec_condition(spec, now=now),
        )
        return None

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=client_scope_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        retry = RetryRequest(
            TARGET_UNAVAILABLE_REASON,
            "KeycloakClientScope is not ready because the referenced KeycloakTarget "
            "could not be resolved.",
        )
        _set_ready_condition(
            patch,
            existing_conditions,
            ready_condition(
                "False",
                retry.reason,
                retry.message,
                now=now,
            ),
        )
        _set_remote_id(patch, None)
        return retry

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        reconcile_result = ensure_keycloak_client_scope(keycloak_client, client_scope_spec)
    except KeycloakAuthenticationError:
        retry = RetryRequest(
            AUTHENTICATION_FAILED_REASON,
            "KeycloakClientScope is not ready because Keycloak authentication failed.",
        )
        _set_ready_condition(
            patch,
            existing_conditions,
            ready_condition(
                "False",
                retry.reason,
                retry.message,
                now=now,
            ),
        )
        _set_remote_id(patch, None)
        return retry
    except KeycloakClientError:
        retry = RetryRequest(
            REQUEST_FAILED_REASON,
            "KeycloakClientScope reconciliation failed while calling the Keycloak Admin API.",
        )
        _set_ready_condition(
            patch,
            existing_conditions,
            ready_condition(
                "False",
                retry.reason,
                retry.message,
                now=now,
            ),
        )
        _set_remote_id(patch, None)
        return retry

    _set_remote_id(patch, reconcile_result.remote_id)
    _set_conditions(
        patch,
        existing_conditions,
        (
            _client_scope_ready_condition(reconcile_result, now=now),
            _client_scope_drift_condition(reconcile_result, now=now),
        ),
    )
    return None


def ensure_keycloak_client_scope(
    client: KeycloakClientScopeClient,
    client_scope_spec: ClientScopeSpec,
) -> ClientScopeReconcileResult:
    """Create, update, or observe a realm client scope and return the result."""
    client_scopes = client.request("GET", _client_scopes_path(client_scope_spec.realm))
    if not isinstance(client_scopes, list):
        raise KeycloakRequestError("Keycloak client scope lookup response was not a list")

    existing_client_scope = _matching_client_scope(client_scopes, client_scope_spec.name)
    if existing_client_scope is None:
        if client_scope_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
            return ClientScopeReconcileResult(
                "False",
                CLIENT_SCOPE_MISSING_REASON,
                True,
            )

        client.request(
            "POST",
            _client_scopes_path(client_scope_spec.realm),
            json=_modeled_client_scope_payload(client_scope_spec),
        )
        client_scopes = client.request("GET", _client_scopes_path(client_scope_spec.realm))
        if not isinstance(client_scopes, list):
            raise KeycloakRequestError("Keycloak client scope lookup response was not a list")

        created_client_scope = _matching_client_scope(client_scopes, client_scope_spec.name)
        return ClientScopeReconcileResult(
            "True",
            CLIENT_SCOPE_CREATED_REASON,
            False,
            _remote_id(created_client_scope) if created_client_scope is not None else None,
        )

    if not _has_modeled_drift(existing_client_scope, client_scope_spec):
        return ClientScopeReconcileResult(
            "True",
            CLIENT_SCOPE_OBSERVED_REASON,
            False,
            _remote_id(existing_client_scope),
        )

    if client_scope_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
        return ClientScopeReconcileResult(
            "True",
            CLIENT_SCOPE_DRIFT_DETECTED_REASON,
            True,
            _remote_id(existing_client_scope),
        )

    internal_id = existing_client_scope.get("id")
    if not _is_non_empty_string(internal_id):
        raise KeycloakRequestError("Keycloak client scope lookup response did not include id")

    client.request(
        "PUT",
        _client_scope_path(client_scope_spec.realm, internal_id.strip()),
        json=_client_scope_update_payload(existing_client_scope, client_scope_spec),
    )
    return ClientScopeReconcileResult(
        "True",
        CLIENT_SCOPE_UPDATED_REASON,
        False,
        internal_id.strip(),
    )


def delete_keycloak_client_scope_if_exists(
    client: KeycloakClientScopeClient,
    client_scope_spec: ClientScopeSpec,
) -> None:
    """Delete an existing Keycloak client scope or no-op when it is already missing."""
    client_scopes = client.request("GET", _client_scopes_path(client_scope_spec.realm))
    if not isinstance(client_scopes, list):
        raise KeycloakRequestError("Keycloak client scope lookup response was not a list")

    existing_client_scope = _matching_client_scope(client_scopes, client_scope_spec.name)
    if existing_client_scope is None:
        return

    internal_id = existing_client_scope.get("id")
    if not _is_non_empty_string(internal_id):
        raise KeycloakRequestError("Keycloak client scope lookup response did not include id")

    client.request("DELETE", _client_scope_path(client_scope_spec.realm, internal_id.strip()))


def _modeled_client_scope_payload(client_scope_spec: ClientScopeSpec) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": client_scope_spec.name,
        "protocol": client_scope_spec.protocol,
    }
    if client_scope_spec.description is not None:
        payload["description"] = client_scope_spec.description

    return payload


def _has_modeled_drift(
    existing_client_scope: Mapping[str, Any],
    client_scope_spec: ClientScopeSpec,
) -> bool:
    desired_payload = _modeled_client_scope_payload(client_scope_spec)
    return any(
        existing_client_scope.get(field) != desired_value
        for field, desired_value in desired_payload.items()
    )


def _client_scope_update_payload(
    existing_client_scope: Mapping[str, Any],
    client_scope_spec: ClientScopeSpec,
) -> dict[str, Any]:
    payload = dict(existing_client_scope)
    payload.update(_modeled_client_scope_payload(client_scope_spec))
    return payload


def _remote_id(payload: Mapping[str, Any]) -> str | None:
    remote_id = payload.get("id")
    return remote_id.strip() if _is_non_empty_string(remote_id) else None


def _matching_client_scope(
    client_scopes: Sequence[Any],
    client_scope_name: str,
) -> Mapping[str, Any] | None:
    for candidate in client_scopes:
        if isinstance(candidate, Mapping) and candidate.get("name") == client_scope_name:
            return candidate

    return None


def _parse_client_scope_spec(spec: Mapping[str, Any] | None) -> ClientScopeSpec | None:
    if not isinstance(spec, Mapping):
        return None

    target_ref = spec.get("targetRef")
    target_name = target_ref.get("name") if isinstance(target_ref, Mapping) else None
    realm = spec.get("realm")
    name = spec.get("name")
    protocol = spec.get("protocol", DEFAULT_PROTOCOL)
    management_policy = spec.get("managementPolicy", DEFAULT_MANAGEMENT_POLICY)
    deletion_policy = spec.get("deletionPolicy", DEFAULT_DELETION_POLICY)
    description = spec.get("description")

    if (
        not _is_non_empty_string(target_name)
        or not _is_non_empty_string(realm)
        or not _is_non_empty_string(name)
    ):
        return None

    if not _is_non_empty_string(protocol):
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

    return ClientScopeSpec(
        target_name=target_name.strip(),
        realm=realm.strip(),
        name=name.strip(),
        management_policy=parsed_management_policy,
        deletion_policy=parsed_deletion_policy,
        protocol=protocol.strip(),
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
            f"Missing required KeycloakClientScope spec fields: {fields}.",
            now=now,
        )

    return ready_condition(
        "False",
        INVALID_SPEC_REASON,
        "KeycloakClientScope spec is invalid.",
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


def _client_scope_ready_condition(
    reconcile_result: ClientScopeReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if reconcile_result.ready_reason == CLIENT_SCOPE_CREATED_REASON:
        message = "Keycloak client scope was created."
    elif reconcile_result.ready_reason == CLIENT_SCOPE_UPDATED_REASON:
        message = "Keycloak client scope was updated."
    elif reconcile_result.ready_reason == CLIENT_SCOPE_DRIFT_DETECTED_REASON:
        message = (
            "Keycloak client scope has modeled drift and was not changed because "
            "managementPolicy is ObserveOnly."
        )
    elif reconcile_result.ready_reason == CLIENT_SCOPE_MISSING_REASON:
        message = (
            "Keycloak client scope is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = "Keycloak client scope already matches desired state."

    return ready_condition(
        reconcile_result.ready_status,
        reconcile_result.ready_reason,
        message,
        now=now,
    )


def _client_scope_drift_condition(
    reconcile_result: ClientScopeReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if not reconcile_result.drift_detected:
        return drift_detected_condition(
            "False",
            NO_DRIFT_DETECTED_REASON,
            "Keycloak client scope has no modeled drift.",
            now=now,
        )

    if reconcile_result.ready_reason == CLIENT_SCOPE_MISSING_REASON:
        message = (
            "Keycloak client scope is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = (
            "Keycloak client scope differs from desired state and was not changed "
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


def _set_ready_condition(
    patch: MutableMapping[str, Any],
    existing_conditions: Sequence[Mapping[str, str]],
    condition: Mapping[str, str],
) -> None:
    _set_conditions(patch, existing_conditions, (condition,))


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
            CLIENT_SCOPE_CREATED_REASON: ("Normal", "Keycloak client scope was created."),
            CLIENT_SCOPE_UPDATED_REASON: ("Normal", "Keycloak client scope was updated."),
            CLIENT_SCOPE_DRIFT_DETECTED_REASON: (
                "Warning",
                "Keycloak client scope has modeled drift and was left unchanged.",
            ),
            CLIENT_SCOPE_MISSING_REASON: (
                "Warning",
                "Keycloak client scope is missing and was left unchanged.",
            ),
        },
    )


def _emit_delete_event(body: kopf.Body, deletion_policy: str) -> None:
    if deletion_policy == DELETION_POLICY_DELETE:
        kopf.event(
            body,
            type="Normal",
            reason="ClientScopeDeleted",
            message="Keycloak client scope was deleted because deletionPolicy is Delete.",
        )
        return

    kopf.event(
        body,
        type="Normal",
        reason=CLIENT_SCOPE_ORPHANED_REASON,
        message="Keycloak client scope was left in Keycloak because deletionPolicy is Orphan.",
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


def _client_scopes_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}/client-scopes"


def _client_scope_path(realm: str, internal_id: str) -> str:
    return f"{_client_scopes_path(realm)}/{quote(internal_id, safe='')}"


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
