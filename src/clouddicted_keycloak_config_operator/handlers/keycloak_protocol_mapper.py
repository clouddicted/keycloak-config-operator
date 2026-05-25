"""Kopf handlers for KeycloakProtocolMapper resources."""

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
    KEYCLOAK_PROTOCOL_MAPPER_PLURAL,
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
)
from clouddicted_keycloak_config_operator.status import (
    CONDITION_READY,
    Condition,
    drift_detected_condition,
    drift_unknown_condition,
    ready_condition,
    upsert_condition,
)

KEYCLOAK_PROTOCOL_MAPPER_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_PROTOCOL_MAPPER_PLURAL,
}

AUTHENTICATION_FAILED_REASON = "AuthenticationFailed"
DEFAULT_PROTOCOL = "openid-connect"
INVALID_SPEC_REASON = "InvalidSpec"
PARENT_TYPE_CLIENT = "Client"
PARENT_TYPE_CLIENT_SCOPE = "ClientScope"
PROTOCOL_MAPPER_CREATED_REASON = "ProtocolMapperCreated"
PROTOCOL_MAPPER_DRIFT_DETECTED_REASON = "ProtocolMapperDriftDetected"
PROTOCOL_MAPPER_MISSING_REASON = "ProtocolMapperMissing"
PROTOCOL_MAPPER_OBSERVED_REASON = "ProtocolMapperObserved"
PROTOCOL_MAPPER_ORPHANED_REASON = "ProtocolMapperOrphaned"
PROTOCOL_MAPPER_UPDATED_REASON = "ProtocolMapperUpdated"
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


class KeycloakProtocolMapperClient(Protocol):
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
    ) -> KeycloakProtocolMapperClient:
        """Create a Keycloak Admin API client."""


class TargetResolver(Protocol):
    def __call__(self, *, target_name: str, namespace: str | None) -> TargetConnection:
        """Resolve Keycloak connection settings for a KeycloakTarget."""


@dataclass(frozen=True)
class ProtocolMapperSpec:
    target_name: str
    realm: str
    name: str
    mapper_type: str
    parent_type: str
    parent_name: str
    management_policy: str
    deletion_policy: str
    protocol: str = DEFAULT_PROTOCOL
    config: Mapping[str, str] | None = None


@dataclass(frozen=True)
class ParentReference:
    type: str
    name: str
    internal_id: str


@dataclass(frozen=True)
class ProtocolMapperReconcileResult:
    ready_status: str
    ready_reason: str
    drift_detected: bool
    remote_id: str | None = None


@kopf.on.create(**KEYCLOAK_PROTOCOL_MAPPER_RESOURCE)
@kopf.on.update(**KEYCLOAK_PROTOCOL_MAPPER_RESOURCE)
@kopf.on.resume(**KEYCLOAK_PROTOCOL_MAPPER_RESOURCE)
def reconcile_keycloak_protocol_mapper(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Observe, create, or update a Keycloak protocol mapper and patch status."""
    retry = patch_keycloak_protocol_mapper_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )
    if retry is None:
        _emit_reconcile_event(body, status=status, patch=patch)
    raise_for_retry(retry, body=body)


@kopf.on.delete(**KEYCLOAK_PROTOCOL_MAPPER_RESOURCE)
def delete_keycloak_protocol_mapper(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Delete the remote Keycloak protocol mapper when requested by policy."""
    deletion_policy = delete_keycloak_protocol_mapper_resource(spec=spec, namespace=namespace)
    _emit_delete_event(body, deletion_policy)


def delete_keycloak_protocol_mapper_resource(
    *,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
) -> str:
    """Delete the remote Keycloak protocol mapper when deletionPolicy is Delete."""
    mapper_spec = _parse_protocol_mapper_spec(spec)
    if mapper_spec is None:
        raise kopf.PermanentError(
            "KeycloakProtocolMapper deletion skipped because spec is invalid."
        )

    if mapper_spec.deletion_policy == DELETION_POLICY_ORPHAN:
        return DELETION_POLICY_ORPHAN

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=mapper_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        raise _delete_temporary_error(
            "KeycloakProtocolMapper deletion is waiting for the referenced KeycloakTarget."
        ) from None

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        delete_keycloak_protocol_mapper_if_exists(keycloak_client, mapper_spec)
        return DELETION_POLICY_DELETE
    except KeycloakAuthenticationError:
        raise _delete_temporary_error(
            "KeycloakProtocolMapper deletion failed because Keycloak authentication failed."
        ) from None
    except KeycloakClientError:
        raise _delete_temporary_error(
            "KeycloakProtocolMapper deletion failed while calling the Keycloak Admin API."
        ) from None


def patch_keycloak_protocol_mapper_status(
    *,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
    now: datetime | None = None,
) -> RetryRequest | None:
    """Patch KeycloakProtocolMapper status after reconciliation."""
    existing_conditions = _existing_conditions(status)
    mapper_spec = _parse_protocol_mapper_spec(spec)

    if mapper_spec is None:
        _set_remote_id(patch, None)
        _set_blocked_conditions(
            patch,
            existing_conditions,
            _invalid_spec_condition(spec, now=now),
            "Drift detection was skipped because the KeycloakProtocolMapper spec is invalid.",
            now=now,
        )
        return None

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=mapper_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        retry = RetryRequest(
            TARGET_UNAVAILABLE_REASON,
            "KeycloakProtocolMapper is not ready because the referenced KeycloakTarget "
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
        reconcile_result = ensure_keycloak_protocol_mapper(keycloak_client, mapper_spec)
    except KeycloakAuthenticationError:
        retry = RetryRequest(
            AUTHENTICATION_FAILED_REASON,
            "KeycloakProtocolMapper is not ready because Keycloak authentication failed.",
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
            "KeycloakProtocolMapper reconciliation failed while calling the Keycloak "
            "Admin API.",
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
            _protocol_mapper_ready_condition(reconcile_result, now=now),
            _protocol_mapper_drift_condition(reconcile_result, now=now),
        ),
    )
    return None


def ensure_keycloak_protocol_mapper(
    client: KeycloakProtocolMapperClient,
    mapper_spec: ProtocolMapperSpec,
) -> ProtocolMapperReconcileResult:
    """Create, update, or observe a protocol mapper and return the result."""
    parent = _resolve_parent_reference(client, mapper_spec)
    mappers = client.request("GET", _protocol_mapper_models_path(mapper_spec.realm, parent))
    if not isinstance(mappers, list):
        raise KeycloakRequestError("Keycloak protocol mapper lookup response was not a list")

    existing_mapper = _matching_protocol_mapper(mappers, mapper_spec.name)
    if existing_mapper is None:
        if mapper_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
            return ProtocolMapperReconcileResult(
                "False",
                PROTOCOL_MAPPER_MISSING_REASON,
                True,
            )

        client.request(
            "POST",
            _protocol_mapper_models_path(mapper_spec.realm, parent),
            json=_modeled_protocol_mapper_payload(mapper_spec),
        )
        mappers = client.request("GET", _protocol_mapper_models_path(mapper_spec.realm, parent))
        if not isinstance(mappers, list):
            raise KeycloakRequestError(
                "Keycloak protocol mapper lookup response was not a list"
            )

        created_mapper = _matching_protocol_mapper(mappers, mapper_spec.name)
        return ProtocolMapperReconcileResult(
            "True",
            PROTOCOL_MAPPER_CREATED_REASON,
            False,
            _remote_id(created_mapper) if created_mapper is not None else None,
        )

    if not _has_modeled_drift(existing_mapper, mapper_spec):
        return ProtocolMapperReconcileResult(
            "True",
            PROTOCOL_MAPPER_OBSERVED_REASON,
            False,
            _remote_id(existing_mapper),
        )

    if mapper_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
        return ProtocolMapperReconcileResult(
            "True",
            PROTOCOL_MAPPER_DRIFT_DETECTED_REASON,
            True,
            _remote_id(existing_mapper),
        )

    mapper_id = existing_mapper.get("id")
    if not _is_non_empty_string(mapper_id):
        raise KeycloakRequestError("Keycloak protocol mapper lookup response did not include id")

    client.request(
        "PUT",
        _protocol_mapper_model_path(mapper_spec.realm, parent, mapper_id.strip()),
        json=_protocol_mapper_update_payload(existing_mapper, mapper_spec),
    )
    return ProtocolMapperReconcileResult(
        "True",
        PROTOCOL_MAPPER_UPDATED_REASON,
        False,
        mapper_id.strip(),
    )


def delete_keycloak_protocol_mapper_if_exists(
    client: KeycloakProtocolMapperClient,
    mapper_spec: ProtocolMapperSpec,
) -> None:
    """Delete an existing Keycloak protocol mapper or no-op when it is already missing."""
    parent = _resolve_parent_reference(client, mapper_spec)
    mappers = client.request("GET", _protocol_mapper_models_path(mapper_spec.realm, parent))
    if not isinstance(mappers, list):
        raise KeycloakRequestError("Keycloak protocol mapper lookup response was not a list")

    existing_mapper = _matching_protocol_mapper(mappers, mapper_spec.name)
    if existing_mapper is None:
        return

    mapper_id = existing_mapper.get("id")
    if not _is_non_empty_string(mapper_id):
        raise KeycloakRequestError("Keycloak protocol mapper lookup response did not include id")

    client.request(
        "DELETE",
        _protocol_mapper_model_path(mapper_spec.realm, parent, mapper_id.strip()),
    )


def _resolve_parent_reference(
    client: KeycloakProtocolMapperClient,
    mapper_spec: ProtocolMapperSpec,
) -> ParentReference:
    if mapper_spec.parent_type == PARENT_TYPE_CLIENT:
        clients = client.request(
            "GET",
            _clients_path(mapper_spec.realm),
            params={"clientId": mapper_spec.parent_name},
        )
        if not isinstance(clients, list):
            raise KeycloakRequestError("Keycloak client lookup response was not a list")

        parent = _matching_client(clients, mapper_spec.parent_name)
        if parent is None:
            raise KeycloakRequestError("Keycloak protocol mapper parent client was not found")

    else:
        client_scopes = client.request("GET", _client_scopes_path(mapper_spec.realm))
        if not isinstance(client_scopes, list):
            raise KeycloakRequestError("Keycloak client scope lookup response was not a list")

        parent = _matching_client_scope(client_scopes, mapper_spec.parent_name)
        if parent is None:
            raise KeycloakRequestError(
                "Keycloak protocol mapper parent client scope was not found"
            )

    internal_id = parent.get("id")
    if not _is_non_empty_string(internal_id):
        raise KeycloakRequestError("Keycloak protocol mapper parent did not include id")

    return ParentReference(
        type=mapper_spec.parent_type,
        name=mapper_spec.parent_name,
        internal_id=internal_id.strip(),
    )


def _modeled_protocol_mapper_payload(mapper_spec: ProtocolMapperSpec) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": mapper_spec.name,
        "protocol": mapper_spec.protocol,
        "protocolMapper": mapper_spec.mapper_type,
    }
    if mapper_spec.config:
        payload["config"] = dict(mapper_spec.config)

    return payload


def _has_modeled_drift(
    existing_mapper: Mapping[str, Any],
    mapper_spec: ProtocolMapperSpec,
) -> bool:
    desired_payload = _modeled_protocol_mapper_payload(mapper_spec)
    for field, desired_value in desired_payload.items():
        if field == "config":
            if not _modeled_config_matches(existing_mapper.get("config"), desired_value):
                return True
        elif existing_mapper.get(field) != desired_value:
            return True

    return False


def _modeled_config_matches(existing_config: Any, desired_config: Any) -> bool:
    if not isinstance(desired_config, Mapping):
        return existing_config == desired_config

    if not isinstance(existing_config, Mapping):
        return False

    return all(existing_config.get(key) == value for key, value in desired_config.items())


def _protocol_mapper_update_payload(
    existing_mapper: Mapping[str, Any],
    mapper_spec: ProtocolMapperSpec,
) -> dict[str, Any]:
    payload = dict(existing_mapper)
    payload.update(_modeled_protocol_mapper_payload(mapper_spec))

    if mapper_spec.config:
        existing_config = existing_mapper.get("config")
        config_payload = dict(existing_config) if isinstance(existing_config, Mapping) else {}
        config_payload.update(mapper_spec.config)
        payload["config"] = config_payload

    return payload


def _matching_protocol_mapper(
    mappers: Sequence[Any],
    mapper_name: str,
) -> Mapping[str, Any] | None:
    for candidate in mappers:
        if isinstance(candidate, Mapping) and candidate.get("name") == mapper_name:
            return candidate

    return None


def _remote_id(payload: Mapping[str, Any]) -> str | None:
    remote_id = payload.get("id")
    return remote_id.strip() if _is_non_empty_string(remote_id) else None


def _matching_client(
    clients: Sequence[Any],
    client_id: str,
) -> Mapping[str, Any] | None:
    for candidate in clients:
        if isinstance(candidate, Mapping) and candidate.get("clientId") == client_id:
            return candidate

    return None


def _matching_client_scope(
    client_scopes: Sequence[Any],
    client_scope_name: str,
) -> Mapping[str, Any] | None:
    for candidate in client_scopes:
        if isinstance(candidate, Mapping) and candidate.get("name") == client_scope_name:
            return candidate

    return None


def _parse_protocol_mapper_spec(
    spec: Mapping[str, Any] | None,
) -> ProtocolMapperSpec | None:
    if not isinstance(spec, Mapping):
        return None

    target_ref = spec.get("targetRef")
    target_name = target_ref.get("name") if isinstance(target_ref, Mapping) else None
    realm = spec.get("realm")
    name = spec.get("name")
    mapper_type = spec.get("mapperType")
    protocol = spec.get("protocol", DEFAULT_PROTOCOL)
    parent = spec.get("parent")
    parent_type = parent.get("type") if isinstance(parent, Mapping) else None
    parent_name = _parent_ref_name(parent, parent_type)
    management_policy = spec.get("managementPolicy", DEFAULT_MANAGEMENT_POLICY)
    deletion_policy = spec.get("deletionPolicy", DEFAULT_DELETION_POLICY)
    config = spec.get("config", {})

    if (
        not _is_non_empty_string(target_name)
        or not _is_non_empty_string(realm)
        or not _is_non_empty_string(name)
        or not _is_non_empty_string(mapper_type)
        or not _is_non_empty_string(protocol)
        or not _is_non_empty_string(parent_type)
        or not _is_non_empty_string(parent_name)
    ):
        return None

    parsed_parent_type = parent_type.strip()
    if parsed_parent_type not in {PARENT_TYPE_CLIENT, PARENT_TYPE_CLIENT_SCOPE}:
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

    parsed_config = _parse_config(config)
    if parsed_config is None:
        return None

    return ProtocolMapperSpec(
        target_name=target_name.strip(),
        realm=realm.strip(),
        name=name.strip(),
        mapper_type=mapper_type.strip(),
        parent_type=parsed_parent_type,
        parent_name=parent_name.strip(),
        management_policy=parsed_management_policy,
        deletion_policy=parsed_deletion_policy,
        protocol=protocol.strip(),
        config=parsed_config,
    )


def _parent_ref_name(parent: Any, parent_type: Any) -> str | None:
    if not isinstance(parent, Mapping) or not _is_non_empty_string(parent_type):
        return None

    if parent_type.strip() == PARENT_TYPE_CLIENT:
        client_ref = parent.get("clientRef")
        return client_ref.get("name") if isinstance(client_ref, Mapping) else None

    if parent_type.strip() == PARENT_TYPE_CLIENT_SCOPE:
        client_scope_ref = parent.get("clientScopeRef")
        return (
            client_scope_ref.get("name") if isinstance(client_scope_ref, Mapping) else None
        )

    return None


def _parse_config(config: Any) -> dict[str, str] | None:
    if not isinstance(config, Mapping):
        return None

    parsed: dict[str, str] = {}
    for key, value in config.items():
        if not _is_non_empty_string(key) or not isinstance(value, str):
            return None

        parsed[key.strip()] = value

    return parsed


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
            f"Missing required KeycloakProtocolMapper spec fields: {fields}.",
            now=now,
        )

    invalid_fields = _invalid_spec_fields(spec)
    if invalid_fields:
        return ready_condition(
            "False",
            INVALID_SPEC_REASON,
            invalid_spec_message("KeycloakProtocolMapper", invalid_fields),
            now=now,
        )

    return ready_condition(
        "False",
        INVALID_SPEC_REASON,
        "KeycloakProtocolMapper spec is invalid.",
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

    if not _is_non_empty_string(spec.get("mapperType")):
        missing_fields.append("mapperType")

    parent = spec.get("parent")
    parent_type = parent.get("type") if isinstance(parent, Mapping) else None
    if not _is_non_empty_string(parent_type):
        missing_fields.append("parent.type")
    elif parent_type.strip() == PARENT_TYPE_CLIENT:
        client_ref = parent.get("clientRef") if isinstance(parent, Mapping) else None
        client_name = client_ref.get("name") if isinstance(client_ref, Mapping) else None
        if not _is_non_empty_string(client_name):
            missing_fields.append("parent.clientRef.name")
    elif parent_type.strip() == PARENT_TYPE_CLIENT_SCOPE:
        client_scope_ref = parent.get("clientScopeRef") if isinstance(parent, Mapping) else None
        client_scope_name = (
            client_scope_ref.get("name") if isinstance(client_scope_ref, Mapping) else None
        )
        if not _is_non_empty_string(client_scope_name):
            missing_fields.append("parent.clientScopeRef.name")

    return missing_fields


def _invalid_spec_fields(spec: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(spec, Mapping):
        return []

    parent = spec.get("parent")
    parent_type = parent.get("type") if isinstance(parent, Mapping) else None
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
        non_empty_string_field_error(spec, "protocol"),
        _parent_type_error(parent_type),
        _config_field_error(spec.get("config", {})),
    ]

    return [error for error in errors if error is not None]


def _parent_type_error(parent_type: Any) -> str | None:
    if parent_type is None:
        return None

    if (
        isinstance(parent_type, str)
        and parent_type.strip() in {PARENT_TYPE_CLIENT, PARENT_TYPE_CLIENT_SCOPE}
    ):
        return None

    return "parent.type must be one of: `Client`, `ClientScope`"


def _config_field_error(config: Any) -> str | None:
    if not isinstance(config, Mapping):
        return "config must be an object with string values"

    if all(_is_non_empty_string(key) and isinstance(value, str) for key, value in config.items()):
        return None

    return "config must use non-empty string keys and string values"


def _protocol_mapper_ready_condition(
    reconcile_result: ProtocolMapperReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if reconcile_result.ready_reason == PROTOCOL_MAPPER_CREATED_REASON:
        message = "Keycloak protocol mapper was created."
    elif reconcile_result.ready_reason == PROTOCOL_MAPPER_UPDATED_REASON:
        message = "Keycloak protocol mapper was updated."
    elif reconcile_result.ready_reason == PROTOCOL_MAPPER_DRIFT_DETECTED_REASON:
        message = (
            "Keycloak protocol mapper has modeled drift and was not changed because "
            "managementPolicy is ObserveOnly."
        )
    elif reconcile_result.ready_reason == PROTOCOL_MAPPER_MISSING_REASON:
        message = (
            "Keycloak protocol mapper is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = "Keycloak protocol mapper already matches desired state."

    return ready_condition(
        reconcile_result.ready_status,
        reconcile_result.ready_reason,
        message,
        now=now,
    )


def _protocol_mapper_drift_condition(
    reconcile_result: ProtocolMapperReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if not reconcile_result.drift_detected:
        return drift_detected_condition(
            "False",
            NO_DRIFT_DETECTED_REASON,
            "Keycloak protocol mapper has no modeled drift.",
            now=now,
        )

    if reconcile_result.ready_reason == PROTOCOL_MAPPER_MISSING_REASON:
        message = (
            "Keycloak protocol mapper is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = (
            "Keycloak protocol mapper differs from desired state and was not changed "
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
            PROTOCOL_MAPPER_CREATED_REASON: (
                "Normal",
                "Keycloak protocol mapper was created.",
            ),
            PROTOCOL_MAPPER_UPDATED_REASON: (
                "Normal",
                "Keycloak protocol mapper was updated.",
            ),
            PROTOCOL_MAPPER_DRIFT_DETECTED_REASON: (
                "Warning",
                "Keycloak protocol mapper has modeled drift and was left unchanged.",
            ),
            PROTOCOL_MAPPER_MISSING_REASON: (
                "Warning",
                "Keycloak protocol mapper is missing and was left unchanged.",
            ),
        },
    )


def _emit_delete_event(body: kopf.Body, deletion_policy: str) -> None:
    if deletion_policy == DELETION_POLICY_DELETE:
        kopf.event(
            body,
            type="Normal",
            reason="ProtocolMapperDeleted",
            message="Keycloak protocol mapper was deleted because deletionPolicy is Delete.",
        )
        return

    kopf.event(
        body,
        type="Normal",
        reason=PROTOCOL_MAPPER_ORPHANED_REASON,
        message="Keycloak protocol mapper was left in Keycloak because deletionPolicy is Orphan.",
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


def _clients_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}/clients"


def _client_scopes_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}/client-scopes"


def _protocol_mapper_parent_path(realm: str, parent: ParentReference) -> str:
    if parent.type == PARENT_TYPE_CLIENT:
        return f"{_clients_path(realm)}/{quote(parent.internal_id, safe='')}"

    return f"{_client_scopes_path(realm)}/{quote(parent.internal_id, safe='')}"


def _protocol_mapper_models_path(realm: str, parent: ParentReference) -> str:
    return f"{_protocol_mapper_parent_path(realm, parent)}/protocol-mappers/models"


def _protocol_mapper_model_path(
    realm: str,
    parent: ParentReference,
    mapper_id: str,
) -> str:
    return f"{_protocol_mapper_models_path(realm, parent)}/{quote(mapper_id, safe='')}"


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
