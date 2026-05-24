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
)
from clouddicted_keycloak_config_operator.handlers.reconciliation import (
    RetryRequest,
    raise_for_retry,
)
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAdminClient,
    KeycloakAuthenticationError,
    KeycloakClientError,
    KeycloakRequestError,
)
from clouddicted_keycloak_config_operator.status import (
    Condition,
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
PROTOCOL_MAPPER_OBSERVED_REASON = "ProtocolMapperObserved"
PROTOCOL_MAPPER_UPDATED_REASON = "ProtocolMapperUpdated"
REQUEST_FAILED_REASON = "RequestFailed"
TARGET_UNAVAILABLE_REASON = "TargetUnavailable"
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
    protocol: str = DEFAULT_PROTOCOL
    config: Mapping[str, str] | None = None


@dataclass(frozen=True)
class ParentReference:
    type: str
    name: str
    internal_id: str


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
    raise_for_retry(retry, body=body)


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
        _set_ready_condition(
            patch,
            existing_conditions,
            _invalid_spec_condition(spec, now=now),
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
        return retry

    try:
        keycloak_client = keycloak_client_factory(
            base_url=target.url,
            username=target.username,
            password=target.password,
        )
        keycloak_client.authenticate()
        ready_reason = ensure_keycloak_protocol_mapper(keycloak_client, mapper_spec)
    except KeycloakAuthenticationError:
        retry = RetryRequest(
            AUTHENTICATION_FAILED_REASON,
            "KeycloakProtocolMapper is not ready because Keycloak authentication failed.",
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
        return retry
    except KeycloakClientError:
        retry = RetryRequest(
            REQUEST_FAILED_REASON,
            "KeycloakProtocolMapper reconciliation failed while calling the Keycloak "
            "Admin API.",
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
        return retry

    _set_ready_condition(
        patch,
        existing_conditions,
        ready_condition(
            "True",
            ready_reason,
            _ready_message(ready_reason),
            now=now,
        ),
    )
    return None


def ensure_keycloak_protocol_mapper(
    client: KeycloakProtocolMapperClient,
    mapper_spec: ProtocolMapperSpec,
) -> str:
    """Create, update, or observe a protocol mapper and return the Ready reason."""
    parent = _resolve_parent_reference(client, mapper_spec)
    mappers = client.request("GET", _protocol_mapper_models_path(mapper_spec.realm, parent))
    if not isinstance(mappers, list):
        raise KeycloakRequestError("Keycloak protocol mapper lookup response was not a list")

    existing_mapper = _matching_protocol_mapper(mappers, mapper_spec.name)
    if existing_mapper is None:
        client.request(
            "POST",
            _protocol_mapper_models_path(mapper_spec.realm, parent),
            json=_modeled_protocol_mapper_payload(mapper_spec),
        )
        return PROTOCOL_MAPPER_CREATED_REASON

    if not _has_modeled_drift(existing_mapper, mapper_spec):
        return PROTOCOL_MAPPER_OBSERVED_REASON

    mapper_id = existing_mapper.get("id")
    if not _is_non_empty_string(mapper_id):
        raise KeycloakRequestError("Keycloak protocol mapper lookup response did not include id")

    client.request(
        "PUT",
        _protocol_mapper_model_path(mapper_spec.realm, parent, mapper_id.strip()),
        json=_protocol_mapper_update_payload(existing_mapper, mapper_spec),
    )
    return PROTOCOL_MAPPER_UPDATED_REASON


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


def _ready_message(ready_reason: str) -> str:
    if ready_reason == PROTOCOL_MAPPER_CREATED_REASON:
        return "Keycloak protocol mapper was created."

    if ready_reason == PROTOCOL_MAPPER_UPDATED_REASON:
        return "Keycloak protocol mapper was updated."

    return "Keycloak protocol mapper already matches desired state."


def _set_ready_condition(
    patch: MutableMapping[str, Any],
    existing_conditions: Sequence[Mapping[str, str]],
    condition: Mapping[str, str],
) -> None:
    status_patch = patch.setdefault("status", {})
    status_patch["conditions"] = upsert_condition(existing_conditions, condition)


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
