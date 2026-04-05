"""Kopf handlers for KeycloakClientScope resources."""

from __future__ import annotations

import logging
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

KEYCLOAK_CLIENT_SCOPE_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_CLIENT_SCOPE_PLURAL,
}

AUTHENTICATION_FAILED_REASON = "AuthenticationFailed"
CLIENT_SCOPE_CREATED_REASON = "ClientScopeCreated"
CLIENT_SCOPE_OBSERVED_REASON = "ClientScopeObserved"
CLIENT_SCOPE_UPDATED_REASON = "ClientScopeUpdated"
DEFAULT_PROTOCOL = "openid-connect"
INVALID_SPEC_REASON = "InvalidSpec"
REQUEST_FAILED_REASON = "RequestFailed"
TARGET_UNAVAILABLE_REASON = "TargetUnavailable"
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
    protocol: str = DEFAULT_PROTOCOL
    description: str | None = None


@kopf.on.create(**KEYCLOAK_CLIENT_SCOPE_RESOURCE)
@kopf.on.update(**KEYCLOAK_CLIENT_SCOPE_RESOURCE)
@kopf.on.resume(**KEYCLOAK_CLIENT_SCOPE_RESOURCE)
def reconcile_keycloak_client_scope(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    logger: logging.Logger | None = None,
    **_: Any,
) -> None:
    """Observe, create, or update a realm client scope and patch status."""
    retry = patch_keycloak_client_scope_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )
    raise_for_retry(retry, body=body, logger=logger)


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
        return retry

    try:
        keycloak_client = keycloak_client_factory(
            base_url=target.url,
            username=target.username,
            password=target.password,
        )
        keycloak_client.authenticate()
        ready_reason = ensure_keycloak_client_scope(keycloak_client, client_scope_spec)
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


def ensure_keycloak_client_scope(
    client: KeycloakClientScopeClient,
    client_scope_spec: ClientScopeSpec,
) -> str:
    """Create, update, or observe a realm client scope and return the Ready reason."""
    client_scopes = client.request("GET", _client_scopes_path(client_scope_spec.realm))
    if not isinstance(client_scopes, list):
        raise KeycloakRequestError("Keycloak client scope lookup response was not a list")

    existing_client_scope = _matching_client_scope(client_scopes, client_scope_spec.name)
    if existing_client_scope is None:
        client.request(
            "POST",
            _client_scopes_path(client_scope_spec.realm),
            json=_modeled_client_scope_payload(client_scope_spec),
        )
        return CLIENT_SCOPE_CREATED_REASON

    if not _has_modeled_drift(existing_client_scope, client_scope_spec):
        return CLIENT_SCOPE_OBSERVED_REASON

    internal_id = existing_client_scope.get("id")
    if not _is_non_empty_string(internal_id):
        raise KeycloakRequestError("Keycloak client scope lookup response did not include id")

    client.request(
        "PUT",
        _client_scope_path(client_scope_spec.realm, internal_id.strip()),
        json=_client_scope_update_payload(existing_client_scope, client_scope_spec),
    )
    return CLIENT_SCOPE_UPDATED_REASON


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

    return ClientScopeSpec(
        target_name=target_name.strip(),
        realm=realm.strip(),
        name=name.strip(),
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


def _ready_message(ready_reason: str) -> str:
    if ready_reason == CLIENT_SCOPE_CREATED_REASON:
        return "Keycloak client scope was created."

    if ready_reason == CLIENT_SCOPE_UPDATED_REASON:
        return "Keycloak client scope was updated."

    return "Keycloak client scope already matches desired state."


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


def _client_scopes_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}/client-scopes"


def _client_scope_path(realm: str, internal_id: str) -> str:
    return f"{_client_scopes_path(realm)}/{quote(internal_id, safe='')}"


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
