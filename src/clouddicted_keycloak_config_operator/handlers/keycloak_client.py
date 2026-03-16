"""Kopf handlers for KeycloakClient resources."""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from urllib.parse import quote

import kopf
from kubernetes import client as kubernetes_client
from kubernetes.client.exceptions import ApiException

from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_CLIENT_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers.keycloak_realm import (
    KubernetesTargetResolver,
    TargetConnection,
    TargetResolutionError,
)
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAdminClient,
    KeycloakAuthenticationError,
    KeycloakClientError,
    KeycloakRequestError,
)
from clouddicted_keycloak_config_operator.secrets import (
    DEFAULT_CLIENT_SECRET_KEY,
    SecretRefError,
    load_secret_value,
)
from clouddicted_keycloak_config_operator.status import (
    Condition,
    ready_condition,
    upsert_condition,
)

KEYCLOAK_CLIENT_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_CLIENT_PLURAL,
}

AUTHENTICATION_FAILED_REASON = "AuthenticationFailed"
CLIENT_CREATED_REASON = "ClientCreated"
CLIENT_OBSERVED_REASON = "ClientObserved"
CLIENT_UPDATED_REASON = "ClientUpdated"
INVALID_SPEC_REASON = "InvalidSpec"
REQUEST_FAILED_REASON = "RequestFailed"
SECRET_UNAVAILABLE_REASON = "SecretUnavailable"
TARGET_UNAVAILABLE_REASON = "TargetUnavailable"
CLIENT_TYPE_PUBLIC = "Public"
CLIENT_TYPE_CONFIDENTIAL = "Confidential"
DEFAULT_CLIENT_TYPE = CLIENT_TYPE_PUBLIC
_CONDITION_FIELDS = ("type", "status", "reason", "message", "lastTransitionTime")


class KeycloakPublicClient(Protocol):
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
    ) -> KeycloakPublicClient:
        """Create a Keycloak Admin API client."""


class TargetResolver(Protocol):
    def __call__(self, *, target_name: str, namespace: str | None) -> TargetConnection:
        """Resolve Keycloak connection settings for a KeycloakTarget."""


@dataclass(frozen=True)
class ClientSpec:
    target_name: str
    realm: str
    client_id: str
    client_type: str
    secret_ref: Mapping[str, Any] | None = None
    display_name: str | None = None
    redirect_uris: tuple[str, ...] = ()
    web_origins: tuple[str, ...] = ()


@kopf.on.create(**KEYCLOAK_CLIENT_RESOURCE)
@kopf.on.update(**KEYCLOAK_CLIENT_RESOURCE)
@kopf.on.resume(**KEYCLOAK_CLIENT_RESOURCE)
def reconcile_keycloak_client(
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Observe or create a Keycloak client and patch status."""
    patch_keycloak_client_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )


def patch_keycloak_client_status(
    *,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    core_v1_api: Any | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
    now: datetime | None = None,
) -> None:
    """Patch KeycloakClient status after observing or creating the client."""
    existing_conditions = _existing_conditions(status)
    client_spec = _parse_client_spec(spec)

    if client_spec is None:
        _set_ready_condition(
            patch,
            existing_conditions,
            _invalid_spec_condition(spec, now=now),
        )
        return

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=client_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        _set_ready_condition(
            patch,
            existing_conditions,
            ready_condition(
                "False",
                TARGET_UNAVAILABLE_REASON,
                "KeycloakClient is not ready because the referenced KeycloakTarget "
                "could not be resolved.",
                now=now,
            ),
        )
        return

    try:
        keycloak_client = keycloak_client_factory(
            base_url=target.url,
            username=target.username,
            password=target.password,
        )
        keycloak_client.authenticate()
        reconcile_reason = ensure_keycloak_client(
            keycloak_client,
            client_spec,
            client_secret_loader=_client_secret_loader(
                core_v1_api=core_v1_api,
                namespace=namespace,
                client_spec=client_spec,
            ),
        )
    except KeycloakAuthenticationError:
        _set_ready_condition(
            patch,
            existing_conditions,
            ready_condition(
                "False",
                AUTHENTICATION_FAILED_REASON,
                "KeycloakClient is not ready because Keycloak authentication failed.",
                now=now,
            ),
        )
        return
    except (SecretRefError, ApiException):
        _set_ready_condition(
            patch,
            existing_conditions,
            ready_condition(
                "False",
                SECRET_UNAVAILABLE_REASON,
                "KeycloakClient is not ready because the client Secret could not be loaded.",
                now=now,
            ),
        )
        return
    except KeycloakClientError:
        _set_ready_condition(
            patch,
            existing_conditions,
            ready_condition(
                "False",
                REQUEST_FAILED_REASON,
                "KeycloakClient reconciliation failed while calling the Keycloak Admin API.",
                now=now,
            ),
        )
        return

    _set_ready_condition(
        patch,
        existing_conditions,
        _client_ready_condition(reconcile_reason, client_spec, now=now),
    )


def ensure_keycloak_client(
    client: KeycloakPublicClient,
    client_spec: ClientSpec,
    *,
    client_secret_loader: Callable[[], str] | None = None,
) -> str:
    """Create, update, or observe a Keycloak client and return the Ready reason."""
    clients = client.request(
        "GET",
        _clients_path(client_spec.realm),
        params={"clientId": client_spec.client_id},
    )
    if not isinstance(clients, list):
        raise KeycloakRequestError("Keycloak client lookup response was not a list")

    existing_client = _matching_client(clients, client_spec.client_id)
    if existing_client is not None:
        if not _has_modeled_drift(existing_client, client_spec):
            return CLIENT_OBSERVED_REASON

        internal_id = existing_client.get("id")
        if not _is_non_empty_string(internal_id):
            raise KeycloakRequestError("Keycloak client lookup response did not include id")

        client.request(
            "PUT",
            _client_path(client_spec.realm, internal_id.strip()),
            json=_client_update_payload(existing_client, client_spec),
        )
        return CLIENT_UPDATED_REASON

    client_secret: str | None = None
    if client_spec.client_type == CLIENT_TYPE_CONFIDENTIAL:
        if client_secret_loader is None:
            raise KeycloakRequestError("Confidential Keycloak client secret was not loaded")
        client_secret = client_secret_loader()

    client.request(
        "POST",
        _clients_path(client_spec.realm),
        json=_client_create_payload(client_spec, client_secret=client_secret),
    )
    return CLIENT_CREATED_REASON


def ensure_keycloak_public_client(
    client: KeycloakPublicClient,
    public_client_spec: ClientSpec,
) -> str:
    """Create, update, or observe a public Keycloak client and return the Ready reason."""
    return ensure_keycloak_client(client, public_client_spec)


def _client_create_payload(
    client_spec: ClientSpec,
    *,
    client_secret: str | None,
) -> dict[str, Any]:
    payload = _modeled_client_payload(client_spec)
    if client_spec.client_type == CLIENT_TYPE_CONFIDENTIAL:
        if client_secret is None:
            raise KeycloakRequestError("Confidential Keycloak client secret was not loaded")
        payload["secret"] = client_secret

    return payload


def _modeled_client_payload(client_spec: ClientSpec) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "clientId": client_spec.client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": client_spec.client_type == CLIENT_TYPE_PUBLIC,
    }

    if client_spec.display_name is not None:
        payload["name"] = client_spec.display_name
    if client_spec.redirect_uris:
        payload["redirectUris"] = list(client_spec.redirect_uris)
    if client_spec.web_origins:
        payload["webOrigins"] = list(client_spec.web_origins)

    return payload


def _client_secret_loader(
    *,
    core_v1_api: Any | None,
    namespace: str | None,
    client_spec: ClientSpec,
) -> Callable[[], str] | None:
    if client_spec.client_type != CLIENT_TYPE_CONFIDENTIAL:
        return None

    def load_client_secret() -> str:
        secret_value = load_secret_value(
            core_v1_api or kubernetes_client.CoreV1Api(),
            namespace,
            client_spec.secret_ref or {},
            default_key=DEFAULT_CLIENT_SECRET_KEY,
        )
        return secret_value.value

    return load_client_secret


def _client_ready_condition(
    reconcile_reason: str,
    client_spec: ClientSpec,
    *,
    now: datetime | None,
) -> Condition:
    client_label = _client_type_label(client_spec)
    if reconcile_reason == CLIENT_CREATED_REASON:
        message = f"Keycloak {client_label} client was created."
    elif reconcile_reason == CLIENT_UPDATED_REASON:
        message = f"Keycloak {client_label} client was updated."
    else:
        message = f"Keycloak {client_label} client already matches desired state."

    return ready_condition("True", reconcile_reason, message, now=now)


def _matching_client(
    clients: Sequence[Any],
    client_id: str,
) -> Mapping[str, Any] | None:
    for candidate in clients:
        if isinstance(candidate, Mapping) and candidate.get("clientId") == client_id:
            return candidate

    return None


def _has_modeled_drift(
    existing_client: Mapping[str, Any],
    client_spec: ClientSpec,
) -> bool:
    desired_payload = _modeled_client_payload(client_spec)
    return any(
        not _modeled_value_matches(existing_client.get(field), desired_value)
        for field, desired_value in desired_payload.items()
    )


def _modeled_value_matches(existing_value: Any, desired_value: Any) -> bool:
    if isinstance(desired_value, list):
        return (
            isinstance(existing_value, Sequence)
            and not isinstance(existing_value, str | bytes)
            and list(existing_value) == desired_value
        )

    return existing_value == desired_value


def _client_update_payload(
    existing_client: Mapping[str, Any],
    client_spec: ClientSpec,
) -> dict[str, Any]:
    payload = dict(existing_client)
    payload.pop("secret", None)
    payload.update(_modeled_client_payload(client_spec))
    return payload


def _parse_client_spec(spec: Mapping[str, Any] | None) -> ClientSpec | None:
    if not isinstance(spec, Mapping):
        return None

    target_ref = spec.get("targetRef")
    target_name = target_ref.get("name") if isinstance(target_ref, Mapping) else None
    realm = spec.get("realm")
    client_id = spec.get("clientId")
    client_type = spec.get("clientType", DEFAULT_CLIENT_TYPE)
    secret_ref = spec.get("secretRef")
    display_name = spec.get("displayName")
    redirect_uris = spec.get("redirectUris", ())
    web_origins = spec.get("webOrigins", ())

    if (
        not _is_non_empty_string(target_name)
        or not _is_non_empty_string(realm)
        or not _is_non_empty_string(client_id)
    ):
        return None

    if not _is_non_empty_string(client_type):
        return None

    parsed_client_type = client_type.strip()
    if parsed_client_type not in {CLIENT_TYPE_PUBLIC, CLIENT_TYPE_CONFIDENTIAL}:
        return None

    parsed_secret_ref = None
    if parsed_client_type == CLIENT_TYPE_CONFIDENTIAL:
        if (
            not isinstance(secret_ref, Mapping)
            or not _is_non_empty_string(secret_ref.get("name"))
        ):
            return None
        parsed_secret_ref = secret_ref

    if display_name is not None and not _is_non_empty_string(display_name):
        return None

    parsed_redirect_uris = _parse_string_tuple(redirect_uris)
    parsed_web_origins = _parse_string_tuple(web_origins)
    if parsed_redirect_uris is None or parsed_web_origins is None:
        return None

    return ClientSpec(
        target_name=target_name.strip(),
        realm=realm.strip(),
        client_id=client_id.strip(),
        client_type=parsed_client_type,
        secret_ref=parsed_secret_ref,
        display_name=display_name.strip() if isinstance(display_name, str) else None,
        redirect_uris=parsed_redirect_uris,
        web_origins=parsed_web_origins,
    )


def _parse_string_tuple(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return None

    parsed: list[str] = []
    for item in value:
        if not _is_non_empty_string(item):
            return None
        parsed.append(item.strip())

    return tuple(parsed)


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
            f"Missing required KeycloakClient spec fields: {fields}.",
            now=now,
        )

    return ready_condition("False", INVALID_SPEC_REASON, "KeycloakClient spec is invalid.", now=now)


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

    if not _is_non_empty_string(spec.get("clientId")):
        missing_fields.append("clientId")

    client_type = spec.get("clientType", DEFAULT_CLIENT_TYPE)
    secret_ref = spec.get("secretRef")
    secret_name = secret_ref.get("name") if isinstance(secret_ref, Mapping) else None

    if client_type == CLIENT_TYPE_CONFIDENTIAL and not _is_non_empty_string(secret_name):
        missing_fields.append("secretRef.name")

    return missing_fields


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


def _client_path(realm: str, internal_id: str) -> str:
    return f"{_clients_path(realm)}/{quote(internal_id, safe='')}"


def _client_type_label(client_spec: ClientSpec) -> str:
    return "confidential" if client_spec.client_type == CLIENT_TYPE_CONFIDENTIAL else "public"


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
