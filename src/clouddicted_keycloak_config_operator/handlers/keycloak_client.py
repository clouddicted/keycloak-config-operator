"""Kopf handlers for KeycloakClient resources."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
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

    client_secret: str | None = None
    if client_spec.client_type == CLIENT_TYPE_CONFIDENTIAL:
        try:
            secret_value = load_secret_value(
                core_v1_api or kubernetes_client.CoreV1Api(),
                namespace,
                client_spec.secret_ref or {},
                default_key=DEFAULT_CLIENT_SECRET_KEY,
            )
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

        client_secret = secret_value.value

    try:
        keycloak_client = keycloak_client_factory(
            base_url=target.url,
            username=target.username,
            password=target.password,
        )
        keycloak_client.authenticate()
        client_created = ensure_keycloak_client(
            keycloak_client,
            client_spec,
            client_secret=client_secret,
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

    if client_created:
        _set_ready_condition(
            patch,
            existing_conditions,
            ready_condition(
                "True",
                CLIENT_CREATED_REASON,
                f"Keycloak {_client_type_label(client_spec)} client was created.",
                now=now,
            ),
        )
        return

    _set_ready_condition(
        patch,
        existing_conditions,
        ready_condition(
            "True",
            CLIENT_OBSERVED_REASON,
            f"Keycloak {_client_type_label(client_spec)} client already exists.",
            now=now,
        ),
    )


def ensure_keycloak_client(
    client: KeycloakPublicClient,
    client_spec: ClientSpec,
    *,
    client_secret: str | None = None,
) -> bool:
    """Return True when the client had to be created."""
    clients = client.request(
        "GET",
        _clients_path(client_spec.realm),
        params={"clientId": client_spec.client_id},
    )
    if not isinstance(clients, list):
        raise KeycloakRequestError("Keycloak client lookup response was not a list")

    if any(
        isinstance(candidate, Mapping) and candidate.get("clientId") == client_spec.client_id
        for candidate in clients
    ):
        return False

    client.request(
        "POST",
        _clients_path(client_spec.realm),
        json=_client_payload(client_spec, client_secret=client_secret),
    )
    return True


def ensure_keycloak_public_client(
    client: KeycloakPublicClient,
    public_client_spec: ClientSpec,
) -> bool:
    """Return True when the public client had to be created."""
    return ensure_keycloak_client(client, public_client_spec)


def _client_payload(
    client_spec: ClientSpec,
    *,
    client_secret: str | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "clientId": client_spec.client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": client_spec.client_type == CLIENT_TYPE_PUBLIC,
    }
    if client_spec.client_type == CLIENT_TYPE_CONFIDENTIAL:
        if client_secret is None:
            raise KeycloakRequestError("Confidential Keycloak client secret was not loaded")
        payload["secret"] = client_secret

    if client_spec.display_name is not None:
        payload["name"] = client_spec.display_name
    if client_spec.redirect_uris:
        payload["redirectUris"] = list(client_spec.redirect_uris)
    if client_spec.web_origins:
        payload["webOrigins"] = list(client_spec.web_origins)

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


def _client_type_label(client_spec: ClientSpec) -> str:
    return "confidential" if client_spec.client_type == CLIENT_TYPE_CONFIDENTIAL else "public"


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
