"""Kopf handlers for KeycloakRealm resources."""

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
    KEYCLOAK_REALM_PLURAL,
    KEYCLOAK_TARGET_PLURAL,
)
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAdminClient,
    KeycloakAuthenticationError,
    KeycloakClientError,
    KeycloakResourceNotFoundError,
)
from clouddicted_keycloak_config_operator.secrets import SecretRefError, load_secret_credentials
from clouddicted_keycloak_config_operator.status import (
    Condition,
    ready_condition,
    upsert_condition,
)

KEYCLOAK_REALM_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_REALM_PLURAL,
}

AUTHENTICATION_FAILED_REASON = "AuthenticationFailed"
INVALID_SPEC_REASON = "InvalidSpec"
REALM_CREATED_REASON = "RealmCreated"
REALM_OBSERVED_REASON = "RealmObserved"
REQUEST_FAILED_REASON = "RequestFailed"
TARGET_UNAVAILABLE_REASON = "TargetUnavailable"
_CONDITION_FIELDS = ("type", "status", "reason", "message", "lastTransitionTime")


class KeycloakRealmClient(Protocol):
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
    ) -> KeycloakRealmClient:
        """Create a Keycloak Admin API client."""


class TargetResolver(Protocol):
    def __call__(self, *, target_name: str, namespace: str | None) -> TargetConnection:
        """Resolve Keycloak connection settings for a KeycloakTarget."""


@dataclass(frozen=True)
class RealmSpec:
    target_name: str
    realm: str
    display_name: str | None = None


@dataclass(frozen=True)
class TargetConnection:
    url: str
    username: str
    password: str


class TargetResolutionError(RuntimeError):
    """Raised when a referenced KeycloakTarget cannot be resolved."""


@kopf.on.create(**KEYCLOAK_REALM_RESOURCE)
@kopf.on.update(**KEYCLOAK_REALM_RESOURCE)
@kopf.on.resume(**KEYCLOAK_REALM_RESOURCE)
def reconcile_keycloak_realm(
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Observe or create a Keycloak realm and patch status."""
    patch_keycloak_realm_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )


def patch_keycloak_realm_status(
    *,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
    now: datetime | None = None,
) -> None:
    """Patch KeycloakRealm status after observing or creating the realm."""
    existing_conditions = _existing_conditions(status)
    realm_spec = _parse_realm_spec(spec)

    if realm_spec is None:
        _set_ready_condition(patch, existing_conditions, _invalid_spec_condition(spec, now=now))
        return

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=realm_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        _set_ready_condition(
            patch,
            existing_conditions,
            ready_condition(
                "False",
                TARGET_UNAVAILABLE_REASON,
                "KeycloakRealm is not ready because the referenced KeycloakTarget "
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
        realm_created = ensure_keycloak_realm(keycloak_client, realm_spec)
    except KeycloakAuthenticationError:
        _set_ready_condition(
            patch,
            existing_conditions,
            ready_condition(
                "False",
                AUTHENTICATION_FAILED_REASON,
                "KeycloakRealm is not ready because Keycloak authentication failed.",
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
                "KeycloakRealm reconciliation failed while calling the Keycloak Admin API.",
                now=now,
            ),
        )
        return

    if realm_created:
        _set_ready_condition(
            patch,
            existing_conditions,
            ready_condition(
                "True",
                REALM_CREATED_REASON,
                "Keycloak realm was created.",
                now=now,
            ),
        )
        return

    _set_ready_condition(
        patch,
        existing_conditions,
        ready_condition(
            "True",
            REALM_OBSERVED_REASON,
            "Keycloak realm already exists.",
            now=now,
        ),
    )


def ensure_keycloak_realm(client: KeycloakRealmClient, realm_spec: RealmSpec) -> bool:
    """Return True when the realm had to be created."""
    try:
        client.request("GET", _realm_path(realm_spec.realm))
        return False
    except KeycloakResourceNotFoundError:
        payload: dict[str, Any] = {
            "realm": realm_spec.realm,
            "enabled": True,
        }
        if realm_spec.display_name is not None:
            payload["displayName"] = realm_spec.display_name

        client.request("POST", "realms", json=payload)
        return True


class KubernetesTargetResolver:
    """Resolve KeycloakTarget URL and admin Secret credentials from Kubernetes."""

    def __init__(
        self,
        *,
        custom_objects_api: Any | None = None,
        core_v1_api: Any | None = None,
    ) -> None:
        self.custom_objects_api = custom_objects_api or kubernetes_client.CustomObjectsApi()
        self.core_v1_api = core_v1_api or kubernetes_client.CoreV1Api()

    def __call__(self, *, target_name: str, namespace: str | None) -> TargetConnection:
        if not _is_non_empty_string(namespace):
            raise TargetResolutionError("KeycloakRealm namespace is required.")

        try:
            target = self.custom_objects_api.get_namespaced_custom_object(
                group=API_GROUP,
                version=API_VERSION,
                namespace=namespace,
                plural=KEYCLOAK_TARGET_PLURAL,
                name=target_name,
            )
        except ApiException as exc:
            raise TargetResolutionError("Referenced KeycloakTarget could not be loaded.") from exc

        target_spec = _parse_target_connection_spec(target)
        if target_spec is None:
            raise TargetResolutionError("Referenced KeycloakTarget spec is invalid.")

        try:
            credentials = load_secret_credentials(
                self.core_v1_api,
                namespace,
                target_spec["secret_ref"],
            )
        except (SecretRefError, ApiException) as exc:
            raise TargetResolutionError(
                "Referenced KeycloakTarget credentials Secret could not be loaded."
            ) from exc

        return TargetConnection(
            url=target_spec["url"],
            username=credentials.username,
            password=credentials.password,
        )


def _parse_realm_spec(spec: Mapping[str, Any] | None) -> RealmSpec | None:
    if not isinstance(spec, Mapping):
        return None

    target_ref = spec.get("targetRef")
    target_name = target_ref.get("name") if isinstance(target_ref, Mapping) else None
    realm = spec.get("realm")
    display_name = spec.get("displayName")

    if not _is_non_empty_string(target_name) or not _is_non_empty_string(realm):
        return None

    if display_name is not None and not _is_non_empty_string(display_name):
        return None

    return RealmSpec(
        target_name=target_name.strip(),
        realm=realm.strip(),
        display_name=display_name.strip() if isinstance(display_name, str) else None,
    )


def _parse_target_connection_spec(
    target: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if not isinstance(target, Mapping):
        return None

    spec = target.get("spec")
    if not isinstance(spec, Mapping):
        return None

    url = spec.get("url")
    admin_credentials = spec.get("adminCredentials")
    secret_ref = (
        admin_credentials.get("secretRef")
        if isinstance(admin_credentials, Mapping)
        else None
    )

    if (
        not _is_non_empty_string(url)
        or not isinstance(secret_ref, Mapping)
        or not _is_non_empty_string(secret_ref.get("name"))
    ):
        return None

    return {
        "url": url.strip(),
        "secret_ref": secret_ref,
    }


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
            f"Missing required KeycloakRealm spec fields: {fields}.",
            now=now,
        )

    return ready_condition("False", INVALID_SPEC_REASON, "KeycloakRealm spec is invalid.", now=now)


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


def _realm_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}"


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
