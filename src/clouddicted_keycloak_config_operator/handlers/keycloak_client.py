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
    keycloak_client_factory_kwargs,
)
from clouddicted_keycloak_config_operator.handlers.reconciliation import (
    RetryRequest,
    emit_event_for_condition_reasons,
    raise_for_retry,
)
from clouddicted_keycloak_config_operator.handlers.spec_validation import (
    bool_field_error,
    enum_field_error,
    invalid_spec_message,
    non_empty_string_field_error,
    string_list_field_error,
    unique_string_list_field_error,
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
    CONDITION_READY,
    Condition,
    drift_detected_condition,
    drift_unknown_condition,
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
CLIENT_DRIFT_DETECTED_REASON = "ClientDriftDetected"
CLIENT_MISSING_REASON = "ClientMissing"
CLIENT_OBSERVED_REASON = "ClientObserved"
CLIENT_ORPHANED_REASON = "ClientOrphaned"
CLIENT_UPDATED_REASON = "ClientUpdated"
INVALID_SPEC_REASON = "InvalidSpec"
NO_DRIFT_DETECTED_REASON = "NoDriftDetected"
REQUEST_FAILED_REASON = "RequestFailed"
SECRET_UNAVAILABLE_REASON = "SecretUnavailable"
TARGET_UNAVAILABLE_REASON = "TargetUnavailable"
CLIENT_TYPE_PUBLIC = "Public"
CLIENT_TYPE_CONFIDENTIAL = "Confidential"
DEFAULT_CLIENT_TYPE = CLIENT_TYPE_PUBLIC
MANAGEMENT_POLICY_OBSERVE_ONLY = "ObserveOnly"
MANAGEMENT_POLICY_RECONCILE = "Reconcile"
DEFAULT_MANAGEMENT_POLICY = MANAGEMENT_POLICY_RECONCILE
DELETION_POLICY_ORPHAN = "Orphan"
DELETION_POLICY_DELETE = "Delete"
DEFAULT_DELETION_POLICY = DELETION_POLICY_ORPHAN
DELETE_RETRY_DELAY_SECONDS = 30
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
    management_policy: str
    deletion_policy: str
    secret_ref: Mapping[str, Any] | None = None
    enabled: bool = True
    display_name: str | None = None
    description: str | None = None
    root_url: str | None = None
    base_url: str | None = None
    admin_url: str | None = None
    standard_flow_enabled: bool | None = None
    implicit_flow_enabled: bool | None = None
    direct_access_grants_enabled: bool | None = None
    service_accounts_enabled: bool | None = None
    full_scope_allowed: bool | None = None
    frontchannel_logout: bool | None = None
    redirect_uris: tuple[str, ...] = ()
    web_origins: tuple[str, ...] = ()
    default_client_scopes: tuple[str, ...] = ()
    optional_client_scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClientReconcileResult:
    ready_status: str
    ready_reason: str
    drift_detected: bool
    remote_id: str | None = None


@kopf.on.create(**KEYCLOAK_CLIENT_RESOURCE)
@kopf.on.update(**KEYCLOAK_CLIENT_RESOURCE)
@kopf.on.resume(**KEYCLOAK_CLIENT_RESOURCE)
def reconcile_keycloak_client(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Observe or create a Keycloak client and patch status."""
    retry = patch_keycloak_client_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )
    if retry is None:
        _emit_reconcile_event(body, status=status, patch=patch)
    raise_for_retry(retry, body=body)


@kopf.on.delete(**KEYCLOAK_CLIENT_RESOURCE)
def delete_keycloak_client(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Delete the remote Keycloak client when requested by policy."""
    deletion_policy = delete_keycloak_client_resource(spec=spec, namespace=namespace)
    _emit_delete_event(body, deletion_policy)


def delete_keycloak_client_resource(
    *,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
) -> str:
    """Delete the remote Keycloak client when deletionPolicy is Delete."""
    client_spec = _parse_client_spec(spec)
    if client_spec is None:
        raise kopf.PermanentError("KeycloakClient deletion skipped because spec is invalid.")

    if client_spec.deletion_policy == DELETION_POLICY_ORPHAN:
        return DELETION_POLICY_ORPHAN

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=client_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        raise _delete_temporary_error(
            "KeycloakClient deletion is waiting for the referenced KeycloakTarget."
        ) from None

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        delete_keycloak_client_if_exists(keycloak_client, client_spec)
        return DELETION_POLICY_DELETE
    except KeycloakAuthenticationError:
        raise _delete_temporary_error(
            "KeycloakClient deletion failed because Keycloak authentication failed."
        ) from None
    except KeycloakClientError:
        raise _delete_temporary_error(
            "KeycloakClient deletion failed while calling the Keycloak Admin API."
        ) from None


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
) -> RetryRequest | None:
    """Patch KeycloakClient status after observing or creating the client."""
    existing_conditions = _existing_conditions(status)
    client_spec = _parse_client_spec(spec)

    if client_spec is None:
        _set_remote_id(patch, None)
        _set_blocked_conditions(
            patch,
            existing_conditions,
            _invalid_spec_condition(spec, now=now),
            "Drift detection was skipped because the KeycloakClient spec is invalid.",
            now=now,
        )
        return None

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=client_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        retry = RetryRequest(
            TARGET_UNAVAILABLE_REASON,
            "KeycloakClient is not ready because the referenced KeycloakTarget "
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
        reconcile_result = ensure_keycloak_client(
            keycloak_client,
            client_spec,
            client_secret_loader=_client_secret_loader(
                core_v1_api=core_v1_api,
                namespace=namespace,
                client_spec=client_spec,
            ),
        )
    except KeycloakAuthenticationError:
        retry = RetryRequest(
            AUTHENTICATION_FAILED_REASON,
            "KeycloakClient is not ready because Keycloak authentication failed.",
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
    except (SecretRefError, ApiException):
        retry = RetryRequest(
            SECRET_UNAVAILABLE_REASON,
            "KeycloakClient is not ready because the client Secret could not be loaded.",
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
            "Drift detection was skipped because the Keycloak client Secret could not "
            "be loaded.",
            now=now,
        )
        _set_remote_id(patch, None)
        return retry
    except KeycloakClientError:
        retry = RetryRequest(
            REQUEST_FAILED_REASON,
            "KeycloakClient reconciliation failed while calling the Keycloak Admin API.",
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
            _client_ready_condition(reconcile_result, client_spec, now=now),
            _client_drift_condition(reconcile_result, now=now),
        ),
    )
    return None


def ensure_keycloak_client(
    client: KeycloakPublicClient,
    client_spec: ClientSpec,
    *,
    client_secret_loader: Callable[[], str] | None = None,
) -> ClientReconcileResult:
    """Create, update, or observe a Keycloak client and return the result."""
    clients = client.request(
        "GET",
        _clients_path(client_spec.realm),
        params={"clientId": client_spec.client_id},
    )
    if not isinstance(clients, list):
        raise KeycloakRequestError("Keycloak client lookup response was not a list")

    existing_client = _matching_client(clients, client_spec.client_id)
    if existing_client is not None:
        remote_id = _remote_id(existing_client)
        if not _has_modeled_drift(existing_client, client_spec):
            return ClientReconcileResult(
                "True",
                CLIENT_OBSERVED_REASON,
                False,
                remote_id,
            )

        if client_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
            return ClientReconcileResult(
                "True",
                CLIENT_DRIFT_DETECTED_REASON,
                True,
                remote_id,
            )

        internal_id = existing_client.get("id")
        if not _is_non_empty_string(internal_id):
            raise KeycloakRequestError("Keycloak client lookup response did not include id")

        client.request(
            "PUT",
            _client_path(client_spec.realm, internal_id.strip()),
            json=_client_update_payload(existing_client, client_spec),
        )
        return ClientReconcileResult(
            "True",
            CLIENT_UPDATED_REASON,
            False,
            internal_id.strip(),
        )

    if client_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
        return ClientReconcileResult("False", CLIENT_MISSING_REASON, True, None)

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
    return ClientReconcileResult(
        "True",
        CLIENT_CREATED_REASON,
        False,
        _created_client_remote_id(client, client_spec),
    )


def ensure_keycloak_public_client(
    client: KeycloakPublicClient,
    public_client_spec: ClientSpec,
) -> ClientReconcileResult:
    """Create, update, or observe a public Keycloak client and return the result."""
    return ensure_keycloak_client(client, public_client_spec)


def delete_keycloak_client_if_exists(
    client: KeycloakPublicClient,
    client_spec: ClientSpec,
) -> None:
    """Delete an existing Keycloak client or no-op when it is already missing."""
    clients = client.request(
        "GET",
        _clients_path(client_spec.realm),
        params={"clientId": client_spec.client_id},
    )
    if not isinstance(clients, list):
        raise KeycloakRequestError("Keycloak client lookup response was not a list")

    existing_client = _matching_client(clients, client_spec.client_id)
    if existing_client is None:
        return

    internal_id = existing_client.get("id")
    if not _is_non_empty_string(internal_id):
        raise KeycloakRequestError("Keycloak client lookup response did not include id")

    client.request("DELETE", _client_path(client_spec.realm, internal_id.strip()))


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
        "enabled": client_spec.enabled,
        "protocol": "openid-connect",
        "publicClient": client_spec.client_type == CLIENT_TYPE_PUBLIC,
    }

    if client_spec.display_name is not None:
        payload["name"] = client_spec.display_name
    if client_spec.description is not None:
        payload["description"] = client_spec.description
    if client_spec.root_url is not None:
        payload["rootUrl"] = client_spec.root_url
    if client_spec.base_url is not None:
        payload["baseUrl"] = client_spec.base_url
    if client_spec.admin_url is not None:
        payload["adminUrl"] = client_spec.admin_url
    if client_spec.standard_flow_enabled is not None:
        payload["standardFlowEnabled"] = client_spec.standard_flow_enabled
    if client_spec.implicit_flow_enabled is not None:
        payload["implicitFlowEnabled"] = client_spec.implicit_flow_enabled
    if client_spec.direct_access_grants_enabled is not None:
        payload["directAccessGrantsEnabled"] = client_spec.direct_access_grants_enabled
    if client_spec.service_accounts_enabled is not None:
        payload["serviceAccountsEnabled"] = client_spec.service_accounts_enabled
    if client_spec.full_scope_allowed is not None:
        payload["fullScopeAllowed"] = client_spec.full_scope_allowed
    if client_spec.frontchannel_logout is not None:
        payload["frontchannelLogout"] = client_spec.frontchannel_logout
    if client_spec.redirect_uris:
        payload["redirectUris"] = list(client_spec.redirect_uris)
    if client_spec.web_origins:
        payload["webOrigins"] = list(client_spec.web_origins)
    if client_spec.default_client_scopes:
        payload["defaultClientScopes"] = list(client_spec.default_client_scopes)
    if client_spec.optional_client_scopes:
        payload["optionalClientScopes"] = list(client_spec.optional_client_scopes)

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
    reconcile_result: ClientReconcileResult,
    client_spec: ClientSpec,
    *,
    now: datetime | None,
) -> Condition:
    client_label = _client_type_label(client_spec)
    if reconcile_result.ready_reason == CLIENT_CREATED_REASON:
        message = f"Keycloak {client_label} client was created."
    elif reconcile_result.ready_reason == CLIENT_UPDATED_REASON:
        message = f"Keycloak {client_label} client was updated."
    elif reconcile_result.ready_reason == CLIENT_DRIFT_DETECTED_REASON:
        message = (
            f"Keycloak {client_label} client has modeled drift and was not changed "
            "because managementPolicy is ObserveOnly."
        )
    elif reconcile_result.ready_reason == CLIENT_MISSING_REASON:
        message = (
            f"Keycloak {client_label} client is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = f"Keycloak {client_label} client already matches desired state."

    return ready_condition(
        reconcile_result.ready_status,
        reconcile_result.ready_reason,
        message,
        now=now,
    )


def _client_drift_condition(
    reconcile_result: ClientReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if not reconcile_result.drift_detected:
        return drift_detected_condition(
            "False",
            NO_DRIFT_DETECTED_REASON,
            "Keycloak client has no modeled drift.",
            now=now,
        )

    if reconcile_result.ready_reason == CLIENT_MISSING_REASON:
        message = (
            "Keycloak client is missing and was not created because managementPolicy "
            "is ObserveOnly."
        )
    else:
        message = (
            "Keycloak client differs from desired state and was not changed because "
            "managementPolicy is ObserveOnly."
        )

    return drift_detected_condition(
        "True",
        reconcile_result.ready_reason,
        message,
        now=now,
    )


def _matching_client(
    clients: Sequence[Any],
    client_id: str,
) -> Mapping[str, Any] | None:
    for candidate in clients:
        if isinstance(candidate, Mapping) and candidate.get("clientId") == client_id:
            return candidate

    return None


def _created_client_remote_id(
    client: KeycloakPublicClient,
    client_spec: ClientSpec,
) -> str | None:
    clients = client.request(
        "GET",
        _clients_path(client_spec.realm),
        params={"clientId": client_spec.client_id},
    )
    if not isinstance(clients, list):
        raise KeycloakRequestError("Keycloak client lookup response was not a list")

    created_client = _matching_client(clients, client_spec.client_id)
    return _remote_id(created_client) if created_client is not None else None


def _remote_id(payload: Mapping[str, Any]) -> str | None:
    remote_id = payload.get("id")
    return remote_id.strip() if _is_non_empty_string(remote_id) else None


def _has_modeled_drift(
    existing_client: Mapping[str, Any],
    client_spec: ClientSpec,
) -> bool:
    desired_payload = _modeled_client_payload(client_spec)
    return any(
        not _modeled_value_matches(field, existing_client.get(field), desired_value)
        for field, desired_value in desired_payload.items()
    )


def _modeled_value_matches(field: str, existing_value: Any, desired_value: Any) -> bool:
    if field in {"defaultClientScopes", "optionalClientScopes"}:
        return _string_set(existing_value) == _string_set(desired_value)

    if isinstance(desired_value, list):
        return (
            isinstance(existing_value, Sequence)
            and not isinstance(existing_value, str | bytes)
            and list(existing_value) == desired_value
        )

    return existing_value == desired_value


def _string_set(value: Any) -> set[str] | None:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return None

    result: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            return None
        result.add(item)

    return result


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
    management_policy = spec.get("managementPolicy", DEFAULT_MANAGEMENT_POLICY)
    deletion_policy = spec.get("deletionPolicy", DEFAULT_DELETION_POLICY)
    secret_ref = spec.get("secretRef")
    enabled = spec.get("enabled", True)
    display_name = spec.get("displayName")
    description = spec.get("description")
    root_url = spec.get("rootUrl")
    base_url = spec.get("baseUrl")
    admin_url = spec.get("adminUrl")
    redirect_uris = spec.get("redirectUris", ())
    web_origins = spec.get("webOrigins", ())
    default_client_scopes = spec.get("defaultClientScopes", ())
    optional_client_scopes = spec.get("optionalClientScopes", ())

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
    if description is not None and not _is_non_empty_string(description):
        return None
    if root_url is not None and not _is_non_empty_string(root_url):
        return None
    if base_url is not None and not _is_non_empty_string(base_url):
        return None
    if admin_url is not None and not _is_non_empty_string(admin_url):
        return None

    parsed_enabled = _parse_bool(enabled)
    parsed_standard_flow_enabled = _parse_optional_bool(spec, "standardFlowEnabled")
    parsed_implicit_flow_enabled = _parse_optional_bool(spec, "implicitFlowEnabled")
    parsed_direct_access_grants_enabled = _parse_optional_bool(
        spec,
        "directAccessGrantsEnabled",
    )
    parsed_service_accounts_enabled = _parse_optional_bool(spec, "serviceAccountsEnabled")
    parsed_full_scope_allowed = _parse_optional_bool(spec, "fullScopeAllowed")
    parsed_frontchannel_logout = _parse_optional_bool(spec, "frontchannelLogout")
    if (
        parsed_enabled is _INVALID_BOOL
        or parsed_standard_flow_enabled is _INVALID_BOOL
        or parsed_implicit_flow_enabled is _INVALID_BOOL
        or parsed_direct_access_grants_enabled is _INVALID_BOOL
        or parsed_service_accounts_enabled is _INVALID_BOOL
        or parsed_full_scope_allowed is _INVALID_BOOL
        or parsed_frontchannel_logout is _INVALID_BOOL
    ):
        return None
    if (
        parsed_client_type == CLIENT_TYPE_PUBLIC
        and parsed_service_accounts_enabled is True
    ):
        return None

    parsed_redirect_uris = _parse_string_tuple(redirect_uris)
    parsed_web_origins = _parse_string_tuple(web_origins)
    parsed_default_client_scopes = _parse_unique_string_tuple(default_client_scopes)
    parsed_optional_client_scopes = _parse_unique_string_tuple(optional_client_scopes)
    if (
        parsed_redirect_uris is None
        or parsed_web_origins is None
        or parsed_default_client_scopes is None
        or parsed_optional_client_scopes is None
    ):
        return None

    return ClientSpec(
        target_name=target_name.strip(),
        realm=realm.strip(),
        client_id=client_id.strip(),
        client_type=parsed_client_type,
        management_policy=parsed_management_policy,
        deletion_policy=parsed_deletion_policy,
        secret_ref=parsed_secret_ref,
        enabled=parsed_enabled,
        display_name=display_name.strip() if isinstance(display_name, str) else None,
        description=description.strip() if isinstance(description, str) else None,
        root_url=root_url.strip() if isinstance(root_url, str) else None,
        base_url=base_url.strip() if isinstance(base_url, str) else None,
        admin_url=admin_url.strip() if isinstance(admin_url, str) else None,
        standard_flow_enabled=(
            parsed_standard_flow_enabled
            if isinstance(parsed_standard_flow_enabled, bool)
            else None
        ),
        implicit_flow_enabled=(
            parsed_implicit_flow_enabled
            if isinstance(parsed_implicit_flow_enabled, bool)
            else None
        ),
        direct_access_grants_enabled=(
            parsed_direct_access_grants_enabled
            if isinstance(parsed_direct_access_grants_enabled, bool)
            else None
        ),
        service_accounts_enabled=(
            parsed_service_accounts_enabled
            if isinstance(parsed_service_accounts_enabled, bool)
            else None
        ),
        full_scope_allowed=(
            parsed_full_scope_allowed
            if isinstance(parsed_full_scope_allowed, bool)
            else None
        ),
        frontchannel_logout=(
            parsed_frontchannel_logout
            if isinstance(parsed_frontchannel_logout, bool)
            else None
        ),
        redirect_uris=parsed_redirect_uris,
        web_origins=parsed_web_origins,
        default_client_scopes=parsed_default_client_scopes,
        optional_client_scopes=parsed_optional_client_scopes,
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


_INVALID_BOOL = object()


def _parse_bool(value: Any) -> bool | object:
    return value if isinstance(value, bool) else _INVALID_BOOL


def _parse_optional_bool(spec: Mapping[str, Any], field: str) -> bool | object | None:
    if field not in spec:
        return None

    value = spec[field]
    return value if isinstance(value, bool) else _INVALID_BOOL


def _parse_unique_string_tuple(value: Any) -> tuple[str, ...] | None:
    parsed = _parse_string_tuple(value)
    if parsed is None:
        return None

    if len(set(parsed)) != len(parsed):
        return None

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
            f"Missing required KeycloakClient spec fields: {fields}.",
            now=now,
        )

    invalid_fields = _invalid_spec_fields(spec)
    if invalid_fields:
        return ready_condition(
            "False",
            INVALID_SPEC_REASON,
            invalid_spec_message("KeycloakClient", invalid_fields),
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


def _invalid_spec_fields(spec: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(spec, Mapping):
        return []

    errors = [
        enum_field_error(
            spec,
            "clientType",
            {CLIENT_TYPE_PUBLIC, CLIENT_TYPE_CONFIDENTIAL},
            default=DEFAULT_CLIENT_TYPE,
        ),
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
        bool_field_error(spec, "enabled"),
        non_empty_string_field_error(spec, "displayName"),
        non_empty_string_field_error(spec, "description"),
        non_empty_string_field_error(spec, "rootUrl"),
        non_empty_string_field_error(spec, "baseUrl"),
        non_empty_string_field_error(spec, "adminUrl"),
        bool_field_error(spec, "standardFlowEnabled"),
        bool_field_error(spec, "implicitFlowEnabled"),
        bool_field_error(spec, "directAccessGrantsEnabled"),
        bool_field_error(spec, "serviceAccountsEnabled"),
        bool_field_error(spec, "fullScopeAllowed"),
        bool_field_error(spec, "frontchannelLogout"),
        string_list_field_error(spec, "redirectUris"),
        string_list_field_error(spec, "webOrigins"),
        unique_string_list_field_error(spec, "defaultClientScopes"),
        unique_string_list_field_error(spec, "optionalClientScopes"),
    ]

    client_type = spec.get("clientType", DEFAULT_CLIENT_TYPE)
    service_accounts_enabled = spec.get("serviceAccountsEnabled")
    if (
        isinstance(client_type, str)
        and client_type.strip() == CLIENT_TYPE_PUBLIC
        and service_accounts_enabled is True
    ):
        errors.append("serviceAccountsEnabled can be true only for Confidential clients")

    return [error for error in errors if error is not None]


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
            CLIENT_CREATED_REASON: ("Normal", "Keycloak client was created."),
            CLIENT_UPDATED_REASON: ("Normal", "Keycloak client was updated."),
            CLIENT_DRIFT_DETECTED_REASON: (
                "Warning",
                "Keycloak client has modeled drift and was left unchanged.",
            ),
            CLIENT_MISSING_REASON: (
                "Warning",
                "Keycloak client is missing and was left unchanged.",
            ),
        },
    )


def _emit_delete_event(body: kopf.Body, deletion_policy: str) -> None:
    if deletion_policy == DELETION_POLICY_DELETE:
        kopf.event(
            body,
            type="Normal",
            reason="ClientDeleted",
            message="Keycloak client was deleted because deletionPolicy is Delete.",
        )
        return

    kopf.event(
        body,
        type="Normal",
        reason=CLIENT_ORPHANED_REASON,
        message="Keycloak client was left in Keycloak because deletionPolicy is Orphan.",
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


def _client_path(realm: str, internal_id: str) -> str:
    return f"{_clients_path(realm)}/{quote(internal_id, safe='')}"


def _client_type_label(client_spec: ClientSpec) -> str:
    return "confidential" if client_spec.client_type == CLIENT_TYPE_CONFIDENTIAL else "public"


def _delete_temporary_error(message: str) -> kopf.TemporaryError:
    return kopf.TemporaryError(message, delay=DELETE_RETRY_DELAY_SECONDS)


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
