"""Kopf handlers for KeycloakTarget resources."""

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
    KEYCLOAK_TARGET_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers.reconciliation import (
    RetryRequest,
    raise_for_retry,
)
from clouddicted_keycloak_config_operator.keycloak_client import (
    AUTH_METHOD_CLIENT_CREDENTIALS,
    AUTH_METHOD_PASSWORD,
    DEFAULT_CLIENT_ID,
    DEFAULT_REALM,
    KeycloakAdminClient,
    KeycloakClientError,
    KeycloakRequestError,
)
from clouddicted_keycloak_config_operator.redaction import redact_text
from clouddicted_keycloak_config_operator.secrets import (
    DEFAULT_CLIENT_SECRET_KEY,
    SecretRefError,
    load_secret_credentials,
    load_secret_value,
)
from clouddicted_keycloak_config_operator.status import (
    Condition,
    authenticated_condition,
    condition,
    ready_condition,
    secret_ready_condition,
    upsert_condition,
)

KEYCLOAK_TARGET_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_TARGET_PLURAL,
}

AUTHENTICATED_REASON = "Authenticated"
AUTHENTICATION_FAILED_REASON = "AuthenticationFailed"
BOOTSTRAPPED_REASON = "Bootstrapped"
BOOTSTRAP_FAILED_REASON = "BootstrapFailed"
BOOTSTRAP_READY_CONDITION = "BootstrapReady"
CLIENT_CREDENTIALS_AUTH_METHOD = AUTH_METHOD_CLIENT_CREDENTIALS
BOOTSTRAP_CLIENT_CREDENTIALS_AUTH_METHOD = "BootstrapClientCredentials"
INVALID_SPEC_REASON = "InvalidSpec"
RECONCILED_REASON = "Reconciled"
SECRET_LOADED_REASON = "SecretLoaded"
SECRET_UNAVAILABLE_REASON = "SecretUnavailable"
DEFAULT_BOOTSTRAP_REALM_ROLES = ("admin",)
_CONDITION_FIELDS = ("type", "status", "reason", "message", "lastTransitionTime")
_MAX_FAILURE_DETAIL_LENGTH = 300


class KeycloakAuthenticator(Protocol):
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
        realm: str = DEFAULT_REALM,
        client_id: str = DEFAULT_CLIENT_ID,
        client_secret: str | None = None,
        auth_method: str = AUTH_METHOD_PASSWORD,
    ) -> KeycloakAuthenticator:
        """Create a Keycloak authenticator."""


class KeycloakTargetAuthError(KeycloakClientError):
    """Wrap target auth errors with values that must be redacted from status."""

    def __init__(self, redaction_values: Sequence[str]) -> None:
        super().__init__("KeycloakTarget Keycloak operation failed")
        self.redaction_values = tuple(redaction_values)


@dataclass(frozen=True)
class TargetSpec:
    url: str
    auth_method: str
    realm: str
    secret_ref: Mapping[str, Any]
    client_id: str = DEFAULT_CLIENT_ID
    bootstrap_secret_ref: Mapping[str, Any] | None = None
    bootstrap_realm_roles: tuple[str, ...] = DEFAULT_BOOTSTRAP_REALM_ROLES


@dataclass(frozen=True)
class TargetReconcileResult:
    active_auth_method: str
    ready_message: str
    secret_ready_message: str
    authenticated_message: str
    bootstrap_status: str
    bootstrap_reason: str
    bootstrap_message: str
    client_credentials_secret_ref: dict[str, str] | None = None


@kopf.on.create(**KEYCLOAK_TARGET_RESOURCE)
@kopf.on.update(**KEYCLOAK_TARGET_RESOURCE)
@kopf.on.resume(**KEYCLOAK_TARGET_RESOURCE)
def reconcile_keycloak_target(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Validate KeycloakTarget credentials and patch status."""
    retry = patch_keycloak_target_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )
    raise_for_retry(retry, body=body)


def patch_keycloak_target_status(
    *,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    core_v1_api: Any | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
    now: datetime | None = None,
) -> RetryRequest | None:
    """Patch KeycloakTarget status and return a retry message for transient failures."""
    existing_conditions = _existing_conditions(status)
    conditions = list(existing_conditions)

    target_spec = _parse_target_spec(spec)
    if target_spec is None:
        _set_conditions(
            patch,
            conditions,
            [
                _invalid_spec_ready_condition(spec, now=now),
                secret_ready_condition(
                    "Unknown",
                    INVALID_SPEC_REASON,
                    "Secret validation was skipped because the KeycloakTarget spec is invalid.",
                    now=now,
                ),
                authenticated_condition(
                    "Unknown",
                    INVALID_SPEC_REASON,
                    "Authentication was skipped because the KeycloakTarget spec is invalid.",
                    now=now,
                ),
                _bootstrap_ready_condition(
                    "Unknown",
                    INVALID_SPEC_REASON,
                    "Bootstrap was skipped because the KeycloakTarget spec is invalid.",
                    now=now,
                ),
            ],
        )
        return None

    core_api = core_v1_api or kubernetes_client.CoreV1Api()
    try:
        result = _reconcile_target_auth(
            target_spec,
            namespace=namespace,
            core_v1_api=core_api,
            keycloak_client_factory=keycloak_client_factory,
        )
    except (SecretRefError, ApiException):
        _set_conditions(
            patch,
            conditions,
            [
                ready_condition(
                    "False",
                    SECRET_UNAVAILABLE_REASON,
                    "KeycloakTarget is not ready because credentials could not be loaded.",
                    now=now,
                ),
                secret_ready_condition(
                    "False",
                    SECRET_UNAVAILABLE_REASON,
                    "Unable to load the referenced credentials Secret.",
                    now=now,
                ),
                authenticated_condition(
                    "Unknown",
                    SECRET_UNAVAILABLE_REASON,
                    "Authentication was skipped because credentials could not be loaded.",
                    now=now,
                ),
                _bootstrap_ready_condition(
                    "Unknown",
                    SECRET_UNAVAILABLE_REASON,
                    "Bootstrap was skipped because credentials could not be loaded.",
                    now=now,
                ),
            ],
        )
        return RetryRequest(
            SECRET_UNAVAILABLE_REASON,
            "KeycloakTarget credentials could not be loaded.",
        )
    except KeycloakClientError as exc:
        failure_message = _authentication_failure_message(exc)
        _set_conditions(
            patch,
            conditions,
            [
                ready_condition(
                    "False",
                    AUTHENTICATION_FAILED_REASON,
                    "KeycloakTarget is not ready because authentication failed.",
                    now=now,
                ),
                secret_ready_condition(
                    "True",
                    SECRET_LOADED_REASON,
                    "Referenced credentials Secret is readable.",
                    now=now,
                ),
                authenticated_condition(
                    "False",
                    AUTHENTICATION_FAILED_REASON,
                    failure_message,
                    now=now,
                ),
                _bootstrap_ready_condition(
                    "False",
                    BOOTSTRAP_FAILED_REASON,
                    "KeycloakTarget bootstrap did not complete.",
                    now=now,
                ),
            ],
        )
        return RetryRequest(AUTHENTICATION_FAILED_REASON, failure_message)

    _set_conditions(
        patch,
        conditions,
        [
            ready_condition(
                "True",
                RECONCILED_REASON,
                result.ready_message,
                now=now,
            ),
            secret_ready_condition(
                "True",
                SECRET_LOADED_REASON,
                result.secret_ready_message,
                now=now,
            ),
            authenticated_condition(
                "True",
                AUTHENTICATED_REASON,
                result.authenticated_message,
                now=now,
            ),
            _bootstrap_ready_condition(
                result.bootstrap_status,
                result.bootstrap_reason,
                result.bootstrap_message,
                now=now,
            ),
        ],
    )
    status_patch = patch.setdefault("status", {})
    status_patch["activeAuthMethod"] = result.active_auth_method
    if result.client_credentials_secret_ref is not None:
        status_patch["clientCredentialsSecretRef"] = result.client_credentials_secret_ref
    else:
        status_patch["clientCredentialsSecretRef"] = None

    return None


def _invalid_spec_ready_condition(
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
            f"Missing required KeycloakTarget spec fields: {fields}.",
            now=now,
        )

    return ready_condition("False", INVALID_SPEC_REASON, "KeycloakTarget spec is invalid.", now=now)


def _parse_target_spec(spec: Mapping[str, Any] | None) -> TargetSpec | None:
    if not isinstance(spec, Mapping):
        return None

    url = spec.get("url")
    if not _is_non_empty_string(url):
        return None

    auth = spec.get("auth")
    if isinstance(auth, Mapping):
        return _parse_auth_target_spec(url.strip(), auth)

    secret_ref = _secret_ref(spec.get("adminCredentials"))
    if secret_ref is None:
        return None

    return TargetSpec(
        url=url.strip(),
        auth_method=AUTH_METHOD_PASSWORD,
        realm=DEFAULT_REALM,
        client_id=DEFAULT_CLIENT_ID,
        secret_ref=secret_ref,
    )


def _parse_auth_target_spec(url: str, auth: Mapping[str, Any]) -> TargetSpec | None:
    auth_type = auth.get("type")
    realm = auth.get("realm", DEFAULT_REALM)
    if not _is_non_empty_string(auth_type) or not _is_non_empty_string(realm):
        return None

    parsed_auth_type = auth_type.strip()
    parsed_realm = realm.strip()

    if parsed_auth_type == AUTH_METHOD_PASSWORD:
        client_id = auth.get("clientId", DEFAULT_CLIENT_ID)
        secret_ref = _secret_ref(auth.get("password"))
        if secret_ref is None or not _is_non_empty_string(client_id):
            return None

        return TargetSpec(
            url=url,
            auth_method=AUTH_METHOD_PASSWORD,
            realm=parsed_realm,
            client_id=client_id.strip(),
            secret_ref=secret_ref,
        )

    if parsed_auth_type == CLIENT_CREDENTIALS_AUTH_METHOD:
        client_credentials = auth.get("clientCredentials")
        parsed_client_credentials = _parse_client_credentials(client_credentials)
        if parsed_client_credentials is None:
            return None

        client_id, secret_ref = parsed_client_credentials
        return TargetSpec(
            url=url,
            auth_method=CLIENT_CREDENTIALS_AUTH_METHOD,
            realm=parsed_realm,
            client_id=client_id,
            secret_ref=secret_ref,
        )

    if parsed_auth_type == BOOTSTRAP_CLIENT_CREDENTIALS_AUTH_METHOD:
        client_credentials = auth.get("clientCredentials")
        parsed_client_credentials = _parse_client_credentials(client_credentials)
        bootstrap_secret_ref = _secret_ref(auth.get("bootstrapAdminCredentials"))
        realm_roles = _parse_string_tuple(
            auth.get("bootstrapRealmRoles", DEFAULT_BOOTSTRAP_REALM_ROLES)
        )
        if (
            parsed_client_credentials is None
            or bootstrap_secret_ref is None
            or realm_roles is None
        ):
            return None

        client_id, secret_ref = parsed_client_credentials
        return TargetSpec(
            url=url,
            auth_method=BOOTSTRAP_CLIENT_CREDENTIALS_AUTH_METHOD,
            realm=parsed_realm,
            client_id=client_id,
            secret_ref=secret_ref,
            bootstrap_secret_ref=bootstrap_secret_ref,
            bootstrap_realm_roles=realm_roles,
        )

    return None


def _parse_client_credentials(value: Any) -> tuple[str, Mapping[str, Any]] | None:
    if not isinstance(value, Mapping):
        return None

    client_id = value.get("clientId")
    secret_ref = value.get("secretRef")
    if (
        not _is_non_empty_string(client_id)
        or not isinstance(secret_ref, Mapping)
        or not _is_non_empty_string(secret_ref.get("name"))
    ):
        return None

    return client_id.strip(), secret_ref


def _secret_ref(value: Any) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        return None

    secret_ref = value.get("secretRef")
    if not isinstance(secret_ref, Mapping) or not _is_non_empty_string(secret_ref.get("name")):
        return None

    return secret_ref


def _parse_string_tuple(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return None

    parsed: list[str] = []
    for item in value:
        if not _is_non_empty_string(item):
            return None

        parsed.append(item.strip())

    return tuple(parsed)


def _reconcile_target_auth(
    target_spec: TargetSpec,
    *,
    namespace: str | None,
    core_v1_api: Any,
    keycloak_client_factory: KeycloakClientFactory,
) -> TargetReconcileResult:
    if target_spec.auth_method == CLIENT_CREDENTIALS_AUTH_METHOD:
        client_secret = load_secret_value(
            core_v1_api,
            namespace,
            target_spec.secret_ref,
            default_key=_client_secret_key(target_spec.secret_ref),
        )
        keycloak_client = keycloak_client_factory(
            base_url=target_spec.url,
            username="",
            password="",
            realm=target_spec.realm,
            client_id=target_spec.client_id,
            client_secret=client_secret.value,
            auth_method=AUTH_METHOD_CLIENT_CREDENTIALS,
        )
        _authenticate(keycloak_client, (client_secret.value,))
        return _client_credentials_result(target_spec)

    if target_spec.auth_method == BOOTSTRAP_CLIENT_CREDENTIALS_AUTH_METHOD:
        client_secret = _load_existing_client_secret(
            target_spec,
            namespace=namespace,
            core_v1_api=core_v1_api,
        )
        if client_secret is None:
            bootstrap_credentials = load_secret_credentials(
                core_v1_api,
                namespace,
                target_spec.bootstrap_secret_ref or {},
            )
            admin_client = keycloak_client_factory(
                **_password_client_kwargs(
                    target_spec.url,
                    bootstrap_credentials.username,
                    bootstrap_credentials.password,
                    target_spec.realm,
                    DEFAULT_CLIENT_ID,
                )
            )
            _authenticate(
                admin_client,
                (bootstrap_credentials.username, bootstrap_credentials.password),
            )
            client_secret = ensure_bootstrap_client_credentials(admin_client, target_spec)
            _write_client_credentials_secret(
                core_v1_api,
                namespace=namespace,
                target_spec=target_spec,
                client_secret=client_secret,
            )

        keycloak_client = keycloak_client_factory(
            base_url=target_spec.url,
            username="",
            password="",
            realm=target_spec.realm,
            client_id=target_spec.client_id,
            client_secret=client_secret,
            auth_method=AUTH_METHOD_CLIENT_CREDENTIALS,
        )
        _authenticate(keycloak_client, (client_secret,))
        return TargetReconcileResult(
            active_auth_method=CLIENT_CREDENTIALS_AUTH_METHOD,
            ready_message="KeycloakTarget client credentials are valid.",
            secret_ready_message="Referenced client credentials Secret is readable.",
            authenticated_message="Keycloak client credentials authentication succeeded.",
            bootstrap_status="True",
            bootstrap_reason=BOOTSTRAPPED_REASON,
            bootstrap_message="KeycloakTarget bootstrap client credentials are available.",
            client_credentials_secret_ref=_status_secret_ref(target_spec.secret_ref, namespace),
        )

    credentials = load_secret_credentials(core_v1_api, namespace, target_spec.secret_ref)
    keycloak_client = keycloak_client_factory(
        **_password_client_kwargs(
            target_spec.url,
            credentials.username,
            credentials.password,
            target_spec.realm,
            target_spec.client_id,
        )
    )
    _authenticate(keycloak_client, (credentials.username, credentials.password))
    return TargetReconcileResult(
        active_auth_method=AUTH_METHOD_PASSWORD,
        ready_message="KeycloakTarget credentials are valid.",
        secret_ready_message="Referenced credentials Secret is readable.",
        authenticated_message="Keycloak password authentication succeeded.",
        bootstrap_status="Unknown",
        bootstrap_reason="NotConfigured",
        bootstrap_message="KeycloakTarget bootstrap is not configured.",
    )


def _client_credentials_result(target_spec: TargetSpec) -> TargetReconcileResult:
    return TargetReconcileResult(
        active_auth_method=CLIENT_CREDENTIALS_AUTH_METHOD,
        ready_message="KeycloakTarget client credentials are valid.",
        secret_ready_message="Referenced client credentials Secret is readable.",
        authenticated_message="Keycloak client credentials authentication succeeded.",
        bootstrap_status="Unknown",
        bootstrap_reason="NotConfigured",
        bootstrap_message="KeycloakTarget bootstrap is not configured.",
        client_credentials_secret_ref=None,
    )


def _authenticate(
    client: KeycloakAuthenticator,
    redaction_values: Sequence[str],
) -> None:
    try:
        client.authenticate()
    except KeycloakClientError as exc:
        raise KeycloakTargetAuthError(redaction_values) from exc


def _password_client_kwargs(
    base_url: str,
    username: str,
    password: str,
    realm: str,
    client_id: str,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "base_url": base_url,
        "username": username,
        "password": password,
    }
    if realm != DEFAULT_REALM:
        kwargs["realm"] = realm
    if client_id != DEFAULT_CLIENT_ID:
        kwargs["client_id"] = client_id

    return kwargs


def _load_existing_client_secret(
    target_spec: TargetSpec,
    *,
    namespace: str | None,
    core_v1_api: Any,
) -> str | None:
    try:
        secret = load_secret_value(
            core_v1_api,
            namespace,
            target_spec.secret_ref,
            default_key=_client_secret_key(target_spec.secret_ref),
        )
    except (SecretRefError, ApiException):
        return None

    return secret.value


def ensure_bootstrap_client_credentials(
    client: KeycloakAuthenticator,
    target_spec: TargetSpec,
) -> str:
    """Create or update the bootstrap service-account client and return its secret."""
    existing_client = _find_keycloak_client(client, target_spec)
    if existing_client is None:
        client.request(
            "POST",
            _clients_path(target_spec.realm),
            json=_bootstrap_client_payload(target_spec),
        )
        existing_client = _find_keycloak_client(client, target_spec)

    if existing_client is None:
        raise KeycloakRequestError("Keycloak bootstrap client was not found after creation")

    client_id = _internal_id(existing_client, "Keycloak bootstrap client")
    _ensure_bootstrap_client_settings(client, target_spec, existing_client, client_id)
    _ensure_bootstrap_realm_roles(client, target_spec, client_id)

    secret_payload = client.request(
        "GET",
        f"{_client_path(target_spec.realm, client_id)}/client-secret",
    )
    if not isinstance(secret_payload, Mapping):
        raise KeycloakRequestError("Keycloak bootstrap client secret response was not an object")

    client_secret = secret_payload.get("value")
    if not _is_non_empty_string(client_secret):
        raise KeycloakRequestError(
            "Keycloak bootstrap client secret response did not include value"
        )

    return client_secret.strip()


def _find_keycloak_client(
    client: KeycloakAuthenticator,
    target_spec: TargetSpec,
) -> Mapping[str, Any] | None:
    clients = client.request(
        "GET",
        _clients_path(target_spec.realm),
        params={"clientId": target_spec.client_id},
    )
    if not isinstance(clients, list):
        raise KeycloakRequestError("Keycloak client lookup response was not a list")

    for candidate in clients:
        if isinstance(candidate, Mapping) and candidate.get("clientId") == target_spec.client_id:
            return candidate

    return None


def _ensure_bootstrap_client_settings(
    client: KeycloakAuthenticator,
    target_spec: TargetSpec,
    existing_client: Mapping[str, Any],
    internal_id: str,
) -> None:
    desired = _bootstrap_client_payload(target_spec)
    if all(existing_client.get(key) == value for key, value in desired.items()):
        return

    payload = dict(existing_client)
    payload.update(desired)
    client.request("PUT", _client_path(target_spec.realm, internal_id), json=payload)


def _ensure_bootstrap_realm_roles(
    client: KeycloakAuthenticator,
    target_spec: TargetSpec,
    internal_client_id: str,
) -> None:
    service_account = client.request(
        "GET",
        f"{_client_path(target_spec.realm, internal_client_id)}/service-account-user",
    )
    if not isinstance(service_account, Mapping):
        raise KeycloakRequestError("Keycloak service account response was not an object")

    user_id = _internal_id(service_account, "Keycloak service account user")
    current_roles = client.request(
        "GET",
        f"{_user_path(target_spec.realm, user_id)}/role-mappings/realm",
    )
    if not isinstance(current_roles, list):
        raise KeycloakRequestError("Keycloak realm role mapping response was not a list")

    current_role_names = {
        role.get("name") for role in current_roles if isinstance(role, Mapping)
    }
    missing_roles = [
        _realm_role(client, target_spec.realm, role_name)
        for role_name in target_spec.bootstrap_realm_roles
        if role_name not in current_role_names
    ]
    if not missing_roles:
        return

    client.request(
        "POST",
        f"{_user_path(target_spec.realm, user_id)}/role-mappings/realm",
        json=missing_roles,
    )


def _realm_role(
    client: KeycloakAuthenticator,
    realm: str,
    role_name: str,
) -> Mapping[str, Any]:
    role = client.request("GET", f"{_roles_path(realm)}/{quote(role_name, safe='')}")
    if not isinstance(role, Mapping):
        raise KeycloakRequestError("Keycloak realm role response was not an object")

    return role


def _write_client_credentials_secret(
    core_v1_api: Any,
    *,
    namespace: str | None,
    target_spec: TargetSpec,
    client_secret: str,
) -> None:
    secret_name = _required_secret_name(target_spec.secret_ref)
    secret_namespace = _secret_namespace(target_spec.secret_ref, namespace)
    secret_key = _client_secret_key(target_spec.secret_ref)
    body = kubernetes_client.V1Secret(
        metadata=kubernetes_client.V1ObjectMeta(name=secret_name, namespace=secret_namespace),
        type="Opaque",
        string_data={secret_key: client_secret},
    )

    try:
        core_v1_api.create_namespaced_secret(namespace=secret_namespace, body=body)
    except ApiException as exc:
        if exc.status != 409:
            raise
        core_v1_api.patch_namespaced_secret(
            name=secret_name,
            namespace=secret_namespace,
            body=body,
        )


def _bootstrap_client_payload(target_spec: TargetSpec) -> dict[str, Any]:
    return {
        "clientId": target_spec.client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "serviceAccountsEnabled": True,
    }


def _internal_id(payload: Mapping[str, Any], object_name: str) -> str:
    internal_id = payload.get("id")
    if not _is_non_empty_string(internal_id):
        raise KeycloakRequestError(f"{object_name} response did not include id")

    return internal_id.strip()


def _client_secret_key(secret_ref: Mapping[str, Any]) -> str:
    secret_key = secret_ref.get("clientSecretKey") or secret_ref.get("secretKey")
    return secret_key.strip() if _is_non_empty_string(secret_key) else DEFAULT_CLIENT_SECRET_KEY


def _required_secret_name(secret_ref: Mapping[str, Any]) -> str:
    secret_name = secret_ref.get("name")
    if not _is_non_empty_string(secret_name):
        raise SecretRefError("secretRef.name is required")

    return secret_name.strip()


def _secret_namespace(secret_ref: Mapping[str, Any], resource_namespace: str | None) -> str:
    secret_namespace = secret_ref.get("namespace")
    if _is_non_empty_string(secret_namespace):
        return secret_namespace.strip()

    if _is_non_empty_string(resource_namespace):
        return resource_namespace.strip()

    raise SecretRefError("secretRef.namespace is required when the resource namespace is missing")


def _status_secret_ref(
    secret_ref: Mapping[str, Any],
    resource_namespace: str | None,
) -> dict[str, str]:
    result = {"name": _required_secret_name(secret_ref)}
    secret_namespace = _secret_namespace(secret_ref, resource_namespace)
    if secret_namespace != resource_namespace:
        result["namespace"] = secret_namespace

    return result


def _clients_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}/clients"


def _client_path(realm: str, internal_id: str) -> str:
    return f"{_clients_path(realm)}/{quote(internal_id, safe='')}"


def _roles_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}/roles"


def _user_path(realm: str, user_id: str) -> str:
    return f"realms/{quote(realm, safe='')}/users/{quote(user_id, safe='')}"


def _set_conditions(
    patch: MutableMapping[str, Any],
    existing_conditions: Sequence[Mapping[str, str]],
    new_conditions: Sequence[Mapping[str, str]],
) -> None:
    conditions = list(existing_conditions)
    for new_condition in new_conditions:
        conditions = upsert_condition(conditions, new_condition)

    status_patch = patch.setdefault("status", {})
    status_patch["conditions"] = conditions


def _bootstrap_ready_condition(
    status: str,
    reason: str,
    message: str,
    *,
    now: datetime | None = None,
) -> Condition:
    return condition(BOOTSTRAP_READY_CONDITION, status, reason, message, now=now)


def _authentication_failure_message(error: KeycloakClientError) -> str:
    detail = _failure_detail(error)
    redaction_values = getattr(error, "redaction_values", ())
    redacted_detail = redact_text(detail, redaction_values)
    return f"KeycloakTarget authentication failed: {redacted_detail}."


def _failure_detail(error: BaseException) -> str:
    details = [str(error).strip() or error.__class__.__name__]
    cause = error.__cause__
    while cause is not None:
        cause_detail = str(cause).strip()
        if cause_detail:
            details.append(cause_detail)
        cause = cause.__cause__

    return _truncate(": ".join(details))


def _truncate(value: str) -> str:
    if len(value) <= _MAX_FAILURE_DETAIL_LENGTH:
        return value

    return f"{value[: _MAX_FAILURE_DETAIL_LENGTH - 3]}..."


def _missing_required_fields(spec: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(spec, Mapping):
        return ["spec"]

    missing_fields: list[str] = []

    if not _is_non_empty_string(spec.get("url")):
        missing_fields.append("url")

    auth = spec.get("auth")
    if isinstance(auth, Mapping):
        auth_type = auth.get("type")
        if not _is_non_empty_string(auth_type):
            missing_fields.append("auth.type")
            return missing_fields

        parsed_auth_type = auth_type.strip()
        if parsed_auth_type == AUTH_METHOD_PASSWORD:
            if _secret_ref(auth.get("password")) is None:
                missing_fields.append("auth.password.secretRef.name")
        elif parsed_auth_type == CLIENT_CREDENTIALS_AUTH_METHOD:
            client_credentials = auth.get("clientCredentials")
            if _parse_client_credentials(client_credentials) is None:
                missing_fields.append("auth.clientCredentials")
        elif parsed_auth_type == BOOTSTRAP_CLIENT_CREDENTIALS_AUTH_METHOD:
            if _secret_ref(auth.get("bootstrapAdminCredentials")) is None:
                missing_fields.append("auth.bootstrapAdminCredentials.secretRef.name")
            if _parse_client_credentials(auth.get("clientCredentials")) is None:
                missing_fields.append("auth.clientCredentials")
        return missing_fields

    admin_credentials = spec.get("adminCredentials")
    secret_ref = (
        admin_credentials.get("secretRef")
        if isinstance(admin_credentials, Mapping)
        else None
    )
    secret_name = secret_ref.get("name") if isinstance(secret_ref, Mapping) else None

    if not _is_non_empty_string(secret_name):
        missing_fields.append("adminCredentials.secretRef.name")

    return missing_fields


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


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
