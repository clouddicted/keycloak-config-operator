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
    AUTH_METHOD_CLIENT_CREDENTIALS,
    AUTH_METHOD_PASSWORD,
    DEFAULT_CLIENT_ID,
    DEFAULT_REALM,
    KeycloakAdminClient,
    KeycloakAuthenticationError,
    KeycloakClientError,
    KeycloakRequestError,
    KeycloakResourceNotFoundError,
)
from clouddicted_keycloak_config_operator.secrets import (
    DEFAULT_CLIENT_SECRET_KEY,
    SecretRefError,
    load_secret_credentials,
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

KEYCLOAK_REALM_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_REALM_PLURAL,
}

AUTHENTICATION_FAILED_REASON = "AuthenticationFailed"
INVALID_SPEC_REASON = "InvalidSpec"
REALM_CREATED_REASON = "RealmCreated"
REALM_DRIFT_DETECTED_REASON = "RealmDriftDetected"
REALM_MISSING_REASON = "RealmMissing"
REALM_OBSERVED_REASON = "RealmObserved"
REALM_UPDATED_REASON = "RealmUpdated"
NO_DRIFT_DETECTED_REASON = "NoDriftDetected"
REQUEST_FAILED_REASON = "RequestFailed"
TARGET_UNAVAILABLE_REASON = "TargetUnavailable"
MANAGEMENT_POLICY_OBSERVE_ONLY = "ObserveOnly"
MANAGEMENT_POLICY_RECONCILE = "Reconcile"
DEFAULT_MANAGEMENT_POLICY = MANAGEMENT_POLICY_RECONCILE
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
    management_policy: str
    display_name: str | None = None


@dataclass(frozen=True)
class RealmReconcileResult:
    ready_status: str
    ready_reason: str
    drift_detected: bool


@dataclass(frozen=True)
class TargetConnection:
    url: str
    username: str = ""
    password: str = ""
    realm: str = DEFAULT_REALM
    client_id: str = DEFAULT_CLIENT_ID
    client_secret: str | None = None
    auth_method: str = AUTH_METHOD_PASSWORD


class TargetResolutionError(RuntimeError):
    """Raised when a referenced KeycloakTarget cannot be resolved."""


@kopf.on.create(**KEYCLOAK_REALM_RESOURCE)
@kopf.on.update(**KEYCLOAK_REALM_RESOURCE)
@kopf.on.resume(**KEYCLOAK_REALM_RESOURCE)
def reconcile_keycloak_realm(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Observe or create a Keycloak realm and patch status."""
    retry = patch_keycloak_realm_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )
    if retry is None:
        _emit_reconcile_event(body, status=status, patch=patch)
    raise_for_retry(retry, body=body)


def patch_keycloak_realm_status(
    *,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
    now: datetime | None = None,
) -> RetryRequest | None:
    """Patch KeycloakRealm status after observing or creating the realm."""
    existing_conditions = _existing_conditions(status)
    realm_spec = _parse_realm_spec(spec)

    if realm_spec is None:
        _set_blocked_conditions(
            patch,
            existing_conditions,
            _invalid_spec_condition(spec, now=now),
            "Drift detection was skipped because the KeycloakRealm spec is invalid.",
            now=now,
        )
        return None

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=realm_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        retry = RetryRequest(
            TARGET_UNAVAILABLE_REASON,
            "KeycloakRealm is not ready because the referenced KeycloakTarget "
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
        return retry

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        reconcile_result = ensure_keycloak_realm(keycloak_client, realm_spec)
    except KeycloakAuthenticationError:
        retry = RetryRequest(
            AUTHENTICATION_FAILED_REASON,
            "KeycloakRealm is not ready because Keycloak authentication failed.",
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
        return retry
    except KeycloakClientError:
        retry = RetryRequest(
            REQUEST_FAILED_REASON,
            "KeycloakRealm reconciliation failed while calling the Keycloak Admin API.",
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
        return retry

    _set_conditions(
        patch,
        existing_conditions,
        (
            _realm_ready_condition(reconcile_result, now=now),
            _realm_drift_condition(reconcile_result, now=now),
        ),
    )
    return None


def ensure_keycloak_realm(
    client: KeycloakRealmClient,
    realm_spec: RealmSpec,
) -> RealmReconcileResult:
    """Create, update, or observe a realm and return the result."""
    try:
        existing_realm = client.request("GET", _realm_path(realm_spec.realm))
    except KeycloakResourceNotFoundError:
        if realm_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
            return RealmReconcileResult("False", REALM_MISSING_REASON, True)

        client.request("POST", "realms", json=_realm_create_payload(realm_spec))
        return RealmReconcileResult("True", REALM_CREATED_REASON, False)

    if not isinstance(existing_realm, Mapping):
        raise KeycloakRequestError("Keycloak realm lookup response was not an object")

    if not _has_modeled_drift(existing_realm, realm_spec):
        return RealmReconcileResult("True", REALM_OBSERVED_REASON, False)

    if realm_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
        return RealmReconcileResult("True", REALM_DRIFT_DETECTED_REASON, True)

    client.request(
        "PUT",
        _realm_path(realm_spec.realm),
        json=_realm_update_payload(existing_realm, realm_spec),
    )
    return RealmReconcileResult("True", REALM_UPDATED_REASON, False)


def _realm_create_payload(realm_spec: RealmSpec) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "realm": realm_spec.realm,
        "enabled": True,
    }
    payload.update(_modeled_realm_payload(realm_spec))
    return payload


def _modeled_realm_payload(realm_spec: RealmSpec) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if realm_spec.display_name is not None:
        payload["displayName"] = realm_spec.display_name

    return payload


def _has_modeled_drift(existing_realm: Mapping[str, Any], realm_spec: RealmSpec) -> bool:
    desired_payload = _modeled_realm_payload(realm_spec)
    return any(
        existing_realm.get(field) != desired_value
        for field, desired_value in desired_payload.items()
    )


def _realm_update_payload(
    existing_realm: Mapping[str, Any],
    realm_spec: RealmSpec,
) -> dict[str, Any]:
    payload = dict(existing_realm)
    payload.update(_modeled_realm_payload(realm_spec))
    return payload


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

        auth_method = target_spec["auth_method"]
        if auth_method == AUTH_METHOD_CLIENT_CREDENTIALS:
            try:
                client_secret = load_secret_value(
                    self.core_v1_api,
                    namespace,
                    target_spec["secret_ref"],
                    default_key=_client_secret_key(target_spec["secret_ref"]),
                )
            except (SecretRefError, ApiException) as exc:
                raise TargetResolutionError(
                    "Referenced KeycloakTarget client credentials Secret could not be loaded."
                ) from exc

            return TargetConnection(
                url=target_spec["url"],
                realm=target_spec["realm"],
                client_id=target_spec["client_id"],
                client_secret=client_secret.value,
                auth_method=AUTH_METHOD_CLIENT_CREDENTIALS,
            )

        if auth_method == "BootstrapClientCredentials":
            try:
                client_secret = load_secret_value(
                    self.core_v1_api,
                    namespace,
                    target_spec["secret_ref"],
                    default_key=_client_secret_key(target_spec["secret_ref"]),
                )
            except (SecretRefError, ApiException):
                try:
                    credentials = load_secret_credentials(
                        self.core_v1_api,
                        namespace,
                        target_spec["bootstrap_secret_ref"],
                    )
                except (SecretRefError, ApiException) as exc:
                    raise TargetResolutionError(
                        "Referenced KeycloakTarget bootstrap credentials could not be loaded."
                    ) from exc

                return TargetConnection(
                    url=target_spec["url"],
                    username=credentials.username,
                    password=credentials.password,
                    realm=target_spec["realm"],
                )

            return TargetConnection(
                url=target_spec["url"],
                realm=target_spec["realm"],
                client_id=target_spec["client_id"],
                client_secret=client_secret.value,
                auth_method=AUTH_METHOD_CLIENT_CREDENTIALS,
            )

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

        client_id = target_spec["client_id"]
        return TargetConnection(
            url=target_spec["url"],
            username=credentials.username,
            password=credentials.password,
            realm=target_spec["realm"],
            client_id=client_id.strip() if _is_non_empty_string(client_id) else DEFAULT_CLIENT_ID,
        )


def _parse_realm_spec(spec: Mapping[str, Any] | None) -> RealmSpec | None:
    if not isinstance(spec, Mapping):
        return None

    target_ref = spec.get("targetRef")
    target_name = target_ref.get("name") if isinstance(target_ref, Mapping) else None
    realm = spec.get("realm")
    management_policy = spec.get("managementPolicy", DEFAULT_MANAGEMENT_POLICY)
    display_name = spec.get("displayName")

    if not _is_non_empty_string(target_name) or not _is_non_empty_string(realm):
        return None

    if display_name is not None and not _is_non_empty_string(display_name):
        return None

    if not _is_non_empty_string(management_policy):
        return None

    parsed_management_policy = management_policy.strip()
    if parsed_management_policy not in {
        MANAGEMENT_POLICY_OBSERVE_ONLY,
        MANAGEMENT_POLICY_RECONCILE,
    }:
        return None

    return RealmSpec(
        target_name=target_name.strip(),
        realm=realm.strip(),
        management_policy=parsed_management_policy,
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
    if not _is_non_empty_string(url):
        return None

    auth = spec.get("auth")
    if isinstance(auth, Mapping):
        parsed_auth = _parse_target_auth_spec(auth)
        if parsed_auth is None:
            return None

        parsed_auth["url"] = url.strip()
        return parsed_auth

    admin_credentials = spec.get("adminCredentials")
    secret_ref = _secret_ref(admin_credentials)
    if secret_ref is None:
        return None

    return {
        "url": url.strip(),
        "auth_method": AUTH_METHOD_PASSWORD,
        "realm": DEFAULT_REALM,
        "client_id": DEFAULT_CLIENT_ID,
        "secret_ref": secret_ref,
    }


def _parse_target_auth_spec(auth: Mapping[str, Any]) -> dict[str, Any] | None:
    auth_type = auth.get("type")
    if not _is_non_empty_string(auth_type):
        return None

    parsed_auth_type = auth_type.strip()
    realm = auth.get("realm", DEFAULT_REALM)
    if not _is_non_empty_string(realm):
        return None

    if parsed_auth_type == AUTH_METHOD_CLIENT_CREDENTIALS:
        client_credentials = _parse_client_credentials_spec(auth.get("clientCredentials"))
        if client_credentials is None:
            return None

        return {
            "auth_method": AUTH_METHOD_CLIENT_CREDENTIALS,
            "realm": realm.strip(),
            **client_credentials,
        }

    if parsed_auth_type == "BootstrapClientCredentials":
        client_credentials = _parse_client_credentials_spec(auth.get("clientCredentials"))
        bootstrap_secret_ref = _secret_ref(auth.get("bootstrapAdminCredentials"))
        if client_credentials is None or bootstrap_secret_ref is None:
            return None

        return {
            "auth_method": "BootstrapClientCredentials",
            "realm": realm.strip(),
            "bootstrap_secret_ref": bootstrap_secret_ref,
            **client_credentials,
        }

    if parsed_auth_type == AUTH_METHOD_PASSWORD:
        secret_ref = _secret_ref(auth.get("password"))
        client_id = auth.get("clientId", DEFAULT_CLIENT_ID)
        if secret_ref is None or not _is_non_empty_string(client_id):
            return None

        return {
            "auth_method": AUTH_METHOD_PASSWORD,
            "realm": realm.strip(),
            "client_id": client_id.strip(),
            "secret_ref": secret_ref,
        }

    return None


def _parse_client_credentials_spec(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None

    client_id = value.get("clientId")
    secret_ref = value.get("secretRef")
    if not _is_non_empty_string(client_id) or not isinstance(secret_ref, Mapping):
        return None

    if not _is_non_empty_string(secret_ref.get("name")):
        return None

    return {
        "client_id": client_id.strip(),
        "secret_ref": secret_ref,
    }


def _secret_ref(value: Any) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        return None

    secret_ref = value.get("secretRef")
    if not isinstance(secret_ref, Mapping) or not _is_non_empty_string(secret_ref.get("name")):
        return None

    return secret_ref


def keycloak_client_factory_kwargs(target: TargetConnection) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "base_url": target.url,
        "username": target.username,
        "password": target.password,
    }

    if target.realm != DEFAULT_REALM:
        kwargs["realm"] = target.realm
    if target.client_id != DEFAULT_CLIENT_ID:
        kwargs["client_id"] = target.client_id
    if target.auth_method == AUTH_METHOD_CLIENT_CREDENTIALS:
        kwargs["auth_method"] = AUTH_METHOD_CLIENT_CREDENTIALS
        kwargs["client_secret"] = target.client_secret

    return kwargs


def _client_secret_key(secret_ref: Mapping[str, Any]) -> str:
    secret_key = secret_ref.get("clientSecretKey") or secret_ref.get("secretKey")
    return secret_key.strip() if _is_non_empty_string(secret_key) else DEFAULT_CLIENT_SECRET_KEY


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

    invalid_fields = _invalid_spec_fields(spec)
    if invalid_fields:
        return ready_condition(
            "False",
            INVALID_SPEC_REASON,
            invalid_spec_message("KeycloakRealm", invalid_fields),
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
        non_empty_string_field_error(spec, "displayName"),
    ]

    return [error for error in errors if error is not None]


def _realm_ready_condition(
    reconcile_result: RealmReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if reconcile_result.ready_reason == REALM_CREATED_REASON:
        message = "Keycloak realm was created."
    elif reconcile_result.ready_reason == REALM_UPDATED_REASON:
        message = "Keycloak realm was updated."
    elif reconcile_result.ready_reason == REALM_DRIFT_DETECTED_REASON:
        message = (
            "Keycloak realm has modeled drift and was not changed because "
            "managementPolicy is ObserveOnly."
        )
    elif reconcile_result.ready_reason == REALM_MISSING_REASON:
        message = (
            "Keycloak realm is missing and was not created because managementPolicy "
            "is ObserveOnly."
        )
    else:
        message = "Keycloak realm already matches desired state."

    return ready_condition(
        reconcile_result.ready_status,
        reconcile_result.ready_reason,
        message,
        now=now,
    )


def _realm_drift_condition(
    reconcile_result: RealmReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if not reconcile_result.drift_detected:
        return drift_detected_condition(
            "False",
            NO_DRIFT_DETECTED_REASON,
            "Keycloak realm has no modeled drift.",
            now=now,
        )

    if reconcile_result.ready_reason == REALM_MISSING_REASON:
        message = (
            "Keycloak realm is missing and was not created because managementPolicy "
            "is ObserveOnly."
        )
    else:
        message = (
            "Keycloak realm differs from desired state and was not changed because "
            "managementPolicy is ObserveOnly."
        )

    return drift_detected_condition(
        "True",
        reconcile_result.ready_reason,
        message,
        now=now,
    )


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
            REALM_CREATED_REASON: ("Normal", "Keycloak realm was created."),
            REALM_UPDATED_REASON: ("Normal", "Keycloak realm was updated."),
            REALM_DRIFT_DETECTED_REASON: (
                "Warning",
                "Keycloak realm has modeled drift and was left unchanged.",
            ),
            REALM_MISSING_REASON: (
                "Warning",
                "Keycloak realm is missing and was left unchanged.",
            ),
        },
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


def _realm_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}"


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
