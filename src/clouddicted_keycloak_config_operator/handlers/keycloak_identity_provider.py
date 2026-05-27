"""Kopf handlers for KeycloakIdentityProvider resources."""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Protocol
from urllib.parse import quote

import kopf
from kubernetes import client as kubernetes_client
from kubernetes.client.exceptions import ApiException

from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_IDENTITY_PROVIDER_PLURAL,
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
)
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAdminClient,
    KeycloakAuthenticationError,
    KeycloakClientError,
    KeycloakRequestError,
)
from clouddicted_keycloak_config_operator.secrets import SecretRefError, load_secret_value
from clouddicted_keycloak_config_operator.status import (
    CONDITION_READY,
    Condition,
    drift_detected_condition,
    drift_unknown_condition,
    ready_condition,
    upsert_condition,
)

KEYCLOAK_IDENTITY_PROVIDER_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_IDENTITY_PROVIDER_PLURAL,
}

AUTHENTICATION_FAILED_REASON = "AuthenticationFailed"
IDENTITY_PROVIDER_CREATED_REASON = "IdentityProviderCreated"
IDENTITY_PROVIDER_DRIFT_DETECTED_REASON = "IdentityProviderDriftDetected"
IDENTITY_PROVIDER_MISSING_REASON = "IdentityProviderMissing"
IDENTITY_PROVIDER_OBSERVED_REASON = "IdentityProviderObserved"
IDENTITY_PROVIDER_ORPHANED_REASON = "IdentityProviderOrphaned"
IDENTITY_PROVIDER_UPDATED_REASON = "IdentityProviderUpdated"
INVALID_SPEC_REASON = "InvalidSpec"
NO_DRIFT_DETECTED_REASON = "NoDriftDetected"
REQUEST_FAILED_REASON = "RequestFailed"
SECRET_UNAVAILABLE_REASON = "SecretUnavailable"
TARGET_UNAVAILABLE_REASON = "TargetUnavailable"
MANAGEMENT_POLICY_OBSERVE_ONLY = "ObserveOnly"
MANAGEMENT_POLICY_RECONCILE = "Reconcile"
DEFAULT_MANAGEMENT_POLICY = MANAGEMENT_POLICY_RECONCILE
DELETION_POLICY_ORPHAN = "Orphan"
DELETION_POLICY_DELETE = "Delete"
DEFAULT_DELETION_POLICY = DELETION_POLICY_ORPHAN
DELETE_RETRY_DELAY_SECONDS = 30
_CONDITION_FIELDS = ("type", "status", "reason", "message", "lastTransitionTime")


class KeycloakIdentityProviderClient(Protocol):
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
    ) -> KeycloakIdentityProviderClient:
        """Create a Keycloak Admin API client."""


class TargetResolver(Protocol):
    def __call__(self, *, target_name: str, namespace: str | None) -> TargetConnection:
        """Resolve Keycloak connection settings for a KeycloakTarget."""


@dataclass(frozen=True)
class IdentityProviderSpec:
    target_name: str
    realm: str
    alias: str
    provider_id: str
    management_policy: str
    deletion_policy: str
    enabled: bool = True
    display_name: str | None = None
    config: Mapping[str, str] | None = None
    config_secret_refs: Mapping[str, Mapping[str, Any]] | None = None


@dataclass(frozen=True)
class IdentityProviderReconcileResult:
    ready_status: str
    ready_reason: str
    drift_detected: bool
    remote_id: str | None = None


@kopf.on.create(**KEYCLOAK_IDENTITY_PROVIDER_RESOURCE)
@kopf.on.update(**KEYCLOAK_IDENTITY_PROVIDER_RESOURCE)
@kopf.on.resume(**KEYCLOAK_IDENTITY_PROVIDER_RESOURCE)
def reconcile_keycloak_identity_provider(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Observe, create, or update a realm identity provider and patch status."""
    retry = patch_keycloak_identity_provider_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )
    if retry is None:
        _emit_reconcile_event(body, status=status, patch=patch)
    raise_for_retry(retry, body=body)


@kopf.on.delete(**KEYCLOAK_IDENTITY_PROVIDER_RESOURCE)
def delete_keycloak_identity_provider(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Delete the remote Keycloak identity provider when requested by policy."""
    deletion_policy = delete_keycloak_identity_provider_resource(
        spec=spec,
        namespace=namespace,
    )
    _emit_delete_event(body, deletion_policy)


def delete_keycloak_identity_provider_resource(
    *,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
) -> str:
    """Delete the remote Keycloak identity provider when deletionPolicy is Delete."""
    provider_spec = _parse_identity_provider_spec(spec)
    if provider_spec is None:
        raise kopf.PermanentError(
            "KeycloakIdentityProvider deletion skipped because spec is invalid."
        )

    if provider_spec.deletion_policy == DELETION_POLICY_ORPHAN:
        return DELETION_POLICY_ORPHAN

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=provider_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        raise _delete_temporary_error(
            "KeycloakIdentityProvider deletion is waiting for the referenced "
            "KeycloakTarget."
        ) from None

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        delete_keycloak_identity_provider_if_exists(keycloak_client, provider_spec)
        return DELETION_POLICY_DELETE
    except KeycloakAuthenticationError:
        raise _delete_temporary_error(
            "KeycloakIdentityProvider deletion failed because Keycloak authentication "
            "failed."
        ) from None
    except KeycloakClientError:
        raise _delete_temporary_error(
            "KeycloakIdentityProvider deletion failed while calling the Keycloak "
            "Admin API."
        ) from None


def patch_keycloak_identity_provider_status(
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
    """Patch KeycloakIdentityProvider status after reconciliation."""
    existing_conditions = _existing_conditions(status)
    provider_spec = _parse_identity_provider_spec(spec)

    if provider_spec is None:
        _set_remote_id(patch, None)
        _set_blocked_conditions(
            patch,
            existing_conditions,
            _invalid_spec_condition(spec, now=now),
            "Drift detection was skipped because the KeycloakIdentityProvider spec "
            "is invalid.",
            now=now,
        )
        return None

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=provider_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        retry = RetryRequest(
            TARGET_UNAVAILABLE_REASON,
            "KeycloakIdentityProvider is not ready because the referenced "
            "KeycloakTarget could not be resolved.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition("False", retry.reason, retry.message, now=now),
            "Drift detection was skipped because the referenced KeycloakTarget "
            "could not be resolved.",
            now=now,
        )
        _set_remote_id(patch, None)
        return retry

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        reconcile_result = ensure_keycloak_identity_provider(
            keycloak_client,
            _with_loaded_secret_config(
                provider_spec,
                config_secret_loader=_config_secret_loader(
                    core_v1_api=core_v1_api,
                    namespace=namespace,
                    provider_spec=provider_spec,
                ),
            ),
        )
    except KeycloakAuthenticationError:
        retry = RetryRequest(
            AUTHENTICATION_FAILED_REASON,
            "KeycloakIdentityProvider is not ready because Keycloak authentication "
            "failed.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition("False", retry.reason, retry.message, now=now),
            "Drift detection was skipped because Keycloak authentication failed.",
            now=now,
        )
        _set_remote_id(patch, None)
        return retry
    except (SecretRefError, ApiException):
        retry = RetryRequest(
            SECRET_UNAVAILABLE_REASON,
            "KeycloakIdentityProvider is not ready because a provider config Secret "
            "could not be loaded.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition("False", retry.reason, retry.message, now=now),
            "Drift detection was skipped because a Keycloak identity provider "
            "config Secret could not be loaded.",
            now=now,
        )
        _set_remote_id(patch, None)
        return retry
    except KeycloakClientError:
        retry = RetryRequest(
            REQUEST_FAILED_REASON,
            "KeycloakIdentityProvider reconciliation failed while calling the Keycloak "
            "Admin API.",
        )
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition("False", retry.reason, retry.message, now=now),
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
            _identity_provider_ready_condition(reconcile_result, now=now),
            _identity_provider_drift_condition(reconcile_result, now=now),
        ),
    )
    return None


def _with_loaded_secret_config(
    provider_spec: IdentityProviderSpec,
    *,
    config_secret_loader: Callable[[str, Mapping[str, Any]], str] | None,
) -> IdentityProviderSpec:
    if not provider_spec.config_secret_refs:
        return provider_spec

    if config_secret_loader is None:
        raise KeycloakRequestError("Keycloak identity provider config Secret was not loaded")

    config = dict(provider_spec.config or {})
    for config_key, secret_ref in provider_spec.config_secret_refs.items():
        config[config_key] = config_secret_loader(config_key, secret_ref)

    return replace(provider_spec, config=config)


def _config_secret_loader(
    *,
    core_v1_api: Any | None,
    namespace: str | None,
    provider_spec: IdentityProviderSpec,
) -> Callable[[str, Mapping[str, Any]], str] | None:
    if not provider_spec.config_secret_refs:
        return None

    def load_config_secret(config_key: str, secret_ref: Mapping[str, Any]) -> str:
        secret_value = load_secret_value(
            core_v1_api or kubernetes_client.CoreV1Api(),
            namespace,
            secret_ref,
            default_key=config_key,
        )
        return secret_value.value

    return load_config_secret


def ensure_keycloak_identity_provider(
    client: KeycloakIdentityProviderClient,
    provider_spec: IdentityProviderSpec,
) -> IdentityProviderReconcileResult:
    """Create, update, or observe an identity provider and return the result."""
    providers = client.request("GET", _identity_providers_path(provider_spec.realm))
    if not isinstance(providers, list):
        raise KeycloakRequestError("Keycloak identity provider lookup response was not a list")

    existing_provider = _matching_identity_provider(providers, provider_spec.alias)
    if existing_provider is None:
        if provider_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
            return IdentityProviderReconcileResult(
                "False",
                IDENTITY_PROVIDER_MISSING_REASON,
                True,
            )

        client.request(
            "POST",
            _identity_providers_path(provider_spec.realm),
            json=_modeled_identity_provider_payload(provider_spec),
        )
        created_provider = _get_identity_provider(client, provider_spec)
        return IdentityProviderReconcileResult(
            "True",
            IDENTITY_PROVIDER_CREATED_REASON,
            False,
            _remote_id(created_provider),
        )

    if not _has_modeled_drift(existing_provider, provider_spec):
        return IdentityProviderReconcileResult(
            "True",
            IDENTITY_PROVIDER_OBSERVED_REASON,
            False,
            _remote_id(existing_provider),
        )

    if provider_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
        return IdentityProviderReconcileResult(
            "True",
            IDENTITY_PROVIDER_DRIFT_DETECTED_REASON,
            True,
            _remote_id(existing_provider),
        )

    client.request(
        "PUT",
        _identity_provider_path(provider_spec.realm, provider_spec.alias),
        json=_identity_provider_update_payload(existing_provider, provider_spec),
    )
    updated_provider = _get_identity_provider(client, provider_spec)
    return IdentityProviderReconcileResult(
        "True",
        IDENTITY_PROVIDER_UPDATED_REASON,
        False,
        _remote_id(updated_provider),
    )


def delete_keycloak_identity_provider_if_exists(
    client: KeycloakIdentityProviderClient,
    provider_spec: IdentityProviderSpec,
) -> None:
    """Delete an existing identity provider or no-op when it is already missing."""
    providers = client.request("GET", _identity_providers_path(provider_spec.realm))
    if not isinstance(providers, list):
        raise KeycloakRequestError("Keycloak identity provider lookup response was not a list")

    existing_provider = _matching_identity_provider(providers, provider_spec.alias)
    if existing_provider is None:
        return

    client.request("DELETE", _identity_provider_path(provider_spec.realm, provider_spec.alias))


def _get_identity_provider(
    client: KeycloakIdentityProviderClient,
    provider_spec: IdentityProviderSpec,
) -> Mapping[str, Any]:
    provider = client.request(
        "GET",
        _identity_provider_path(provider_spec.realm, provider_spec.alias),
    )
    if not isinstance(provider, Mapping):
        raise KeycloakRequestError(
            "Keycloak identity provider lookup response was not an object"
        )

    return provider


def _modeled_identity_provider_payload(
    provider_spec: IdentityProviderSpec,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "alias": provider_spec.alias,
        "providerId": provider_spec.provider_id,
        "enabled": provider_spec.enabled,
    }
    if provider_spec.display_name is not None:
        payload["displayName"] = provider_spec.display_name
    if provider_spec.config:
        payload["config"] = dict(provider_spec.config)

    return payload


def _has_modeled_drift(
    existing_provider: Mapping[str, Any],
    provider_spec: IdentityProviderSpec,
) -> bool:
    desired_payload = _modeled_identity_provider_payload(provider_spec)
    for field, desired_value in desired_payload.items():
        if field == "config":
            if not _modeled_config_matches(existing_provider.get("config"), desired_value):
                return True
        elif existing_provider.get(field) != desired_value:
            return True

    return False


def _modeled_config_matches(existing_config: Any, desired_config: Any) -> bool:
    if not isinstance(desired_config, Mapping):
        return existing_config == desired_config

    if not isinstance(existing_config, Mapping):
        return False

    return all(existing_config.get(key) == value for key, value in desired_config.items())


def _identity_provider_update_payload(
    existing_provider: Mapping[str, Any],
    provider_spec: IdentityProviderSpec,
) -> dict[str, Any]:
    payload = dict(existing_provider)
    payload.update(_modeled_identity_provider_payload(provider_spec))

    if provider_spec.config:
        existing_config = existing_provider.get("config")
        config_payload = dict(existing_config) if isinstance(existing_config, Mapping) else {}
        config_payload.update(provider_spec.config)
        payload["config"] = config_payload

    return payload


def _matching_identity_provider(
    providers: Sequence[Any],
    alias: str,
) -> Mapping[str, Any] | None:
    for candidate in providers:
        if isinstance(candidate, Mapping) and candidate.get("alias") == alias:
            return candidate

    return None


def _remote_id(payload: Mapping[str, Any]) -> str | None:
    for field in ("internalId", "id"):
        remote_id = payload.get(field)
        if _is_non_empty_string(remote_id):
            return remote_id.strip()

    return None


def _parse_identity_provider_spec(
    spec: Mapping[str, Any] | None,
) -> IdentityProviderSpec | None:
    if not isinstance(spec, Mapping):
        return None

    target_ref = spec.get("targetRef")
    target_name = target_ref.get("name") if isinstance(target_ref, Mapping) else None
    realm = spec.get("realm")
    alias = spec.get("alias")
    provider_id = spec.get("providerId")
    management_policy = spec.get("managementPolicy", DEFAULT_MANAGEMENT_POLICY)
    deletion_policy = spec.get("deletionPolicy", DEFAULT_DELETION_POLICY)
    enabled = spec.get("enabled", True)
    display_name = spec.get("displayName")
    config = spec.get("config", {})
    config_secret_refs = spec.get("configSecretRefs", {})

    if (
        not _is_non_empty_string(target_name)
        or not _is_non_empty_string(realm)
        or not _is_non_empty_string(alias)
        or not _is_non_empty_string(provider_id)
    ):
        return None

    parsed_management_policy = _parse_policy(
        management_policy,
        {MANAGEMENT_POLICY_OBSERVE_ONLY, MANAGEMENT_POLICY_RECONCILE},
    )
    parsed_deletion_policy = _parse_policy(
        deletion_policy,
        {DELETION_POLICY_ORPHAN, DELETION_POLICY_DELETE},
    )
    parsed_enabled = _parse_bool(enabled)
    parsed_config = _parse_config(config)
    parsed_config_secret_refs = _parse_config_secret_refs(config_secret_refs)
    if (
        parsed_management_policy is None
        or parsed_deletion_policy is None
        or parsed_enabled is None
        or parsed_config is None
        or parsed_config_secret_refs is None
    ):
        return None

    if display_name is not None and not _is_non_empty_string(display_name):
        return None

    return IdentityProviderSpec(
        target_name=target_name.strip(),
        realm=realm.strip(),
        alias=alias.strip(),
        provider_id=provider_id.strip(),
        management_policy=parsed_management_policy,
        deletion_policy=parsed_deletion_policy,
        enabled=parsed_enabled,
        display_name=display_name.strip() if isinstance(display_name, str) else None,
        config=parsed_config,
        config_secret_refs=parsed_config_secret_refs,
    )


def _parse_policy(value: Any, allowed_values: set[str]) -> str | None:
    if not _is_non_empty_string(value):
        return None

    parsed_value = value.strip()
    return parsed_value if parsed_value in allowed_values else None


def _parse_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _parse_config(value: Any) -> Mapping[str, str] | None:
    if not isinstance(value, Mapping):
        return None

    if all(_is_non_empty_string(key) and isinstance(item, str) for key, item in value.items()):
        return dict(value)

    return None


def _parse_config_secret_refs(value: Any) -> Mapping[str, Mapping[str, Any]] | None:
    if not isinstance(value, Mapping):
        return None

    parsed: dict[str, dict[str, str]] = {}
    for config_key, secret_ref in value.items():
        if not _is_non_empty_string(config_key) or not isinstance(secret_ref, Mapping):
            return None

        secret_name = secret_ref.get("name")
        if not _is_non_empty_string(secret_name):
            return None

        parsed_secret_ref = {"name": secret_name.strip()}
        for field in ("namespace", "secretKey"):
            field_value = secret_ref.get(field)
            if field_value is None:
                continue
            if not _is_non_empty_string(field_value):
                return None
            parsed_secret_ref[field] = field_value.strip()

        parsed[config_key.strip()] = parsed_secret_ref

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
            f"Missing required KeycloakIdentityProvider spec fields: {fields}.",
            now=now,
        )

    invalid_fields = _invalid_spec_fields(spec)
    if invalid_fields:
        return ready_condition(
            "False",
            INVALID_SPEC_REASON,
            invalid_spec_message("KeycloakIdentityProvider", invalid_fields),
            now=now,
        )

    return ready_condition(
        "False",
        INVALID_SPEC_REASON,
        "KeycloakIdentityProvider spec is invalid.",
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
    if not _is_non_empty_string(spec.get("alias")):
        missing_fields.append("alias")
    if not _is_non_empty_string(spec.get("providerId")):
        missing_fields.append("providerId")

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
        enum_field_error(
            spec,
            "deletionPolicy",
            {DELETION_POLICY_ORPHAN, DELETION_POLICY_DELETE},
            default=DEFAULT_DELETION_POLICY,
        ),
        bool_field_error(spec, "enabled"),
        non_empty_string_field_error(spec, "displayName"),
        _config_field_error(spec.get("config", {})),
        _config_secret_refs_field_error(spec.get("configSecretRefs", {})),
    ]

    return [error for error in errors if error is not None]


def _config_field_error(config: Any) -> str | None:
    if not isinstance(config, Mapping):
        return "config must be an object with string values"

    if all(_is_non_empty_string(key) and isinstance(value, str) for key, value in config.items()):
        return None

    return "config must use non-empty string keys and string values"


def _config_secret_refs_field_error(config_secret_refs: Any) -> str | None:
    if not isinstance(config_secret_refs, Mapping):
        return "configSecretRefs must be an object with Secret references"

    for config_key, secret_ref in config_secret_refs.items():
        if not _is_non_empty_string(config_key) or not isinstance(secret_ref, Mapping):
            return (
                "configSecretRefs must map non-empty config keys to Secret "
                "references"
            )
        if not _is_non_empty_string(secret_ref.get("name")):
            return "configSecretRefs values must include name"
        for field in ("namespace", "secretKey"):
            if field in secret_ref and not _is_non_empty_string(secret_ref.get(field)):
                return f"configSecretRefs.{field} must be a non-empty string"

    return None


def _identity_provider_ready_condition(
    reconcile_result: IdentityProviderReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if reconcile_result.ready_reason == IDENTITY_PROVIDER_CREATED_REASON:
        message = "Keycloak identity provider was created."
    elif reconcile_result.ready_reason == IDENTITY_PROVIDER_UPDATED_REASON:
        message = "Keycloak identity provider was updated."
    elif reconcile_result.ready_reason == IDENTITY_PROVIDER_DRIFT_DETECTED_REASON:
        message = (
            "Keycloak identity provider has modeled drift and was not changed because "
            "managementPolicy is ObserveOnly."
        )
    elif reconcile_result.ready_reason == IDENTITY_PROVIDER_MISSING_REASON:
        message = (
            "Keycloak identity provider is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = "Keycloak identity provider already matches desired state."

    return ready_condition(
        reconcile_result.ready_status,
        reconcile_result.ready_reason,
        message,
        now=now,
    )


def _identity_provider_drift_condition(
    reconcile_result: IdentityProviderReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if not reconcile_result.drift_detected:
        return drift_detected_condition(
            "False",
            NO_DRIFT_DETECTED_REASON,
            "Keycloak identity provider has no modeled drift.",
            now=now,
        )

    if reconcile_result.ready_reason == IDENTITY_PROVIDER_MISSING_REASON:
        message = (
            "Keycloak identity provider is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = (
            "Keycloak identity provider differs from desired state and was not changed "
            "because managementPolicy is ObserveOnly."
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
            IDENTITY_PROVIDER_CREATED_REASON: (
                "Normal",
                "Keycloak identity provider was created.",
            ),
            IDENTITY_PROVIDER_UPDATED_REASON: (
                "Normal",
                "Keycloak identity provider was updated.",
            ),
            IDENTITY_PROVIDER_DRIFT_DETECTED_REASON: (
                "Warning",
                "Keycloak identity provider has modeled drift and was left unchanged.",
            ),
            IDENTITY_PROVIDER_MISSING_REASON: (
                "Warning",
                "Keycloak identity provider is missing and was left unchanged.",
            ),
        },
    )


def _emit_delete_event(body: kopf.Body, deletion_policy: str) -> None:
    if deletion_policy == DELETION_POLICY_DELETE:
        kopf.event(
            body,
            type="Normal",
            reason="IdentityProviderDeleted",
            message="Keycloak identity provider was deleted because deletionPolicy is Delete.",
        )
        return

    kopf.event(
        body,
        type="Normal",
        reason=IDENTITY_PROVIDER_ORPHANED_REASON,
        message=(
            "Keycloak identity provider was left in Keycloak because deletionPolicy is "
            "Orphan."
        ),
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


def _identity_providers_path(realm: str) -> str:
    return f"realms/{quote(realm, safe='')}/identity-provider/instances"


def _identity_provider_path(realm: str, alias: str) -> str:
    return f"{_identity_providers_path(realm)}/{quote(alias, safe='')}"


def _delete_temporary_error(message: str) -> kopf.TemporaryError:
    return kopf.TemporaryError(message, delay=DELETE_RETRY_DELAY_SECONDS)


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
