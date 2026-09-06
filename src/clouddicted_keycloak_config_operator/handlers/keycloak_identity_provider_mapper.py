"""Kopf handlers for KeycloakIdentityProviderMapper resources."""

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
    KEYCLOAK_IDENTITY_PROVIDER_MAPPER_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers.keycloak_realm import (
    KubernetesTargetResolver,
    TargetConnection,
    TargetResolutionError,
    keycloak_client_factory_kwargs,
)
from clouddicted_keycloak_config_operator.handlers.reconciliation import (
    RetryRequest,
    discard_unchanged_status_patch,
    emit_event_for_condition_reasons,
    periodic_reconciliation,
    raise_for_retry,
    serialized_deletion,
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

KEYCLOAK_IDENTITY_PROVIDER_MAPPER_RESOURCE = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": KEYCLOAK_IDENTITY_PROVIDER_MAPPER_PLURAL,
}

AUTHENTICATION_FAILED_REASON = "AuthenticationFailed"
IDENTITY_PROVIDER_MISSING_REASON = "IdentityProviderMissing"
IDENTITY_PROVIDER_MAPPER_CREATED_REASON = "IdentityProviderMapperCreated"
IDENTITY_PROVIDER_MAPPER_DRIFT_DETECTED_REASON = "IdentityProviderMapperDriftDetected"
IDENTITY_PROVIDER_MAPPER_MISSING_REASON = "IdentityProviderMapperMissing"
IDENTITY_PROVIDER_MAPPER_OBSERVED_REASON = "IdentityProviderMapperObserved"
IDENTITY_PROVIDER_MAPPER_ORPHANED_REASON = "IdentityProviderMapperOrphaned"
IDENTITY_PROVIDER_MAPPER_UPDATED_REASON = "IdentityProviderMapperUpdated"
INVALID_SPEC_REASON = "InvalidSpec"
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


class KeycloakIdentityProviderMapperClient(Protocol):
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
    ) -> KeycloakIdentityProviderMapperClient:
        """Create a Keycloak Admin API client."""


class TargetResolver(Protocol):
    def __call__(self, *, target_name: str, namespace: str | None) -> TargetConnection:
        """Resolve Keycloak connection settings for a KeycloakTarget."""


class IdentityProviderDependencyError(Exception):
    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


@dataclass(frozen=True)
class IdentityProviderMapperSpec:
    target_name: str
    realm: str
    name: str
    identity_provider_name: str
    identity_provider_alias: str
    identity_provider_mapper: str
    management_policy: str
    deletion_policy: str
    config: Mapping[str, str] | None = None


@dataclass(frozen=True)
class IdentityProviderMapperReconcileResult:
    ready_status: str
    ready_reason: str
    drift_detected: bool
    remote_id: str | None = None


@kopf.on.create(**KEYCLOAK_IDENTITY_PROVIDER_MAPPER_RESOURCE)
@kopf.on.update(**KEYCLOAK_IDENTITY_PROVIDER_MAPPER_RESOURCE)
@kopf.on.resume(**KEYCLOAK_IDENTITY_PROVIDER_MAPPER_RESOURCE)
@periodic_reconciliation(KEYCLOAK_IDENTITY_PROVIDER_MAPPER_RESOURCE)
def reconcile_keycloak_identity_provider_mapper(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Observe, create, or update a Keycloak identity provider mapper and patch status."""
    retry = patch_keycloak_identity_provider_mapper_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
    )
    discard_unchanged_status_patch(patch, status)
    if retry is None:
        _emit_reconcile_event(body, status=status, patch=patch)
    raise_for_retry(retry, body=body)


@kopf.on.delete(**KEYCLOAK_IDENTITY_PROVIDER_MAPPER_RESOURCE)
@serialized_deletion
def delete_keycloak_identity_provider_mapper(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    **_: Any,
) -> None:
    """Delete the remote Keycloak identity provider mapper when requested by policy."""
    deletion_policy = delete_keycloak_identity_provider_mapper_resource(
        spec=spec,
        namespace=namespace,
    )
    _emit_delete_event(body, deletion_policy)


def delete_keycloak_identity_provider_mapper_resource(
    *,
    spec: Mapping[str, Any] | None,
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
) -> str:
    """Delete the remote Keycloak identity provider mapper when deletionPolicy is Delete."""
    mapper_spec = _parse_identity_provider_mapper_spec(spec)
    if mapper_spec is None:
        raise kopf.PermanentError(
            "KeycloakIdentityProviderMapper deletion skipped because spec is invalid."
        )

    if mapper_spec.deletion_policy == DELETION_POLICY_ORPHAN:
        return DELETION_POLICY_ORPHAN

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=mapper_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        raise _delete_temporary_error(
            "KeycloakIdentityProviderMapper deletion is waiting for the referenced "
            "KeycloakTarget."
        ) from None

    try:
        keycloak_client = keycloak_client_factory(**keycloak_client_factory_kwargs(target))
        keycloak_client.authenticate()
        delete_keycloak_identity_provider_mapper_if_exists(keycloak_client, mapper_spec)
        return DELETION_POLICY_DELETE
    except KeycloakAuthenticationError:
        raise _delete_temporary_error(
            "KeycloakIdentityProviderMapper deletion failed because Keycloak "
            "authentication failed."
        ) from None
    except KeycloakClientError:
        raise _delete_temporary_error(
            "KeycloakIdentityProviderMapper deletion failed while calling the Keycloak "
            "Admin API."
        ) from None


def patch_keycloak_identity_provider_mapper_status(
    *,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    target_resolver: TargetResolver | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
    now: datetime | None = None,
) -> RetryRequest | None:
    """Patch KeycloakIdentityProviderMapper status after reconciliation."""
    existing_conditions = _existing_conditions(status)
    mapper_spec = _parse_identity_provider_mapper_spec(spec)

    if mapper_spec is None:
        _set_remote_id(patch, None)
        _set_blocked_conditions(
            patch,
            existing_conditions,
            _invalid_spec_condition(spec, now=now),
            "Drift detection was skipped because the KeycloakIdentityProviderMapper "
            "spec is invalid.",
            now=now,
        )
        return None

    resolver = target_resolver or KubernetesTargetResolver()
    try:
        target = resolver(target_name=mapper_spec.target_name, namespace=namespace)
    except TargetResolutionError:
        retry = RetryRequest(
            TARGET_UNAVAILABLE_REASON,
            "KeycloakIdentityProviderMapper is not ready because the referenced "
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
        reconcile_result = ensure_keycloak_identity_provider_mapper(
            keycloak_client,
            mapper_spec,
        )
    except KeycloakAuthenticationError:
        retry = RetryRequest(
            AUTHENTICATION_FAILED_REASON,
            "KeycloakIdentityProviderMapper is not ready because Keycloak "
            "authentication failed.",
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
    except IdentityProviderDependencyError as exc:
        retry = RetryRequest(exc.reason, exc.message)
        _set_blocked_conditions(
            patch,
            existing_conditions,
            ready_condition("False", retry.reason, retry.message, now=now),
            "Drift detection was skipped because the referenced Keycloak identity "
            "provider was not found.",
            now=now,
        )
        _set_remote_id(patch, None)
        return retry
    except KeycloakClientError:
        retry = RetryRequest(
            REQUEST_FAILED_REASON,
            "KeycloakIdentityProviderMapper reconciliation failed while calling the "
            "Keycloak Admin API.",
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
            _identity_provider_mapper_ready_condition(reconcile_result, now=now),
            _identity_provider_mapper_drift_condition(reconcile_result, now=now),
        ),
    )
    return None


def ensure_keycloak_identity_provider_mapper(
    client: KeycloakIdentityProviderMapperClient,
    mapper_spec: IdentityProviderMapperSpec,
) -> IdentityProviderMapperReconcileResult:
    """Create, update, or observe an identity provider mapper and return the result."""
    provider = _find_identity_provider(
        client,
        mapper_spec.realm,
        mapper_spec.identity_provider_alias,
    )
    if provider is None:
        raise IdentityProviderDependencyError(
            IDENTITY_PROVIDER_MISSING_REASON,
            "KeycloakIdentityProviderMapper is waiting for the referenced Keycloak "
            "identity provider.",
        )

    mappers = client.request(
        "GET",
        _identity_provider_mappers_path(
            mapper_spec.realm,
            mapper_spec.identity_provider_alias,
        ),
    )
    if not isinstance(mappers, list):
        raise KeycloakRequestError(
            "Keycloak identity provider mapper lookup response was not a list"
        )

    existing_mapper = _matching_mapper(mappers, mapper_spec.name)
    if existing_mapper is None:
        if mapper_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
            return IdentityProviderMapperReconcileResult(
                "False",
                IDENTITY_PROVIDER_MAPPER_MISSING_REASON,
                True,
            )

        client.request(
            "POST",
            _identity_provider_mappers_path(
                mapper_spec.realm,
                mapper_spec.identity_provider_alias,
            ),
            json=_modeled_mapper_payload(mapper_spec),
        )
        mappers = client.request(
            "GET",
            _identity_provider_mappers_path(
                mapper_spec.realm,
                mapper_spec.identity_provider_alias,
            ),
        )
        if not isinstance(mappers, list):
            raise KeycloakRequestError(
                "Keycloak identity provider mapper lookup response was not a list"
            )

        created_mapper = _matching_mapper(mappers, mapper_spec.name)
        return IdentityProviderMapperReconcileResult(
            "True",
            IDENTITY_PROVIDER_MAPPER_CREATED_REASON,
            False,
            _remote_id(created_mapper) if created_mapper is not None else None,
        )

    if not _has_modeled_drift(existing_mapper, mapper_spec):
        return IdentityProviderMapperReconcileResult(
            "True",
            IDENTITY_PROVIDER_MAPPER_OBSERVED_REASON,
            False,
            _remote_id(existing_mapper),
        )

    if mapper_spec.management_policy == MANAGEMENT_POLICY_OBSERVE_ONLY:
        return IdentityProviderMapperReconcileResult(
            "True",
            IDENTITY_PROVIDER_MAPPER_DRIFT_DETECTED_REASON,
            True,
            _remote_id(existing_mapper),
        )

    mapper_id = existing_mapper.get("id")
    if not _is_non_empty_string(mapper_id):
        raise KeycloakRequestError(
            "Keycloak identity provider mapper lookup response did not include id"
        )

    client.request(
        "PUT",
        _identity_provider_mapper_path(
            mapper_spec.realm,
            mapper_spec.identity_provider_alias,
            mapper_id.strip(),
        ),
        json=_mapper_update_payload(existing_mapper, mapper_spec),
    )
    return IdentityProviderMapperReconcileResult(
        "True",
        IDENTITY_PROVIDER_MAPPER_UPDATED_REASON,
        False,
        mapper_id.strip(),
    )


def delete_keycloak_identity_provider_mapper_if_exists(
    client: KeycloakIdentityProviderMapperClient,
    mapper_spec: IdentityProviderMapperSpec,
) -> None:
    """Delete an existing Keycloak identity provider mapper or no-op when absent."""
    provider = _find_identity_provider(
        client,
        mapper_spec.realm,
        mapper_spec.identity_provider_alias,
    )
    if provider is None:
        return

    mappers = client.request(
        "GET",
        _identity_provider_mappers_path(
            mapper_spec.realm,
            mapper_spec.identity_provider_alias,
        ),
    )
    if not isinstance(mappers, list):
        raise KeycloakRequestError(
            "Keycloak identity provider mapper lookup response was not a list"
        )

    existing_mapper = _matching_mapper(mappers, mapper_spec.name)
    if existing_mapper is None:
        return

    mapper_id = existing_mapper.get("id")
    if not _is_non_empty_string(mapper_id):
        raise KeycloakRequestError(
            "Keycloak identity provider mapper lookup response did not include id"
        )

    client.request(
        "DELETE",
        _identity_provider_mapper_path(
            mapper_spec.realm,
            mapper_spec.identity_provider_alias,
            mapper_id.strip(),
        ),
    )


def _find_identity_provider(
    client: KeycloakIdentityProviderMapperClient,
    realm: str,
    alias: str,
) -> Mapping[str, Any] | None:
    providers = client.request("GET", _identity_providers_path(realm))
    if not isinstance(providers, list):
        raise KeycloakRequestError(
            "Keycloak identity provider lookup response was not a list"
        )

    for candidate in providers:
        if isinstance(candidate, Mapping) and candidate.get("alias") == alias:
            return candidate

    return None


def _modeled_mapper_payload(mapper_spec: IdentityProviderMapperSpec) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": mapper_spec.name,
        "identityProviderAlias": mapper_spec.identity_provider_alias,
        "identityProviderMapper": mapper_spec.identity_provider_mapper,
    }
    if mapper_spec.config:
        payload["config"] = dict(mapper_spec.config)

    return payload


def _has_modeled_drift(
    existing_mapper: Mapping[str, Any],
    mapper_spec: IdentityProviderMapperSpec,
) -> bool:
    if existing_mapper.get("identityProviderMapper") != mapper_spec.identity_provider_mapper:
        return True

    if existing_mapper.get("name") != mapper_spec.name:
        return True

    desired_config = mapper_spec.config or {}
    existing_config = existing_mapper.get("config") or {}
    if not isinstance(existing_config, Mapping):
        return bool(desired_config)

    return any(existing_config.get(key) != value for key, value in desired_config.items())


def _mapper_update_payload(
    existing_mapper: Mapping[str, Any],
    mapper_spec: IdentityProviderMapperSpec,
) -> dict[str, Any]:
    payload = dict(existing_mapper)
    payload.update(_modeled_mapper_payload(mapper_spec))

    if mapper_spec.config:
        existing_config = existing_mapper.get("config")
        config_payload = dict(existing_config) if isinstance(existing_config, Mapping) else {}
        config_payload.update(mapper_spec.config)
        payload["config"] = config_payload

    return payload


def _matching_mapper(
    mappers: Sequence[Any],
    name: str,
) -> Mapping[str, Any] | None:
    for candidate in mappers:
        if isinstance(candidate, Mapping) and candidate.get("name") == name:
            return candidate

    return None


def _remote_id(payload: Mapping[str, Any] | None) -> str | None:
    if payload is None:
        return None

    for field in ("id", "internalId"):
        remote_id = payload.get(field)
        if _is_non_empty_string(remote_id):
            return remote_id.strip()

    return None


def _parse_identity_provider_mapper_spec(
    spec: Mapping[str, Any] | None,
) -> IdentityProviderMapperSpec | None:
    if not isinstance(spec, Mapping):
        return None

    target_ref = spec.get("targetRef")
    target_name = target_ref.get("name") if isinstance(target_ref, Mapping) else None
    realm = spec.get("realm")
    name = spec.get("name")
    idp_ref = spec.get("identityProviderRef")
    idp_name = idp_ref.get("name") if isinstance(idp_ref, Mapping) else None
    idp_alias = (
        idp_ref.get("alias")
        if isinstance(idp_ref, Mapping) and _is_non_empty_string(idp_ref.get("alias"))
        else idp_name
    )
    mapper_type = spec.get("identityProviderMapper") or spec.get("mapperType")
    management_policy = spec.get("managementPolicy", DEFAULT_MANAGEMENT_POLICY)
    deletion_policy = spec.get("deletionPolicy", DEFAULT_DELETION_POLICY)
    config = spec.get("config", {})

    if (
        not _is_non_empty_string(target_name)
        or not _is_non_empty_string(realm)
        or not _is_non_empty_string(name)
        or not _is_non_empty_string(idp_name)
        or not _is_non_empty_string(idp_alias)
        or not _is_non_empty_string(mapper_type)
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
    parsed_config = _parse_config(config)
    if (
        parsed_management_policy is None
        or parsed_deletion_policy is None
        or parsed_config is None
    ):
        return None

    return IdentityProviderMapperSpec(
        target_name=target_name.strip(),
        realm=realm.strip(),
        name=name.strip(),
        identity_provider_name=idp_name.strip(),
        identity_provider_alias=idp_alias.strip(),
        identity_provider_mapper=mapper_type.strip(),
        management_policy=parsed_management_policy,
        deletion_policy=parsed_deletion_policy,
        config=parsed_config,
    )


def _parse_policy(value: Any, allowed_values: set[str]) -> str | None:
    if not _is_non_empty_string(value):
        return None

    parsed_value = value.strip()
    return parsed_value if parsed_value in allowed_values else None


def _parse_config(value: Any) -> Mapping[str, str] | None:
    if not isinstance(value, Mapping):
        return None

    if all(_is_non_empty_string(key) and isinstance(item, str) for key, item in value.items()):
        return dict(value)

    return None


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
            f"Missing required KeycloakIdentityProviderMapper spec fields: {fields}.",
            now=now,
        )

    invalid_fields = _invalid_spec_fields(spec)
    if invalid_fields:
        return ready_condition(
            "False",
            INVALID_SPEC_REASON,
            invalid_spec_message("KeycloakIdentityProviderMapper", invalid_fields),
            now=now,
        )

    return ready_condition(
        "False",
        INVALID_SPEC_REASON,
        "KeycloakIdentityProviderMapper spec is invalid.",
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

    idp_ref = spec.get("identityProviderRef")
    idp_name = idp_ref.get("name") if isinstance(idp_ref, Mapping) else None
    if not _is_non_empty_string(idp_name):
        missing_fields.append("identityProviderRef.name")

    mapper_type = spec.get("identityProviderMapper") or spec.get("mapperType")
    if not _is_non_empty_string(mapper_type):
        missing_fields.append("identityProviderMapper")

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
        _identity_provider_ref_field_error(spec.get("identityProviderRef")),
        non_empty_string_field_error(spec, "identityProviderMapper"),
        _config_field_error(spec.get("config", {})),
    ]

    return [error for error in errors if error is not None]


def _identity_provider_ref_field_error(idp_ref: Any) -> str | None:
    if not isinstance(idp_ref, Mapping):
        return "identityProviderRef must be an object"

    if "name" in idp_ref and not _is_non_empty_string(idp_ref["name"]):
        return "identityProviderRef.name must be a non-empty string"

    if "alias" in idp_ref and not _is_non_empty_string(idp_ref["alias"]):
        return "identityProviderRef.alias must be a non-empty string"

    return None


def _config_field_error(config: Any) -> str | None:
    if not isinstance(config, Mapping):
        return "config must be an object with string values"

    if all(_is_non_empty_string(key) and isinstance(value, str) for key, value in config.items()):
        return None

    return "config must use non-empty string keys and string values"


def _identity_provider_mapper_ready_condition(
    reconcile_result: IdentityProviderMapperReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if reconcile_result.ready_reason == IDENTITY_PROVIDER_MAPPER_CREATED_REASON:
        message = "Keycloak identity provider mapper was created."
    elif reconcile_result.ready_reason == IDENTITY_PROVIDER_MAPPER_UPDATED_REASON:
        message = "Keycloak identity provider mapper was updated."
    elif reconcile_result.ready_reason == IDENTITY_PROVIDER_MAPPER_DRIFT_DETECTED_REASON:
        message = (
            "Keycloak identity provider mapper has modeled drift and was not changed "
            "because managementPolicy is ObserveOnly."
        )
    elif reconcile_result.ready_reason == IDENTITY_PROVIDER_MAPPER_MISSING_REASON:
        message = (
            "Keycloak identity provider mapper is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = "Keycloak identity provider mapper already matches desired state."

    return ready_condition(
        reconcile_result.ready_status,
        reconcile_result.ready_reason,
        message,
        now=now,
    )


def _identity_provider_mapper_drift_condition(
    reconcile_result: IdentityProviderMapperReconcileResult,
    *,
    now: datetime | None,
) -> Condition:
    if not reconcile_result.drift_detected:
        return drift_detected_condition(
            "False",
            NO_DRIFT_DETECTED_REASON,
            "Keycloak identity provider mapper has no modeled drift.",
            now=now,
        )

    if reconcile_result.ready_reason == IDENTITY_PROVIDER_MAPPER_MISSING_REASON:
        message = (
            "Keycloak identity provider mapper is missing and was not created because "
            "managementPolicy is ObserveOnly."
        )
    else:
        message = (
            "Keycloak identity provider mapper differs from desired state and was not "
            "changed because managementPolicy is ObserveOnly."
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
            IDENTITY_PROVIDER_MAPPER_CREATED_REASON: (
                "Normal",
                "Keycloak identity provider mapper was created.",
            ),
            IDENTITY_PROVIDER_MAPPER_UPDATED_REASON: (
                "Normal",
                "Keycloak identity provider mapper was updated.",
            ),
            IDENTITY_PROVIDER_MAPPER_DRIFT_DETECTED_REASON: (
                "Warning",
                "Keycloak identity provider mapper has modeled drift and was left unchanged.",
            ),
            IDENTITY_PROVIDER_MAPPER_MISSING_REASON: (
                "Warning",
                "Keycloak identity provider mapper is missing and was left unchanged.",
            ),
        },
    )


def _emit_delete_event(body: kopf.Body, deletion_policy: str) -> None:
    if deletion_policy == DELETION_POLICY_DELETE:
        kopf.event(
            body,
            type="Normal",
            reason="IdentityProviderMapperDeleted",
            message=(
                "Keycloak identity provider mapper was deleted because deletionPolicy "
                "is Delete."
            ),
        )
        return

    kopf.event(
        body,
        type="Normal",
        reason=IDENTITY_PROVIDER_MAPPER_ORPHANED_REASON,
        message=(
            "Keycloak identity provider mapper was left in Keycloak because deletionPolicy "
            "is Orphan."
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


def _identity_provider_mappers_path(realm: str, alias: str) -> str:
    return f"{_identity_providers_path(realm)}/{quote(alias, safe='')}/mappers"


def _identity_provider_mapper_path(realm: str, alias: str, mapper_id: str) -> str:
    return f"{_identity_provider_mappers_path(realm, alias)}/{quote(mapper_id, safe='')}"


def _delete_temporary_error(message: str) -> kopf.TemporaryError:
    return kopf.TemporaryError(message, delay=DELETE_RETRY_DELAY_SECONDS)


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())

