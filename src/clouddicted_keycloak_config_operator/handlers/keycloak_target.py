"""Kopf handlers for KeycloakTarget resources."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

import kopf
from kubernetes import client as kubernetes_client
from kubernetes.client.exceptions import ApiException

from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_TARGET_PLURAL,
)
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAdminClient,
    KeycloakClientError,
)
from clouddicted_keycloak_config_operator.redaction import redact_text
from clouddicted_keycloak_config_operator.secrets import (
    SecretCredentials,
    SecretRefError,
    load_secret_credentials,
)
from clouddicted_keycloak_config_operator.status import (
    Condition,
    authenticated_condition,
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
INVALID_SPEC_REASON = "InvalidSpec"
RECONCILED_REASON = "Reconciled"
SECRET_LOADED_REASON = "SecretLoaded"
SECRET_UNAVAILABLE_REASON = "SecretUnavailable"
_CONDITION_FIELDS = ("type", "status", "reason", "message", "lastTransitionTime")
_MAX_FAILURE_DETAIL_LENGTH = 300
EventRecorder = Callable[[str, str], None]


class KeycloakAuthenticator(Protocol):
    def authenticate(self) -> None:
        """Authenticate to Keycloak."""


class KeycloakClientFactory(Protocol):
    def __call__(
        self,
        *,
        base_url: str,
        username: str,
        password: str,
    ) -> KeycloakAuthenticator:
        """Create a Keycloak authenticator."""


@dataclass(frozen=True)
class TargetSpec:
    url: str
    secret_ref: Mapping[str, Any]


@kopf.on.create(**KEYCLOAK_TARGET_RESOURCE)
@kopf.on.update(**KEYCLOAK_TARGET_RESOURCE)
@kopf.on.resume(**KEYCLOAK_TARGET_RESOURCE)
def reconcile_keycloak_target(
    body: kopf.Body,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    logger: logging.Logger | None = None,
    **_: Any,
) -> None:
    """Validate KeycloakTarget credentials and patch status."""
    patch_keycloak_target_status(
        spec=spec,
        status=status,
        patch=patch,
        namespace=namespace,
        event_recorder=lambda reason, message: kopf.warn(
            body,
            reason=reason,
            message=message,
        ),
        logger=logger,
    )


def patch_keycloak_target_status(
    *,
    spec: Mapping[str, Any] | None,
    status: Mapping[str, Any] | None,
    patch: MutableMapping[str, Any],
    namespace: str | None = None,
    core_v1_api: Any | None = None,
    keycloak_client_factory: KeycloakClientFactory = KeycloakAdminClient,
    event_recorder: EventRecorder | None = None,
    logger: logging.Logger | None = None,
    now: datetime | None = None,
) -> None:
    """Patch KeycloakTarget status after checking Secret credentials and authentication."""
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
            ],
        )
        return

    try:
        credentials = load_secret_credentials(
            core_v1_api or kubernetes_client.CoreV1Api(),
            namespace,
            target_spec.secret_ref,
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
            ],
        )
        return

    try:
        keycloak_client = keycloak_client_factory(
            base_url=target_spec.url,
            username=credentials.username,
            password=credentials.password,
        )
        keycloak_client.authenticate()
    except KeycloakClientError as exc:
        failure_message = _authentication_failure_message(exc, credentials)
        _report_warning(
            event_recorder,
            logger,
            reason=AUTHENTICATION_FAILED_REASON,
            message=failure_message,
        )
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
            ],
        )
        return

    _set_conditions(
        patch,
        conditions,
        [
            ready_condition(
                "True",
                RECONCILED_REASON,
                "KeycloakTarget credentials are valid.",
                now=now,
            ),
            secret_ready_condition(
                "True",
                SECRET_LOADED_REASON,
                "Referenced credentials Secret is readable.",
                now=now,
            ),
            authenticated_condition(
                "True",
                AUTHENTICATED_REASON,
                "Keycloak authentication succeeded.",
                now=now,
            ),
        ],
    )


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

    return TargetSpec(url=url.strip(), secret_ref=secret_ref)


def _set_conditions(
    patch: MutableMapping[str, Any],
    existing_conditions: Sequence[Mapping[str, str]],
    new_conditions: Sequence[Mapping[str, str]],
) -> None:
    conditions = list(existing_conditions)
    for condition in new_conditions:
        conditions = upsert_condition(conditions, condition)

    status_patch = patch.setdefault("status", {})
    status_patch["conditions"] = conditions


def _authentication_failure_message(
    error: KeycloakClientError,
    credentials: SecretCredentials,
) -> str:
    detail = _failure_detail(error)
    redacted_detail = redact_text(
        detail,
        (credentials.username, credentials.password),
    )
    return f"Keycloak authentication failed: {redacted_detail}."


def _failure_detail(error: BaseException) -> str:
    detail = str(error).strip() or error.__class__.__name__
    cause = error.__cause__
    if cause is not None and str(cause).strip():
        detail = f"{detail}: {cause}"

    return _truncate(detail)


def _truncate(value: str) -> str:
    if len(value) <= _MAX_FAILURE_DETAIL_LENGTH:
        return value

    return f"{value[: _MAX_FAILURE_DETAIL_LENGTH - 3]}..."


def _report_warning(
    event_recorder: EventRecorder | None,
    logger: logging.Logger | None,
    *,
    reason: str,
    message: str,
) -> None:
    if logger is not None:
        logger.warning("%s: %s", reason, message)

    if event_recorder is not None:
        event_recorder(reason, message)


def _missing_required_fields(spec: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(spec, Mapping):
        return ["spec"]

    missing_fields: list[str] = []

    if not _is_non_empty_string(spec.get("url")):
        missing_fields.append("url")

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
