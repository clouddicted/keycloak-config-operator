import base64
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import kopf
import pytest

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_TARGET_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import keycloak_target, reconciliation
from clouddicted_keycloak_config_operator.keycloak_client import KeycloakAuthenticationError
from clouddicted_keycloak_config_operator.status import (
    CONDITION_AUTHENTICATED,
    CONDITION_READY,
    CONDITION_SECRET_READY,
    authenticated_condition,
    ready_condition,
    secret_ready_condition,
)

NOW = datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC)
OLD_NOW = datetime(2026, 5, 22, 9, 30, 45, tzinfo=UTC)


@dataclass
class FakeSecret:
    data: dict[str, str] | None


class FakeCoreV1Api:
    def __init__(self, secrets: dict[tuple[str, str], FakeSecret]) -> None:
        self.secrets = secrets
        self.calls: list[tuple[str, str]] = []

    def read_namespaced_secret(self, *, name: str, namespace: str) -> FakeSecret:
        self.calls.append((namespace, name))
        return self.secrets[(namespace, name)]


class FailingCoreV1Api:
    def read_namespaced_secret(self, *, name: str, namespace: str) -> FakeSecret:
        raise AssertionError(f"unexpected Secret read: {namespace}/{name}")


class FakeKeycloakClient:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.authenticate_calls = 0

    def authenticate(self) -> None:
        self.authenticate_calls += 1
        if self.error is not None:
            raise self.error


class FakeKeycloakClientFactory:
    def __init__(self, client: FakeKeycloakClient) -> None:
        self.client = client
        self.calls: list[dict[str, str]] = []

    def __call__(self, *, base_url: str, username: str, password: str) -> FakeKeycloakClient:
        self.calls.append(
            {
                "base_url": base_url,
                "username": username,
                "password": password,
            }
        )
        return self.client


def test_keycloak_target_resource_registration_values() -> None:
    assert keycloak_target.KEYCLOAK_TARGET_RESOURCE == {
        "group": API_GROUP,
        "version": API_VERSION,
        "plural": KEYCLOAK_TARGET_PLURAL,
    }


def test_main_imports_keycloak_target_handler_module() -> None:
    assert keycloak_target in main.REGISTERED_HANDLER_MODULES


def test_configure_sets_operator_settings() -> None:
    settings = kopf.OperatorSettings()

    main.configure(settings)

    assert settings.posting.level == logging.INFO
    assert settings.persistence.finalizer == f"{API_GROUP}/finalizer"
    assert isinstance(settings.persistence.progress_storage, kopf.AnnotationsProgressStorage)
    assert isinstance(settings.persistence.diffbase_storage, kopf.AnnotationsDiffBaseStorage)
    assert settings.persistence.diffbase_storage.ignored_fields == ["status"]


def test_configure_presents_framework_logs_under_operator_name() -> None:
    handler = logging.NullHandler()
    original_handlers = logging.getLogger().handlers[:]

    try:
        logging.getLogger().handlers[:] = [handler]
        main.configure(kopf.OperatorSettings())

        kopf_record = logging.LogRecord(
            "kopf.objects",
            logging.ERROR,
            __file__,
            1,
            "message",
            (),
            None,
        )
        app_record = logging.LogRecord(
            "clouddicted_keycloak_config_operator.main",
            logging.INFO,
            __file__,
            1,
            "message",
            (),
            None,
        )

        assert handler.filter(kopf_record)
        assert handler.filter(app_record)
        assert kopf_record.name == main.LOG_RECORD_NAME
        assert app_record.name == "clouddicted_keycloak_config_operator.main"
    finally:
        logging.getLogger().handlers[:] = original_handlers


def test_reconcile_keycloak_target_requeues_retryable_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch: dict[str, Any] = {}
    calls: list[dict[str, Any]] = []
    events: list[tuple[str, str]] = []

    def fake_patch_keycloak_target_status(**kwargs: Any) -> reconciliation.RetryRequest:
        calls.append(kwargs)
        return reconciliation.RetryRequest("RetryReason", "retry message")

    monkeypatch.setattr(
        keycloak_target,
        "patch_keycloak_target_status",
        fake_patch_keycloak_target_status,
    )
    monkeypatch.setattr(
        reconciliation.kopf,
        "event",
        lambda body, type, reason, message: events.append((type, reason, message)),
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_target.reconcile_keycloak_target(
            body={"metadata": {"name": "example-keycloak", "namespace": "apps"}},
            spec={},
            status={},
            patch=patch,
            namespace="apps",
        )

    assert str(exc_info.value) == "retry message"
    assert exc_info.value.delay == reconciliation.DEFAULT_RETRY_DELAY_SECONDS
    assert events == [("Warning", "RetryReason", "retry message")]
    assert calls[0]["spec"] == {}
    assert calls[0]["status"] == {}
    assert calls[0]["patch"] is patch
    assert calls[0]["namespace"] == "apps"


def test_patch_keycloak_target_status_reports_successful_authentication() -> None:
    core_v1_api = _core_v1_api(username="kc-admin", password="secret-password")
    keycloak_client = FakeKeycloakClient()
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    retry = keycloak_target.patch_keycloak_target_status(
        spec=_target_spec(),
        status={},
        patch=patch,
        namespace="apps",
        core_v1_api=core_v1_api,
        keycloak_client_factory=keycloak_client_factory,
        now=NOW,
    )

    assert retry is None
    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "True",
        "reason": keycloak_target.RECONCILED_REASON,
        "message": "KeycloakTarget credentials are valid.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert conditions[CONDITION_SECRET_READY]["status"] == "True"
    assert conditions[CONDITION_SECRET_READY]["reason"] == keycloak_target.SECRET_LOADED_REASON
    assert conditions[CONDITION_AUTHENTICATED]["status"] == "True"
    assert conditions[CONDITION_AUTHENTICATED]["reason"] == keycloak_target.AUTHENTICATED_REASON
    assert core_v1_api.calls == [("apps", "keycloak-admin")]
    assert keycloak_client_factory.calls == [
        {
            "base_url": "https://keycloak.example.test",
            "username": "kc-admin",
            "password": "secret-password",
        }
    ]
    assert keycloak_client.authenticate_calls == 1
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password"})


def test_patch_keycloak_target_status_reports_invalid_spec_without_external_calls() -> None:
    patch: dict[str, Any] = {}

    retry = keycloak_target.patch_keycloak_target_status(
        spec={"adminCredentials": {"secretRef": {}}},
        status={},
        patch=patch,
        core_v1_api=FailingCoreV1Api(),
        keycloak_client_factory=_failing_keycloak_client_factory,
        now=NOW,
    )

    assert retry is None
    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "False",
        "reason": keycloak_target.INVALID_SPEC_REASON,
        "message": (
            "Missing required KeycloakTarget spec fields: "
            "url, adminCredentials.secretRef.name."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert conditions[CONDITION_SECRET_READY]["status"] == "Unknown"
    assert conditions[CONDITION_SECRET_READY]["reason"] == keycloak_target.INVALID_SPEC_REASON
    assert conditions[CONDITION_AUTHENTICATED]["status"] == "Unknown"
    assert conditions[CONDITION_AUTHENTICATED]["reason"] == keycloak_target.INVALID_SPEC_REASON


def test_patch_keycloak_target_status_reports_secret_loading_failure() -> None:
    core_v1_api = FakeCoreV1Api({("apps", "keycloak-admin"): FakeSecret(data=None)})
    patch: dict[str, Any] = {}

    retry = keycloak_target.patch_keycloak_target_status(
        spec=_target_spec(),
        status={},
        patch=patch,
        namespace="apps",
        core_v1_api=core_v1_api,
        keycloak_client_factory=_failing_keycloak_client_factory,
        now=NOW,
    )

    assert retry == reconciliation.RetryRequest(
        keycloak_target.SECRET_UNAVAILABLE_REASON,
        "KeycloakTarget credentials could not be loaded.",
    )
    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["status"] == "False"
    assert conditions[CONDITION_READY]["reason"] == keycloak_target.SECRET_UNAVAILABLE_REASON
    assert conditions[CONDITION_SECRET_READY]["status"] == "False"
    assert conditions[CONDITION_SECRET_READY]["reason"] == keycloak_target.SECRET_UNAVAILABLE_REASON
    assert conditions[CONDITION_AUTHENTICATED]["status"] == "Unknown"
    assert (
        conditions[CONDITION_AUTHENTICATED]["reason"]
        == keycloak_target.SECRET_UNAVAILABLE_REASON
    )
    assert core_v1_api.calls == [("apps", "keycloak-admin")]


def test_patch_keycloak_target_status_reports_auth_failure_without_secret_values() -> None:
    core_v1_api = _core_v1_api(username="kc-admin", password="secret-password")
    keycloak_client = FakeKeycloakClient(
        KeycloakAuthenticationError("invalid credentials for kc-admin: secret-password")
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    retry = keycloak_target.patch_keycloak_target_status(
        spec=_target_spec(),
        status={},
        patch=patch,
        namespace="apps",
        core_v1_api=core_v1_api,
        keycloak_client_factory=keycloak_client_factory,
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_target.AUTHENTICATION_FAILED_REASON,
        conditions[CONDITION_AUTHENTICATED]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert conditions[CONDITION_READY]["reason"] == keycloak_target.AUTHENTICATION_FAILED_REASON
    assert conditions[CONDITION_SECRET_READY]["status"] == "True"
    assert conditions[CONDITION_SECRET_READY]["reason"] == keycloak_target.SECRET_LOADED_REASON
    assert conditions[CONDITION_AUTHENTICATED]["status"] == "False"
    assert (
        conditions[CONDITION_AUTHENTICATED]["reason"]
        == keycloak_target.AUTHENTICATION_FAILED_REASON
    )
    assert conditions[CONDITION_AUTHENTICATED]["message"] == (
        "KeycloakTarget authentication failed: invalid credentials for "
        "<redacted>: <redacted>."
    )
    assert keycloak_client.authenticate_calls == 1
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password"})


def test_patch_keycloak_target_status_reports_auth_failure_cause() -> None:
    core_v1_api = _core_v1_api(username="kc-admin", password="secret-password")
    keycloak_client = FakeKeycloakClient(_authentication_error_with_cause())
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    retry = keycloak_target.patch_keycloak_target_status(
        spec=_target_spec(),
        status={},
        patch=patch,
        namespace="apps",
        core_v1_api=core_v1_api,
        keycloak_client_factory=keycloak_client_factory,
        now=NOW,
    )

    message = _conditions_by_type(patch)[CONDITION_AUTHENTICATED]["message"]
    assert retry == reconciliation.RetryRequest(
        keycloak_target.AUTHENTICATION_FAILED_REASON,
        message,
    )
    assert message.startswith("KeycloakTarget authentication failed:")
    assert "Keycloak authentication request failed" in message
    assert "WRONG_VERSION_NUMBER" in message


def test_patch_keycloak_target_status_preserves_stable_transition_times() -> None:
    core_v1_api = _core_v1_api(username="kc-admin", password="secret-password")
    keycloak_client_factory = FakeKeycloakClientFactory(FakeKeycloakClient())
    patch: dict[str, Any] = {}

    retry = keycloak_target.patch_keycloak_target_status(
        spec=_target_spec(),
        status={
            "conditions": [
                ready_condition("True", "OldReady", "Old ready message.", now=OLD_NOW),
                secret_ready_condition("True", "OldSecret", "Old secret message.", now=OLD_NOW),
                authenticated_condition("True", "OldAuth", "Old auth message.", now=OLD_NOW),
            ],
        },
        patch=patch,
        namespace="apps",
        core_v1_api=core_v1_api,
        keycloak_client_factory=keycloak_client_factory,
        now=NOW,
    )

    assert retry is None
    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["reason"] == keycloak_target.RECONCILED_REASON
    assert conditions[CONDITION_READY]["lastTransitionTime"] == "2026-05-22T09:30:45Z"
    assert conditions[CONDITION_SECRET_READY]["reason"] == keycloak_target.SECRET_LOADED_REASON
    assert (
        conditions[CONDITION_SECRET_READY]["lastTransitionTime"] == "2026-05-22T09:30:45Z"
    )
    assert conditions[CONDITION_AUTHENTICATED]["reason"] == keycloak_target.AUTHENTICATED_REASON
    assert (
        conditions[CONDITION_AUTHENTICATED]["lastTransitionTime"] == "2026-05-22T09:30:45Z"
    )


def _core_v1_api(*, username: str, password: str) -> FakeCoreV1Api:
    return FakeCoreV1Api(
        {
            ("apps", "keycloak-admin"): FakeSecret(
                data={
                    "username": _b64(username),
                    "password": _b64(password),
                }
            )
        }
    )


def _target_spec() -> dict[str, Any]:
    return {
        "url": "https://keycloak.example.test",
        "adminCredentials": {"secretRef": {"name": "keycloak-admin"}},
    }


def _conditions_by_type(patch: dict[str, Any]) -> dict[str, dict[str, str]]:
    return {
        condition["type"]: condition
        for condition in patch["status"]["conditions"]
        if isinstance(condition, dict)
    }


def _condition_messages(patch: dict[str, Any]) -> set[str]:
    return {
        word
        for condition in patch["status"]["conditions"]
        for word in condition["message"].split()
    }


def _failing_keycloak_client_factory(
    *,
    base_url: str,
    username: str,
    password: str,
) -> FakeKeycloakClient:
    raise AssertionError(f"unexpected Keycloak client: {base_url}, {username}, {password}")


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _authentication_error_with_cause() -> KeycloakAuthenticationError:
    try:
        try:
            raise OSError("[SSL: WRONG_VERSION_NUMBER] wrong version number")
        except OSError as exc:
            raise KeycloakAuthenticationError(
                "Keycloak authentication request failed"
            ) from exc
    except KeycloakAuthenticationError as exc:
        return exc
