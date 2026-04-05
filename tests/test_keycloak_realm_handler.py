from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_REALM_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import keycloak_realm, reconciliation
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAuthenticationError,
    KeycloakRequestError,
    KeycloakResourceNotFoundError,
)
from clouddicted_keycloak_config_operator.status import CONDITION_READY, ready_condition

NOW = datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC)
OLD_NOW = datetime(2026, 5, 22, 9, 30, 45, tzinfo=UTC)


@dataclass
class FakeTargetResolver:
    target: keycloak_realm.TargetConnection

    def __post_init__(self) -> None:
        self.calls: list[dict[str, str | None]] = []

    def __call__(
        self,
        *,
        target_name: str,
        namespace: str | None,
    ) -> keycloak_realm.TargetConnection:
        self.calls.append({"target_name": target_name, "namespace": namespace})
        return self.target


class FakeKeycloakClient:
    def __init__(
        self,
        *,
        auth_error: Exception | None = None,
        get_error: Exception | None = None,
        post_error: Exception | None = None,
    ) -> None:
        self.auth_error = auth_error
        self.get_error = get_error
        self.post_error = post_error
        self.authenticate_calls = 0
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def authenticate(self) -> None:
        self.authenticate_calls += 1
        if self.auth_error is not None:
            raise self.auth_error

    def request(self, method: str, path: str, **kwargs: Any) -> Any | None:
        self.requests.append((method, path, kwargs))

        if method == "GET":
            if self.get_error is not None:
                raise self.get_error
            return {"realm": "example"}

        if method == "POST":
            if self.post_error is not None:
                raise self.post_error
            return None

        raise AssertionError(f"unexpected request: {method} {path}")


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


def test_keycloak_realm_resource_registration_values() -> None:
    assert keycloak_realm.KEYCLOAK_REALM_RESOURCE == {
        "group": API_GROUP,
        "version": API_VERSION,
        "plural": KEYCLOAK_REALM_PLURAL,
    }


def test_main_imports_keycloak_realm_handler_module() -> None:
    assert keycloak_realm in main.REGISTERED_HANDLER_MODULES


def test_patch_keycloak_realm_status_reports_invalid_spec_without_external_calls() -> None:
    patch: dict[str, Any] = {}

    keycloak_realm.patch_keycloak_realm_status(
        spec={"targetRef": {}},
        status={},
        patch=patch,
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
        now=NOW,
    )

    assert _conditions_by_type(patch)[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "False",
        "reason": keycloak_realm.INVALID_SPEC_REASON,
        "message": "Missing required KeycloakRealm spec fields: targetRef.name, realm.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }


def test_patch_keycloak_realm_status_reports_target_resolution_failure() -> None:
    patch: dict[str, Any] = {}

    retry = keycloak_realm.patch_keycloak_realm_status(
        spec=_realm_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_unavailable_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
        now=NOW,
    )

    ready = _conditions_by_type(patch)[CONDITION_READY]
    assert ready["status"] == "False"
    assert ready["reason"] == keycloak_realm.TARGET_UNAVAILABLE_REASON
    assert retry == reconciliation.RetryRequest(
        keycloak_realm.TARGET_UNAVAILABLE_REASON,
        ready["message"],
    )


def test_patch_keycloak_realm_status_observes_existing_realm() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient()
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    retry = keycloak_realm.patch_keycloak_realm_status(
        spec=_realm_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=resolver,
        keycloak_client_factory=keycloak_client_factory,
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry is None
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "True",
        "reason": keycloak_realm.REALM_OBSERVED_REASON,
        "message": "Keycloak realm already exists.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert resolver.calls == [{"target_name": "example-keycloak", "namespace": "apps"}]
    assert keycloak_client_factory.calls == [
        {
            "base_url": "https://keycloak.example.test",
            "username": "kc-admin",
            "password": "secret-password",
        }
    ]
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == [("GET", "realms/example", {})]
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password"})


def test_patch_keycloak_realm_status_creates_missing_realm() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakResourceNotFoundError("realm missing")
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    keycloak_realm.patch_keycloak_realm_status(
        spec=_realm_spec(display_name="Example"),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=keycloak_client_factory,
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["status"] == "True"
    assert conditions[CONDITION_READY]["reason"] == keycloak_realm.REALM_CREATED_REASON
    assert keycloak_client.requests == [
        ("GET", "realms/example", {}),
        (
            "POST",
            "realms",
            {"json": {"realm": "example", "enabled": True, "displayName": "Example"}},
        ),
    ]


def test_patch_keycloak_realm_status_reports_auth_failure_without_secret_values() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_realm.patch_keycloak_realm_status(
        spec=_realm_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_realm.AUTHENTICATION_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert conditions[CONDITION_READY]["reason"] == keycloak_realm.AUTHENTICATION_FAILED_REASON
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_realm_status_reports_request_failure_without_secret_values() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakRequestError("failed for kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_realm.patch_keycloak_realm_status(
        spec=_realm_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_realm.REQUEST_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert conditions[CONDITION_READY]["reason"] == keycloak_realm.REQUEST_FAILED_REASON
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_realm_status_preserves_stable_transition_time() -> None:
    patch: dict[str, Any] = {}

    keycloak_realm.patch_keycloak_realm_status(
        spec=_realm_spec(),
        status={
            "conditions": [
                ready_condition("True", "OldReady", "Old ready message.", now=OLD_NOW),
            ],
        },
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(FakeKeycloakClient()),
        now=NOW,
    )

    ready = _conditions_by_type(patch)[CONDITION_READY]
    assert ready["reason"] == keycloak_realm.REALM_OBSERVED_REASON
    assert ready["lastTransitionTime"] == "2026-05-22T09:30:45Z"


def _target_resolver() -> FakeTargetResolver:
    return FakeTargetResolver(
        keycloak_realm.TargetConnection(
            url="https://keycloak.example.test",
            username="kc-admin",
            password="secret-password",
        )
    )


def _realm_spec(*, display_name: str | None = None) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "targetRef": {"name": "example-keycloak"},
        "realm": "example",
    }
    if display_name is not None:
        spec["displayName"] = display_name

    return spec


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


def _failing_target_resolver(
    *,
    target_name: str,
    namespace: str | None,
) -> keycloak_realm.TargetConnection:
    raise AssertionError(f"unexpected target resolution: {namespace}/{target_name}")


def _unavailable_target_resolver(
    *,
    target_name: str,
    namespace: str | None,
) -> keycloak_realm.TargetConnection:
    raise keycloak_realm.TargetResolutionError(
        f"target unavailable: {namespace}/{target_name}"
    )


def _failing_keycloak_client_factory(
    *,
    base_url: str,
    username: str,
    password: str,
) -> FakeKeycloakClient:
    raise AssertionError(f"unexpected Keycloak client: {base_url}, {username}, {password}")
