from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import kopf
import pytest

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_CLIENT_SCOPE_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import (
    keycloak_client_scope,
    reconciliation,
)
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAuthenticationError,
    KeycloakRequestError,
)
from clouddicted_keycloak_config_operator.status import CONDITION_READY, ready_condition

NOW = datetime(2026, 5, 24, 10, 30, 45, tzinfo=UTC)
OLD_NOW = datetime(2026, 5, 24, 9, 30, 45, tzinfo=UTC)


@dataclass
class FakeTargetResolver:
    target: keycloak_client_scope.TargetConnection

    def __post_init__(self) -> None:
        self.calls: list[dict[str, str | None]] = []

    def __call__(
        self,
        *,
        target_name: str,
        namespace: str | None,
    ) -> keycloak_client_scope.TargetConnection:
        self.calls.append({"target_name": target_name, "namespace": namespace})
        return self.target


class FakeKeycloakClient:
    def __init__(
        self,
        *,
        scope_result: list[dict[str, Any]] | None = None,
        auth_error: Exception | None = None,
        get_error: Exception | None = None,
        post_error: Exception | None = None,
        put_error: Exception | None = None,
        delete_error: Exception | None = None,
    ) -> None:
        self.scope_result = [_existing_client_scope()] if scope_result is None else scope_result
        self.auth_error = auth_error
        self.get_error = get_error
        self.post_error = post_error
        self.put_error = put_error
        self.delete_error = delete_error
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
            return self.scope_result

        if method == "POST":
            if self.post_error is not None:
                raise self.post_error
            payload = kwargs.get("json")
            if isinstance(payload, dict) and isinstance(payload.get("name"), str):
                self.scope_result.append(
                    {
                        "id": "created-client-scope-uuid",
                        **payload,
                    }
                )
            return None

        if method == "PUT":
            if self.put_error is not None:
                raise self.put_error
            return None

        if method == "DELETE":
            if self.delete_error is not None:
                raise self.delete_error
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


def test_keycloak_client_scope_resource_registration_values() -> None:
    assert keycloak_client_scope.KEYCLOAK_CLIENT_SCOPE_RESOURCE == {
        "group": API_GROUP,
        "version": API_VERSION,
        "plural": KEYCLOAK_CLIENT_SCOPE_PLURAL,
    }


def test_main_imports_keycloak_client_scope_handler_module() -> None:
    assert keycloak_client_scope in main.REGISTERED_HANDLER_MODULES


def test_patch_keycloak_client_scope_status_reports_invalid_spec_without_external_calls() -> None:
    patch: dict[str, Any] = {}

    keycloak_client_scope.patch_keycloak_client_scope_status(
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
        "reason": keycloak_client_scope.INVALID_SPEC_REASON,
        "message": (
            "Missing required KeycloakClientScope spec fields: targetRef.name, realm, name."
        ),
        "lastTransitionTime": "2026-05-24T10:30:45Z",
    }


def test_patch_keycloak_client_scope_status_reports_target_resolution_failure() -> None:
    patch: dict[str, Any] = {}

    retry = keycloak_client_scope.patch_keycloak_client_scope_status(
        spec=_client_scope_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_unavailable_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
        now=NOW,
    )

    ready = _conditions_by_type(patch)[CONDITION_READY]
    assert ready["status"] == "False"
    assert ready["reason"] == keycloak_client_scope.TARGET_UNAVAILABLE_REASON
    assert retry == reconciliation.RetryRequest(
        keycloak_client_scope.TARGET_UNAVAILABLE_REASON,
        ready["message"],
    )


def test_patch_keycloak_client_scope_status_observes_existing_matching_scope() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        scope_result=[
            _existing_client_scope(
                name="profile/read",
                protocol="openid-connect",
                description="Profile scope",
            )
        ],
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    keycloak_client_scope.patch_keycloak_client_scope_status(
        spec=_client_scope_spec(
            realm="example realm",
            name="profile/read",
            description="Profile scope",
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=resolver,
        keycloak_client_factory=keycloak_client_factory,
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "True",
        "reason": keycloak_client_scope.CLIENT_SCOPE_OBSERVED_REASON,
        "message": "Keycloak client scope already matches desired state.",
        "lastTransitionTime": "2026-05-24T10:30:45Z",
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
    assert keycloak_client.requests == [
        ("GET", "realms/example%20realm/client-scopes", {})
    ]
    assert patch["status"]["remoteId"] == "client-scope-uuid"
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password"})


def test_patch_keycloak_client_scope_status_creates_missing_scope_with_default_protocol() -> None:
    keycloak_client = FakeKeycloakClient(scope_result=[])
    patch: dict[str, Any] = {}

    keycloak_client_scope.patch_keycloak_client_scope_status(
        spec=_client_scope_spec(description="Example scope"),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["status"] == "True"
    assert (
        conditions[CONDITION_READY]["reason"]
        == keycloak_client_scope.CLIENT_SCOPE_CREATED_REASON
    )
    assert keycloak_client.requests == [
        ("GET", "realms/example/client-scopes", {}),
        (
            "POST",
            "realms/example/client-scopes",
            {
                "json": {
                    "name": "example-scope",
                    "protocol": "openid-connect",
                    "description": "Example scope",
                }
            },
        ),
        ("GET", "realms/example/client-scopes", {}),
    ]
    assert patch["status"]["remoteId"] == "created-client-scope-uuid"


def test_patch_keycloak_client_scope_status_updates_drift_preserving_fields() -> None:
    keycloak_client = FakeKeycloakClient(
        scope_result=[
            _existing_client_scope(
                description="Old description",
                protocol="saml",
                attributes={"include.in.token.scope": "true"},
            )
        ],
    )
    patch: dict[str, Any] = {}

    keycloak_client_scope.patch_keycloak_client_scope_status(
        spec=_client_scope_spec(description="Example scope"),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "True",
        "reason": keycloak_client_scope.CLIENT_SCOPE_UPDATED_REASON,
        "message": "Keycloak client scope was updated.",
        "lastTransitionTime": "2026-05-24T10:30:45Z",
    }
    assert keycloak_client.requests == [
        ("GET", "realms/example/client-scopes", {}),
        (
            "PUT",
            "realms/example/client-scopes/client-scope-uuid",
            {
                "json": {
                    "id": "client-scope-uuid",
                    "name": "example-scope",
                    "description": "Example scope",
                    "protocol": "openid-connect",
                    "attributes": {"include.in.token.scope": "true"},
                }
            },
        ),
    ]
    assert patch["status"]["remoteId"] == "client-scope-uuid"


def test_patch_keycloak_client_scope_status_reports_auth_failure_without_secret_values() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_client_scope.patch_keycloak_client_scope_status(
        spec=_client_scope_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_client_scope.AUTHENTICATION_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert (
        conditions[CONDITION_READY]["reason"]
        == keycloak_client_scope.AUTHENTICATION_FAILED_REASON
    )
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_client_scope_status_reports_request_failure_without_secret_values() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakRequestError("failed for kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_client_scope.patch_keycloak_client_scope_status(
        spec=_client_scope_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_client_scope.REQUEST_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert conditions[CONDITION_READY]["reason"] == keycloak_client_scope.REQUEST_FAILED_REASON
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_delete_keycloak_client_scope_resource_orphan_noop_without_external_calls() -> None:
    keycloak_client_scope.delete_keycloak_client_scope_resource(
        spec=_client_scope_spec(),
        namespace="apps",
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
    )


def test_delete_keycloak_client_scope_resource_delete_removes_existing_scope() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        scope_result=[_existing_client_scope(name="profile/read")]
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)

    keycloak_client_scope.delete_keycloak_client_scope_resource(
        spec=_client_scope_spec(
            name="profile/read",
            deletion_policy=keycloak_client_scope.DELETION_POLICY_DELETE,
        ),
        namespace="apps",
        target_resolver=resolver,
        keycloak_client_factory=keycloak_client_factory,
    )

    assert resolver.calls == [{"target_name": "example-keycloak", "namespace": "apps"}]
    assert keycloak_client_factory.calls == [
        {
            "base_url": "https://keycloak.example.test",
            "username": "kc-admin",
            "password": "secret-password",
        }
    ]
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == [
        ("GET", "realms/example/client-scopes", {}),
        ("DELETE", "realms/example/client-scopes/client-scope-uuid", {}),
    ]


def test_delete_keycloak_client_scope_resource_delete_missing_scope_noop() -> None:
    keycloak_client = FakeKeycloakClient(scope_result=[])

    keycloak_client_scope.delete_keycloak_client_scope_resource(
        spec=_client_scope_spec(deletion_policy=keycloak_client_scope.DELETION_POLICY_DELETE),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == [("GET", "realms/example/client-scopes", {})]


def test_delete_keycloak_client_scope_resource_delete_missing_id_safe_failure() -> None:
    keycloak_client = FakeKeycloakClient(
        scope_result=[_existing_client_scope(id=None)],
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_client_scope.delete_keycloak_client_scope_resource(
            spec=_client_scope_spec(
                deletion_policy=keycloak_client_scope.DELETION_POLICY_DELETE
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakClientScope deletion failed while calling the Keycloak Admin API."
    )
    assert keycloak_client.requests == [("GET", "realms/example/client-scopes", {})]


def test_delete_keycloak_client_scope_resource_invalid_spec_is_permanent_failure() -> None:
    with pytest.raises(kopf.PermanentError) as exc_info:
        keycloak_client_scope.delete_keycloak_client_scope_resource(
            spec={"targetRef": {}},
            namespace="apps",
            target_resolver=_failing_target_resolver,
            keycloak_client_factory=_failing_keycloak_client_factory,
        )

    assert str(exc_info.value) == (
        "KeycloakClientScope deletion skipped because spec is invalid."
    )


def test_delete_keycloak_client_scope_resource_auth_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_client_scope.delete_keycloak_client_scope_resource(
            spec=_client_scope_spec(
                deletion_policy=keycloak_client_scope.DELETION_POLICY_DELETE
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakClientScope deletion failed because Keycloak authentication failed."
    )
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert {"kc-admin", "secret-password", "token"}.isdisjoint(
        set(str(exc_info.value).split())
    )


def test_delete_keycloak_client_scope_resource_request_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        delete_error=KeycloakRequestError("failed for kc-admin secret-password token")
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_client_scope.delete_keycloak_client_scope_resource(
            spec=_client_scope_spec(
                deletion_policy=keycloak_client_scope.DELETION_POLICY_DELETE
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakClientScope deletion failed while calling the Keycloak Admin API."
    )
    assert keycloak_client.requests == [
        ("GET", "realms/example/client-scopes", {}),
        ("DELETE", "realms/example/client-scopes/client-scope-uuid", {}),
    ]
    assert {"kc-admin", "secret-password", "token"}.isdisjoint(
        set(str(exc_info.value).split())
    )


def test_patch_keycloak_client_scope_status_preserves_stable_transition_time() -> None:
    patch: dict[str, Any] = {}

    keycloak_client_scope.patch_keycloak_client_scope_status(
        spec=_client_scope_spec(),
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
    assert ready["reason"] == keycloak_client_scope.CLIENT_SCOPE_OBSERVED_REASON
    assert ready["lastTransitionTime"] == "2026-05-24T09:30:45Z"


def _target_resolver() -> FakeTargetResolver:
    return FakeTargetResolver(
        keycloak_client_scope.TargetConnection(
            url="https://keycloak.example.test",
            username="kc-admin",
            password="secret-password",
        )
    )


def _client_scope_spec(
    *,
    realm: str = "example",
    name: str = "example-scope",
    description: str | None = None,
    protocol: str | None = None,
    deletion_policy: str | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "targetRef": {"name": "example-keycloak"},
        "realm": realm,
        "name": name,
    }
    if description is not None:
        spec["description"] = description
    if protocol is not None:
        spec["protocol"] = protocol
    if deletion_policy is not None:
        spec["deletionPolicy"] = deletion_policy

    return spec


def _existing_client_scope(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "client-scope-uuid",
        "name": "example-scope",
        "protocol": "openid-connect",
    }
    payload.update(overrides)
    return payload


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
) -> keycloak_client_scope.TargetConnection:
    raise AssertionError(f"unexpected target resolution: {namespace}/{target_name}")


def _unavailable_target_resolver(
    *,
    target_name: str,
    namespace: str | None,
) -> keycloak_client_scope.TargetConnection:
    raise keycloak_client_scope.TargetResolutionError(
        f"target unavailable: {namespace}/{target_name}"
    )


def _failing_keycloak_client_factory(
    *,
    base_url: str,
    username: str,
    password: str,
) -> FakeKeycloakClient:
    raise AssertionError(f"unexpected Keycloak client: {base_url}, {username}, {password}")
