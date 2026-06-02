from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import kopf
import pytest

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_CLIENT_ROLE_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import (
    keycloak_client_role,
    reconciliation,
)
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAuthenticationError,
    KeycloakRequestError,
    KeycloakResourceNotFoundError,
)
from clouddicted_keycloak_config_operator.status import (
    CONDITION_DRIFT_DETECTED,
    CONDITION_READY,
    ready_condition,
)

NOW = datetime(2026, 5, 28, 10, 30, 45, tzinfo=UTC)
OLD_NOW = datetime(2026, 5, 28, 9, 30, 45, tzinfo=UTC)


@dataclass
class FakeTargetResolver:
    target: keycloak_client_role.TargetConnection

    def __post_init__(self) -> None:
        self.calls: list[dict[str, str | None]] = []

    def __call__(
        self,
        *,
        target_name: str,
        namespace: str | None,
    ) -> keycloak_client_role.TargetConnection:
        self.calls.append({"target_name": target_name, "namespace": namespace})
        return self.target


class FakeKeycloakClient:
    def __init__(
        self,
        *,
        clients_result: list[dict[str, Any]] | None = None,
        role_result: dict[str, Any] | None = None,
        auth_error: Exception | None = None,
        get_role_error: Exception | None = None,
        get_client_error: Exception | None = None,
        post_error: Exception | None = None,
        put_error: Exception | None = None,
        delete_error: Exception | None = None,
    ) -> None:
        self.clients_result = [_existing_client()] if clients_result is None else clients_result
        self.role_result = _existing_client_role() if role_result is None else role_result
        self.auth_error = auth_error
        self.get_role_error = get_role_error
        self.get_client_error = get_client_error
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

        if method == "GET" and path.endswith("/clients"):
            if self.get_client_error is not None:
                raise self.get_client_error
            return self.clients_result

        if method == "GET":
            if self.get_role_error is not None:
                error = self.get_role_error
                self.get_role_error = None
                raise error
            return self.role_result

        if method == "POST":
            if self.post_error is not None:
                raise self.post_error
            payload = kwargs.get("json")
            if isinstance(payload, dict):
                self.role_result = {"id": "created-client-role-uuid", **payload}
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


def test_keycloak_client_role_resource_registration_values() -> None:
    assert keycloak_client_role.KEYCLOAK_CLIENT_ROLE_RESOURCE == {
        "group": API_GROUP,
        "version": API_VERSION,
        "plural": KEYCLOAK_CLIENT_ROLE_PLURAL,
    }


def test_main_imports_keycloak_client_role_handler_module() -> None:
    assert keycloak_client_role in main.REGISTERED_HANDLER_MODULES


def test_patch_keycloak_client_role_status_reports_invalid_spec() -> None:
    patch: dict[str, Any] = {}

    keycloak_client_role.patch_keycloak_client_role_status(
        spec={"targetRef": {}, "clientRef": {}},
        status={},
        patch=patch,
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "False",
        "reason": keycloak_client_role.INVALID_SPEC_REASON,
        "message": (
            "Missing required KeycloakClientRole spec fields: targetRef.name, realm, "
            "clientRef.name, name."
        ),
        "lastTransitionTime": "2026-05-28T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": keycloak_client_role.INVALID_SPEC_REASON,
        "message": (
            "Drift detection was skipped because the KeycloakClientRole spec is invalid."
        ),
        "lastTransitionTime": "2026-05-28T10:30:45Z",
    }


def test_patch_keycloak_client_role_status_reports_invalid_field_values() -> None:
    patch: dict[str, Any] = {}

    keycloak_client_role.patch_keycloak_client_role_status(
        spec=_client_role_spec(
            description="",
            management_policy="Apply",
            deletion_policy="Remove",
        ),
        status={},
        patch=patch,
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
        now=NOW,
    )

    assert _conditions_by_type(patch)[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "False",
        "reason": keycloak_client_role.INVALID_SPEC_REASON,
        "message": (
            "Invalid KeycloakClientRole spec fields: managementPolicy must be one "
            "of: `ObserveOnly`, `Reconcile`; deletionPolicy must be one of: "
            "`Delete`, `Orphan`; description must be a non-empty string."
        ),
        "lastTransitionTime": "2026-05-28T10:30:45Z",
    }


def test_patch_keycloak_client_role_status_reports_target_resolution_failure() -> None:
    patch: dict[str, Any] = {}

    retry = keycloak_client_role.patch_keycloak_client_role_status(
        spec=_client_role_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_unavailable_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    ready = conditions[CONDITION_READY]
    assert ready["status"] == "False"
    assert ready["reason"] == keycloak_client_role.TARGET_UNAVAILABLE_REASON
    assert retry == reconciliation.RetryRequest(
        keycloak_client_role.TARGET_UNAVAILABLE_REASON,
        ready["message"],
    )


def test_patch_keycloak_client_role_status_observes_existing_matching_role() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        clients_result=[_existing_client(clientId="example web")],
        role_result=_existing_client_role(name="reader/admin", description="Reader role"),
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    keycloak_client_role.patch_keycloak_client_role_status(
        spec=_client_role_spec(
            realm="example realm",
            client_name="example web",
            name="reader/admin",
            description="Reader role",
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
        "reason": keycloak_client_role.CLIENT_ROLE_OBSERVED_REASON,
        "message": "Keycloak client role already matches desired state.",
        "lastTransitionTime": "2026-05-28T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "False",
        "reason": keycloak_client_role.NO_DRIFT_DETECTED_REASON,
        "message": "Keycloak client role has no modeled drift.",
        "lastTransitionTime": "2026-05-28T10:30:45Z",
    }
    assert resolver.calls == [{"target_name": "example-keycloak", "namespace": "apps"}]
    assert keycloak_client_factory.calls == [
        {
            "base_url": "https://keycloak.example.test",
            "username": "kc-admin",
            "password": "secret-password",
        }
    ]
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example%20realm/clients",
            {"params": {"clientId": "example web"}},
        ),
        (
            "GET",
            "realms/example%20realm/clients/client-uuid/roles/reader%2Fadmin",
            {},
        ),
    ]
    assert patch["status"]["remoteId"] == "client-role-uuid"
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password"})


def test_patch_keycloak_client_role_status_creates_missing_role() -> None:
    keycloak_client = FakeKeycloakClient(
        get_role_error=KeycloakResourceNotFoundError("client role missing")
    )
    patch: dict[str, Any] = {}

    keycloak_client_role.patch_keycloak_client_role_status(
        spec=_client_role_spec(description="Example reader role"),
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
        == keycloak_client_role.CLIENT_ROLE_CREATED_REASON
    )
    assert keycloak_client.requests == [
        ("GET", "realms/example/clients", {"params": {"clientId": "example-web"}}),
        ("GET", "realms/example/clients/client-uuid/roles/reader", {}),
        (
            "POST",
            "realms/example/clients/client-uuid/roles",
            {"json": {"name": "reader", "description": "Example reader role"}},
        ),
        ("GET", "realms/example/clients/client-uuid/roles/reader", {}),
    ]
    assert patch["status"]["remoteId"] == "created-client-role-uuid"


def test_patch_keycloak_client_role_status_observe_only_reports_missing_role() -> None:
    keycloak_client = FakeKeycloakClient(
        get_role_error=KeycloakResourceNotFoundError("client role missing")
    )
    patch: dict[str, Any] = {}

    keycloak_client_role.patch_keycloak_client_role_status(
        spec=_client_role_spec(
            management_policy=keycloak_client_role.MANAGEMENT_POLICY_OBSERVE_ONLY
        ),
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
        "status": "False",
        "reason": keycloak_client_role.CLIENT_ROLE_MISSING_REASON,
        "message": (
            "Keycloak client role is missing and was not created because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-28T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED]["status"] == "True"
    assert keycloak_client.requests == [
        ("GET", "realms/example/clients", {"params": {"clientId": "example-web"}}),
        ("GET", "realms/example/clients/client-uuid/roles/reader", {}),
    ]
    assert patch["status"]["remoteId"] is None


def test_patch_keycloak_client_role_status_updates_description_drift() -> None:
    keycloak_client = FakeKeycloakClient(
        role_result=_existing_client_role(description="Old description", composite=True)
    )
    patch: dict[str, Any] = {}

    keycloak_client_role.patch_keycloak_client_role_status(
        spec=_client_role_spec(description="Example reader role"),
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
        "reason": keycloak_client_role.CLIENT_ROLE_UPDATED_REASON,
        "message": "Keycloak client role was updated.",
        "lastTransitionTime": "2026-05-28T10:30:45Z",
    }
    assert keycloak_client.requests == [
        ("GET", "realms/example/clients", {"params": {"clientId": "example-web"}}),
        ("GET", "realms/example/clients/client-uuid/roles/reader", {}),
        (
            "PUT",
            "realms/example/clients/client-uuid/roles/reader",
            {
                "json": {
                    "id": "client-role-uuid",
                    "name": "reader",
                    "description": "Example reader role",
                    "composite": True,
                }
            },
        ),
    ]
    assert patch["status"]["remoteId"] == "client-role-uuid"


def test_patch_keycloak_client_role_status_observe_only_reports_description_drift() -> None:
    keycloak_client = FakeKeycloakClient(
        role_result=_existing_client_role(description="Old description")
    )
    patch: dict[str, Any] = {}

    keycloak_client_role.patch_keycloak_client_role_status(
        spec=_client_role_spec(
            description="Example reader role",
            management_policy=keycloak_client_role.MANAGEMENT_POLICY_OBSERVE_ONLY,
        ),
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
        == keycloak_client_role.CLIENT_ROLE_DRIFT_DETECTED_REASON
    )
    assert conditions[CONDITION_DRIFT_DETECTED]["status"] == "True"
    assert keycloak_client.requests == [
        ("GET", "realms/example/clients", {"params": {"clientId": "example-web"}}),
        ("GET", "realms/example/clients/client-uuid/roles/reader", {}),
    ]


def test_patch_keycloak_client_role_status_reports_auth_failure_safely() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_client_role.patch_keycloak_client_role_status(
        spec=_client_role_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_client_role.AUTHENTICATION_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert keycloak_client.requests == []
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_client_role_status_reports_request_failure_safely() -> None:
    keycloak_client = FakeKeycloakClient(
        get_client_error=KeycloakRequestError("failed for kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_client_role.patch_keycloak_client_role_status(
        spec=_client_role_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_client_role.REQUEST_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_delete_keycloak_client_role_resource_orphan_noop_without_external_calls() -> None:
    keycloak_client_role.delete_keycloak_client_role_resource(
        spec=_client_role_spec(),
        namespace="apps",
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
    )


def test_delete_keycloak_client_role_resource_delete_removes_existing_role() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        role_result=_existing_client_role(name="reader/admin")
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)

    keycloak_client_role.delete_keycloak_client_role_resource(
        spec=_client_role_spec(
            name="reader/admin",
            deletion_policy=keycloak_client_role.DELETION_POLICY_DELETE,
        ),
        namespace="apps",
        target_resolver=resolver,
        keycloak_client_factory=keycloak_client_factory,
    )

    assert resolver.calls == [{"target_name": "example-keycloak", "namespace": "apps"}]
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == [
        ("GET", "realms/example/clients", {"params": {"clientId": "example-web"}}),
        ("GET", "realms/example/clients/client-uuid/roles/reader%2Fadmin", {}),
        ("DELETE", "realms/example/clients/client-uuid/roles/reader%2Fadmin", {}),
    ]


def test_delete_keycloak_client_role_resource_delete_missing_role_noop() -> None:
    keycloak_client = FakeKeycloakClient(
        get_role_error=KeycloakResourceNotFoundError("client role missing")
    )

    keycloak_client_role.delete_keycloak_client_role_resource(
        spec=_client_role_spec(deletion_policy=keycloak_client_role.DELETION_POLICY_DELETE),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert keycloak_client.requests == [
        ("GET", "realms/example/clients", {"params": {"clientId": "example-web"}}),
        ("GET", "realms/example/clients/client-uuid/roles/reader", {}),
    ]


def test_delete_keycloak_client_role_resource_missing_parent_client_noop() -> None:
    keycloak_client = FakeKeycloakClient(clients_result=[])

    keycloak_client_role.delete_keycloak_client_role_resource(
        spec=_client_role_spec(deletion_policy=keycloak_client_role.DELETION_POLICY_DELETE),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert keycloak_client.requests == [
        ("GET", "realms/example/clients", {"params": {"clientId": "example-web"}}),
    ]


def test_delete_keycloak_client_role_resource_invalid_spec_is_permanent_failure() -> None:
    with pytest.raises(kopf.PermanentError) as exc_info:
        keycloak_client_role.delete_keycloak_client_role_resource(
            spec={"targetRef": {}, "clientRef": {}},
            namespace="apps",
            target_resolver=_failing_target_resolver,
            keycloak_client_factory=_failing_keycloak_client_factory,
        )

    assert str(exc_info.value) == (
        "KeycloakClientRole deletion skipped because spec is invalid."
    )


def test_delete_keycloak_client_role_resource_auth_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_client_role.delete_keycloak_client_role_resource(
            spec=_client_role_spec(
                deletion_policy=keycloak_client_role.DELETION_POLICY_DELETE
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakClientRole deletion failed because Keycloak authentication failed."
    )
    assert keycloak_client.requests == []


def test_patch_keycloak_client_role_status_preserves_stable_transition_time() -> None:
    patch: dict[str, Any] = {}

    keycloak_client_role.patch_keycloak_client_role_status(
        spec=_client_role_spec(),
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
    assert ready["reason"] == keycloak_client_role.CLIENT_ROLE_OBSERVED_REASON
    assert ready["lastTransitionTime"] == "2026-05-28T09:30:45Z"


def _target_resolver() -> FakeTargetResolver:
    return FakeTargetResolver(
        keycloak_client_role.TargetConnection(
            url="https://keycloak.example.test",
            username="kc-admin",
            password="secret-password",
        )
    )


def _client_role_spec(
    *,
    realm: str = "example",
    client_name: str = "example-web",
    name: str = "reader",
    description: str | None = None,
    management_policy: str | None = None,
    deletion_policy: str | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "targetRef": {"name": "example-keycloak"},
        "realm": realm,
        "clientRef": {"name": client_name},
        "name": name,
    }
    if description is not None:
        spec["description"] = description
    if management_policy is not None:
        spec["managementPolicy"] = management_policy
    if deletion_policy is not None:
        spec["deletionPolicy"] = deletion_policy

    return spec


def _existing_client(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "client-uuid",
        "clientId": "example-web",
    }
    payload.update(overrides)
    return payload


def _existing_client_role(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "client-role-uuid",
        "name": "reader",
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
) -> keycloak_client_role.TargetConnection:
    raise AssertionError(f"unexpected target resolution: {namespace}/{target_name}")


def _unavailable_target_resolver(
    *,
    target_name: str,
    namespace: str | None,
) -> keycloak_client_role.TargetConnection:
    raise keycloak_client_role.TargetResolutionError(
        f"target unavailable: {namespace}/{target_name}"
    )


def _failing_keycloak_client_factory(
    *,
    base_url: str,
    username: str,
    password: str,
) -> FakeKeycloakClient:
    raise AssertionError(f"unexpected Keycloak client: {base_url}, {username}, {password}")
