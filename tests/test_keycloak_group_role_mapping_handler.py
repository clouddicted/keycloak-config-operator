from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import kopf
import pytest

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_GROUP_ROLE_MAPPING_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import (
    keycloak_group_role_mapping,
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

NOW = datetime(2026, 6, 2, 11, 30, 45, tzinfo=UTC)
OLD_NOW = datetime(2026, 6, 2, 10, 30, 45, tzinfo=UTC)


@dataclass
class FakeTargetResolver:
    target: keycloak_group_role_mapping.TargetConnection

    def __post_init__(self) -> None:
        self.calls: list[dict[str, str | None]] = []

    def __call__(
        self,
        *,
        target_name: str,
        namespace: str | None,
    ) -> keycloak_group_role_mapping.TargetConnection:
        self.calls.append({"target_name": target_name, "namespace": namespace})
        return self.target


class FakeKeycloakClient:
    def __init__(
        self,
        *,
        groups_result: list[dict[str, Any]] | None = None,
        clients_result: list[dict[str, Any]] | None = None,
        realm_role_result: dict[str, Any] | None = None,
        client_role_result: dict[str, Any] | None = None,
        assigned_realm_roles: list[dict[str, Any]] | None = None,
        assigned_client_roles: list[dict[str, Any]] | None = None,
        auth_error: Exception | None = None,
        realm_role_error: Exception | None = None,
        client_role_error: Exception | None = None,
        request_error: Exception | None = None,
    ) -> None:
        self.groups_result = [_existing_group()] if groups_result is None else groups_result
        self.clients_result = [_existing_client()] if clients_result is None else clients_result
        self.realm_role_result = (
            _existing_realm_role() if realm_role_result is None else realm_role_result
        )
        self.client_role_result = (
            _existing_client_role() if client_role_result is None else client_role_result
        )
        self.assigned_realm_roles = (
            [_existing_realm_role()] if assigned_realm_roles is None else assigned_realm_roles
        )
        self.assigned_client_roles = (
            [_existing_client_role()]
            if assigned_client_roles is None
            else assigned_client_roles
        )
        self.auth_error = auth_error
        self.realm_role_error = realm_role_error
        self.client_role_error = client_role_error
        self.request_error = request_error
        self.authenticate_calls = 0
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def authenticate(self) -> None:
        self.authenticate_calls += 1
        if self.auth_error is not None:
            raise self.auth_error

    def request(self, method: str, path: str, **kwargs: Any) -> Any | None:
        self.requests.append((method, path, kwargs))
        if self.request_error is not None:
            raise self.request_error

        if method == "GET" and path.endswith("/groups"):
            return self.groups_result

        if method == "GET" and path.endswith("/clients"):
            return self.clients_result

        if method == "GET" and "/clients/client-uuid/roles/" in path:
            if self.client_role_error is not None:
                raise self.client_role_error
            return self.client_role_result

        if method == "GET" and "/roles/" in path:
            if self.realm_role_error is not None:
                raise self.realm_role_error
            return self.realm_role_result

        if method == "GET" and path.endswith("/role-mappings/realm"):
            return self.assigned_realm_roles

        if method == "GET" and path.endswith("/role-mappings/clients/client-uuid"):
            return self.assigned_client_roles

        if method == "POST" and path.endswith("/role-mappings/realm"):
            self.assigned_realm_roles.extend(kwargs.get("json", []))
            return None

        if method == "POST" and path.endswith("/role-mappings/clients/client-uuid"):
            self.assigned_client_roles.extend(kwargs.get("json", []))
            return None

        if method == "DELETE" and path.endswith("/role-mappings/realm"):
            self.assigned_realm_roles = []
            return None

        if method == "DELETE" and path.endswith("/role-mappings/clients/client-uuid"):
            self.assigned_client_roles = []
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


def test_keycloak_group_role_mapping_resource_registration_values() -> None:
    assert keycloak_group_role_mapping.KEYCLOAK_GROUP_ROLE_MAPPING_RESOURCE == {
        "group": API_GROUP,
        "version": API_VERSION,
        "plural": KEYCLOAK_GROUP_ROLE_MAPPING_PLURAL,
    }


def test_main_imports_keycloak_group_role_mapping_handler_module() -> None:
    assert keycloak_group_role_mapping in main.REGISTERED_HANDLER_MODULES


def test_patch_keycloak_group_role_mapping_status_reports_invalid_spec() -> None:
    patch: dict[str, Any] = {}

    keycloak_group_role_mapping.patch_keycloak_group_role_mapping_status(
        spec={"targetRef": {}, "groupRef": {}, "role": {}},
        status={},
        patch=patch,
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["message"] == (
        "Missing required KeycloakGroupRoleMapping spec fields: targetRef.name, "
        "realm, groupRef.name, role.type, role.roleRef.name."
    )
    assert conditions[CONDITION_DRIFT_DETECTED]["status"] == "Unknown"


def test_patch_keycloak_group_role_mapping_status_reports_invalid_field_values() -> None:
    patch: dict[str, Any] = {}

    keycloak_group_role_mapping.patch_keycloak_group_role_mapping_status(
        spec=_mapping_spec(
            role_type="Realm",
            management_policy="Apply",
            deletion_policy="Remove",
        ),
        status={},
        patch=patch,
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
        now=NOW,
    )

    assert _conditions_by_type(patch)[CONDITION_READY]["message"] == (
        "Invalid KeycloakGroupRoleMapping spec fields: managementPolicy must be "
        "one of: `ObserveOnly`, `Reconcile`; deletionPolicy must be one of: "
        "`Delete`, `Orphan`; role.type must be one of: `ClientRole`, `RealmRole`."
    )


def test_patch_keycloak_group_role_mapping_status_observes_existing_realm_mapping() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient()
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    keycloak_group_role_mapping.patch_keycloak_group_role_mapping_status(
        spec=_mapping_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=resolver,
        keycloak_client_factory=keycloak_client_factory,
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["status"] == "True"
    assert (
        conditions[CONDITION_READY]["reason"]
        == keycloak_group_role_mapping.GROUP_ROLE_MAPPING_OBSERVED_REASON
    )
    assert conditions[CONDITION_DRIFT_DETECTED]["status"] == "False"
    assert resolver.calls == [{"target_name": "example-keycloak", "namespace": "apps"}]
    assert keycloak_client_factory.calls == [
        {
            "base_url": "https://keycloak.example.test",
            "username": "kc-admin",
            "password": "secret-password",
        }
    ]
    assert patch["status"] == {
        "groupRemoteId": "group-uuid",
        "roleRemoteId": "realm-role-uuid",
        "clientRemoteId": None,
        "conditions": patch["status"]["conditions"],
    }
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password"})


def test_patch_keycloak_group_role_mapping_status_assigns_missing_realm_mapping() -> None:
    keycloak_client = FakeKeycloakClient(assigned_realm_roles=[])
    patch: dict[str, Any] = {}

    keycloak_group_role_mapping.patch_keycloak_group_role_mapping_status(
        spec=_mapping_spec(),
        status={},
        patch=patch,
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["status"] == "True"
    assert (
        conditions[CONDITION_READY]["reason"]
        == keycloak_group_role_mapping.GROUP_ROLE_MAPPING_ASSIGNED_REASON
    )
    assert keycloak_client.requests[-1] == (
        "POST",
        "realms/example/groups/group-uuid/role-mappings/realm",
        {"json": [{"id": "realm-role-uuid", "name": "admin"}]},
    )


def test_patch_keycloak_group_role_mapping_status_observe_only_missing_mapping() -> None:
    keycloak_client = FakeKeycloakClient(assigned_realm_roles=[])
    patch: dict[str, Any] = {}

    keycloak_group_role_mapping.patch_keycloak_group_role_mapping_status(
        spec=_mapping_spec(
            management_policy=keycloak_group_role_mapping.MANAGEMENT_POLICY_OBSERVE_ONLY
        ),
        status={},
        patch=patch,
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["status"] == "False"
    assert (
        conditions[CONDITION_READY]["reason"]
        == keycloak_group_role_mapping.GROUP_ROLE_MAPPING_MISSING_REASON
    )
    assert conditions[CONDITION_DRIFT_DETECTED]["status"] == "True"
    assert [request[0] for request in keycloak_client.requests] == ["GET", "GET", "GET"]


def test_patch_keycloak_group_role_mapping_status_assigns_missing_client_mapping() -> None:
    keycloak_client = FakeKeycloakClient(assigned_client_roles=[])
    patch: dict[str, Any] = {}

    keycloak_group_role_mapping.patch_keycloak_group_role_mapping_status(
        spec=_mapping_spec(role_type="ClientRole", role_name="reader", client_name="web"),
        status={},
        patch=patch,
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    assert _conditions_by_type(patch)[CONDITION_READY]["reason"] == (
        keycloak_group_role_mapping.GROUP_ROLE_MAPPING_ASSIGNED_REASON
    )
    assert patch["status"]["clientRemoteId"] == "client-uuid"
    assert keycloak_client.requests[-1] == (
        "POST",
        "realms/example/groups/group-uuid/role-mappings/clients/client-uuid",
        {"json": [{"id": "client-role-uuid", "name": "reader"}]},
    )


def test_patch_keycloak_group_role_mapping_status_reports_missing_group() -> None:
    patch: dict[str, Any] = {}

    retry = keycloak_group_role_mapping.patch_keycloak_group_role_mapping_status(
        spec=_mapping_spec(),
        status={},
        patch=patch,
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(
            FakeKeycloakClient(groups_result=[])
        ),
        now=NOW,
    )

    ready = _conditions_by_type(patch)[CONDITION_READY]
    assert retry == reconciliation.RetryRequest(
        keycloak_group_role_mapping.GROUP_MISSING_REASON,
        ready["message"],
    )
    assert patch["status"]["groupRemoteId"] is None


def test_patch_keycloak_group_role_mapping_status_auth_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_group_role_mapping.patch_keycloak_group_role_mapping_status(
        spec=_mapping_spec(),
        status={},
        patch=patch,
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_group_role_mapping.AUTHENTICATION_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_group_role_mapping_status_request_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        request_error=KeycloakRequestError("bad kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_group_role_mapping.patch_keycloak_group_role_mapping_status(
        spec=_mapping_spec(),
        status={},
        patch=patch,
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_group_role_mapping.REQUEST_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_delete_keycloak_group_role_mapping_resource_orphan_noop_without_calls() -> None:
    keycloak_group_role_mapping.delete_keycloak_group_role_mapping_resource(
        spec=_mapping_spec(),
        namespace="apps",
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
    )


def test_delete_keycloak_group_role_mapping_resource_delete_removes_mapping() -> None:
    keycloak_client = FakeKeycloakClient()

    keycloak_group_role_mapping.delete_keycloak_group_role_mapping_resource(
        spec=_mapping_spec(
            deletion_policy=keycloak_group_role_mapping.DELETION_POLICY_DELETE
        ),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert keycloak_client.requests[-1] == (
        "DELETE",
        "realms/example/groups/group-uuid/role-mappings/realm",
        {"json": [{"id": "realm-role-uuid", "name": "admin"}]},
    )


def test_delete_keycloak_group_role_mapping_resource_missing_mapping_noop() -> None:
    keycloak_client = FakeKeycloakClient(assigned_realm_roles=[])

    keycloak_group_role_mapping.delete_keycloak_group_role_mapping_resource(
        spec=_mapping_spec(
            deletion_policy=keycloak_group_role_mapping.DELETION_POLICY_DELETE
        ),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert [request[0] for request in keycloak_client.requests] == ["GET", "GET", "GET"]


def test_delete_keycloak_group_role_mapping_resource_missing_dependency_noop() -> None:
    keycloak_client = FakeKeycloakClient(
        realm_role_error=KeycloakResourceNotFoundError("missing role")
    )

    keycloak_group_role_mapping.delete_keycloak_group_role_mapping_resource(
        spec=_mapping_spec(
            deletion_policy=keycloak_group_role_mapping.DELETION_POLICY_DELETE
        ),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert [request[0] for request in keycloak_client.requests] == ["GET", "GET"]


def test_delete_keycloak_group_role_mapping_resource_invalid_spec_is_permanent() -> None:
    with pytest.raises(kopf.PermanentError) as exc_info:
        keycloak_group_role_mapping.delete_keycloak_group_role_mapping_resource(
            spec={"targetRef": {}, "groupRef": {}, "role": {}},
            namespace="apps",
            target_resolver=_failing_target_resolver,
            keycloak_client_factory=_failing_keycloak_client_factory,
        )

    assert str(exc_info.value) == (
        "KeycloakGroupRoleMapping deletion skipped because spec is invalid."
    )


def test_patch_keycloak_group_role_mapping_status_preserves_transition_time() -> None:
    patch: dict[str, Any] = {}

    keycloak_group_role_mapping.patch_keycloak_group_role_mapping_status(
        spec=_mapping_spec(),
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
    assert ready["reason"] == keycloak_group_role_mapping.GROUP_ROLE_MAPPING_OBSERVED_REASON
    assert ready["lastTransitionTime"] == "2026-06-02T10:30:45Z"


def _target_resolver() -> FakeTargetResolver:
    return FakeTargetResolver(
        keycloak_group_role_mapping.TargetConnection(
            url="https://keycloak.example.test",
            username="kc-admin",
            password="secret-password",
        )
    )


def _mapping_spec(
    *,
    role_type: str = "RealmRole",
    role_name: str = "admin",
    client_name: str | None = None,
    management_policy: str | None = None,
    deletion_policy: str | None = None,
) -> dict[str, Any]:
    role: dict[str, Any] = {
        "type": role_type,
        "roleRef": {"name": role_name},
    }
    if client_name is not None:
        role["clientRef"] = {"name": client_name}

    spec: dict[str, Any] = {
        "targetRef": {"name": "example-keycloak"},
        "realm": "example",
        "groupRef": {"name": "users"},
        "role": role,
    }
    if management_policy is not None:
        spec["managementPolicy"] = management_policy
    if deletion_policy is not None:
        spec["deletionPolicy"] = deletion_policy

    return spec


def _existing_group(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"id": "group-uuid", "name": "users", "path": "/users"}
    payload.update(overrides)
    return payload


def _existing_client(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"id": "client-uuid", "clientId": "web"}
    payload.update(overrides)
    return payload


def _existing_realm_role(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"id": "realm-role-uuid", "name": "admin"}
    payload.update(overrides)
    return payload


def _existing_client_role(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"id": "client-role-uuid", "name": "reader"}
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
) -> keycloak_group_role_mapping.TargetConnection:
    raise AssertionError(
        f"target resolver should not be called for {target_name} in {namespace}"
    )


def _failing_keycloak_client_factory(**_: Any) -> FakeKeycloakClient:
    raise AssertionError("Keycloak client factory should not be called")
