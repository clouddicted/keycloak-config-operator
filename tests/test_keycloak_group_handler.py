from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import kopf
import pytest

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_GROUP_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import keycloak_group, reconciliation
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAuthenticationError,
    KeycloakRequestError,
)
from clouddicted_keycloak_config_operator.status import (
    CONDITION_DRIFT_DETECTED,
    CONDITION_READY,
    ready_condition,
)

NOW = datetime(2026, 6, 2, 10, 30, 45, tzinfo=UTC)
OLD_NOW = datetime(2026, 6, 2, 9, 30, 45, tzinfo=UTC)


@dataclass
class FakeTargetResolver:
    target: keycloak_group.TargetConnection

    def __post_init__(self) -> None:
        self.calls: list[dict[str, str | None]] = []

    def __call__(
        self,
        *,
        target_name: str,
        namespace: str | None,
    ) -> keycloak_group.TargetConnection:
        self.calls.append({"target_name": target_name, "namespace": namespace})
        return self.target


class FakeKeycloakClient:
    def __init__(
        self,
        *,
        groups_result: list[dict[str, Any]] | None = None,
        auth_error: Exception | None = None,
        get_error: Exception | None = None,
        post_error: Exception | None = None,
        put_error: Exception | None = None,
        delete_error: Exception | None = None,
    ) -> None:
        self.groups_result = [_existing_group()] if groups_result is None else groups_result
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
            return self.groups_result

        if method == "POST":
            if self.post_error is not None:
                raise self.post_error
            payload = kwargs.get("json")
            if isinstance(payload, dict):
                self.groups_result = [{"id": "created-group-uuid", "path": "/users", **payload}]
            return None

        if method == "PUT":
            if self.put_error is not None:
                raise self.put_error
            payload = kwargs.get("json")
            if isinstance(payload, dict):
                self.groups_result = [payload]
            return None

        if method == "DELETE":
            if self.delete_error is not None:
                raise self.delete_error
            self.groups_result = []
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


def test_keycloak_group_resource_registration_values() -> None:
    assert keycloak_group.KEYCLOAK_GROUP_RESOURCE == {
        "group": API_GROUP,
        "version": API_VERSION,
        "plural": KEYCLOAK_GROUP_PLURAL,
    }


def test_main_imports_keycloak_group_handler_module() -> None:
    assert keycloak_group in main.REGISTERED_HANDLER_MODULES


def test_patch_keycloak_group_status_reports_invalid_spec() -> None:
    patch: dict[str, Any] = {}

    keycloak_group.patch_keycloak_group_status(
        spec={"targetRef": {}},
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
        "reason": keycloak_group.INVALID_SPEC_REASON,
        "message": (
            "Missing required KeycloakGroup spec fields: targetRef.name, realm, name."
        ),
        "lastTransitionTime": "2026-06-02T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED]["status"] == "Unknown"


def test_patch_keycloak_group_status_reports_invalid_field_values() -> None:
    patch: dict[str, Any] = {}

    keycloak_group.patch_keycloak_group_status(
        spec=_group_spec(
            attributes={"team": [""]},
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
        "Invalid KeycloakGroup spec fields: managementPolicy must be one of: "
        "`ObserveOnly`, `Reconcile`; deletionPolicy must be one of: `Delete`, "
        "`Orphan`; attributes must be a map of non-empty string keys to lists "
        "of non-empty strings."
    )


def test_patch_keycloak_group_status_reports_target_resolution_failure() -> None:
    patch: dict[str, Any] = {}

    retry = keycloak_group.patch_keycloak_group_status(
        spec=_group_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_unavailable_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
        now=NOW,
    )

    ready = _conditions_by_type(patch)[CONDITION_READY]
    assert ready["status"] == "False"
    assert retry == reconciliation.RetryRequest(
        keycloak_group.TARGET_UNAVAILABLE_REASON,
        ready["message"],
    )


def test_patch_keycloak_group_status_observes_existing_matching_group() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        groups_result=[
            _existing_group(
                name="example users",
                path="/example users",
                attributes={"team": ["platform"]},
            )
        ]
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    keycloak_group.patch_keycloak_group_status(
        spec=_group_spec(
            realm="example realm",
            name="example users",
            attributes={"team": ["platform"]},
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=resolver,
        keycloak_client_factory=keycloak_client_factory,
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["status"] == "True"
    assert conditions[CONDITION_READY]["reason"] == keycloak_group.GROUP_OBSERVED_REASON
    assert conditions[CONDITION_DRIFT_DETECTED]["status"] == "False"
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
            "realms/example%20realm/groups",
            {"params": {"search": "example users", "exact": "true"}},
        ),
    ]
    assert patch["status"]["remoteId"] == "group-uuid"
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password"})


def test_patch_keycloak_group_status_creates_missing_group() -> None:
    keycloak_client = FakeKeycloakClient(groups_result=[])
    patch: dict[str, Any] = {}

    keycloak_group.patch_keycloak_group_status(
        spec=_group_spec(attributes={"team": ["platform"]}),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["status"] == "True"
    assert conditions[CONDITION_READY]["reason"] == keycloak_group.GROUP_CREATED_REASON
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/groups",
            {"params": {"search": "users", "exact": "true"}},
        ),
        (
            "POST",
            "realms/example/groups",
            {"json": {"name": "users", "attributes": {"team": ["platform"]}}},
        ),
        (
            "GET",
            "realms/example/groups",
            {"params": {"search": "users", "exact": "true"}},
        ),
    ]
    assert patch["status"]["remoteId"] == "created-group-uuid"


def test_patch_keycloak_group_status_observe_only_missing_group_reports_drift() -> None:
    patch: dict[str, Any] = {}

    keycloak_group.patch_keycloak_group_status(
        spec=_group_spec(
            management_policy=keycloak_group.MANAGEMENT_POLICY_OBSERVE_ONLY
        ),
        status={},
        patch=patch,
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(FakeKeycloakClient(groups_result=[])),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["status"] == "False"
    assert conditions[CONDITION_READY]["reason"] == keycloak_group.GROUP_MISSING_REASON
    assert conditions[CONDITION_DRIFT_DETECTED]["status"] == "True"


def test_patch_keycloak_group_status_updates_attribute_drift() -> None:
    keycloak_client = FakeKeycloakClient(
        groups_result=[_existing_group(attributes={"team": ["old"]})]
    )
    patch: dict[str, Any] = {}

    keycloak_group.patch_keycloak_group_status(
        spec=_group_spec(attributes={"team": ["platform"]}),
        status={},
        patch=patch,
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["reason"] == keycloak_group.GROUP_UPDATED_REASON
    assert keycloak_client.requests[-1] == (
        "PUT",
        "realms/example/groups/group-uuid",
        {
            "json": {
                "id": "group-uuid",
                "name": "users",
                "path": "/users",
                "attributes": {"team": ["platform"]},
            }
        },
    )


def test_patch_keycloak_group_status_observe_only_drift_does_not_update() -> None:
    keycloak_client = FakeKeycloakClient(
        groups_result=[_existing_group(attributes={"team": ["old"]})]
    )
    patch: dict[str, Any] = {}

    keycloak_group.patch_keycloak_group_status(
        spec=_group_spec(
            attributes={"team": ["platform"]},
            management_policy=keycloak_group.MANAGEMENT_POLICY_OBSERVE_ONLY,
        ),
        status={},
        patch=patch,
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["reason"] == keycloak_group.GROUP_DRIFT_DETECTED_REASON
    assert conditions[CONDITION_DRIFT_DETECTED]["status"] == "True"
    assert [request[0] for request in keycloak_client.requests] == ["GET"]


def test_patch_keycloak_group_status_auth_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_group.patch_keycloak_group_status(
        spec=_group_spec(),
        status={},
        patch=patch,
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_group.AUTHENTICATION_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_group_status_request_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakRequestError("bad kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_group.patch_keycloak_group_status(
        spec=_group_spec(),
        status={},
        patch=patch,
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_group.REQUEST_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_delete_keycloak_group_resource_orphan_noop_without_external_calls() -> None:
    keycloak_group.delete_keycloak_group_resource(
        spec=_group_spec(),
        namespace="apps",
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
    )


def test_delete_keycloak_group_resource_delete_removes_existing_group() -> None:
    keycloak_client = FakeKeycloakClient()

    keycloak_group.delete_keycloak_group_resource(
        spec=_group_spec(deletion_policy=keycloak_group.DELETION_POLICY_DELETE),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/groups",
            {"params": {"search": "users", "exact": "true"}},
        ),
        ("DELETE", "realms/example/groups/group-uuid", {}),
    ]


def test_delete_keycloak_group_resource_delete_missing_group_noop() -> None:
    keycloak_client = FakeKeycloakClient(groups_result=[])

    keycloak_group.delete_keycloak_group_resource(
        spec=_group_spec(deletion_policy=keycloak_group.DELETION_POLICY_DELETE),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/groups",
            {"params": {"search": "users", "exact": "true"}},
        ),
    ]


def test_delete_keycloak_group_resource_invalid_spec_is_permanent_failure() -> None:
    with pytest.raises(kopf.PermanentError) as exc_info:
        keycloak_group.delete_keycloak_group_resource(
            spec={"targetRef": {}},
            namespace="apps",
            target_resolver=_failing_target_resolver,
            keycloak_client_factory=_failing_keycloak_client_factory,
        )

    assert str(exc_info.value) == "KeycloakGroup deletion skipped because spec is invalid."


def test_patch_keycloak_group_status_preserves_stable_transition_time() -> None:
    patch: dict[str, Any] = {}

    keycloak_group.patch_keycloak_group_status(
        spec=_group_spec(),
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
    assert ready["reason"] == keycloak_group.GROUP_OBSERVED_REASON
    assert ready["lastTransitionTime"] == "2026-06-02T09:30:45Z"


def _target_resolver() -> FakeTargetResolver:
    return FakeTargetResolver(
        keycloak_group.TargetConnection(
            url="https://keycloak.example.test",
            username="kc-admin",
            password="secret-password",
        )
    )


def _group_spec(
    *,
    realm: str = "example",
    name: str = "users",
    attributes: dict[str, list[str]] | None = None,
    management_policy: str | None = None,
    deletion_policy: str | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "targetRef": {"name": "example-keycloak"},
        "realm": realm,
        "name": name,
    }
    if attributes is not None:
        spec["attributes"] = attributes
    if management_policy is not None:
        spec["managementPolicy"] = management_policy
    if deletion_policy is not None:
        spec["deletionPolicy"] = deletion_policy

    return spec


def _existing_group(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "group-uuid",
        "name": "users",
        "path": "/users",
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
) -> keycloak_group.TargetConnection:
    raise AssertionError(
        f"target resolver should not be called for {target_name} in {namespace}"
    )


def _unavailable_target_resolver(
    *,
    target_name: str,
    namespace: str | None,
) -> keycloak_group.TargetConnection:
    raise keycloak_group.TargetResolutionError(
        f"target {target_name!r} in {namespace!r} is unavailable"
    )


def _failing_keycloak_client_factory(**_: Any) -> FakeKeycloakClient:
    raise AssertionError("Keycloak client factory should not be called")
