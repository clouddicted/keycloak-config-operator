from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import kopf
import pytest

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_ROLE_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import keycloak_role, reconciliation
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

NOW = datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC)
OLD_NOW = datetime(2026, 5, 22, 9, 30, 45, tzinfo=UTC)


@dataclass
class FakeTargetResolver:
    target: keycloak_role.TargetConnection

    def __post_init__(self) -> None:
        self.calls: list[dict[str, str | None]] = []

    def __call__(
        self,
        *,
        target_name: str,
        namespace: str | None,
    ) -> keycloak_role.TargetConnection:
        self.calls.append({"target_name": target_name, "namespace": namespace})
        return self.target


class FakeKeycloakClient:
    def __init__(
        self,
        *,
        role_result: dict[str, Any] | None = None,
        auth_error: Exception | None = None,
        get_error: Exception | None = None,
        post_error: Exception | None = None,
        put_error: Exception | None = None,
        delete_error: Exception | None = None,
    ) -> None:
        self.role_result = _existing_role() if role_result is None else role_result
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
                error = self.get_error
                self.get_error = None
                raise error
            return self.role_result

        if method == "POST":
            if self.post_error is not None:
                raise self.post_error
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


def test_keycloak_role_resource_registration_values() -> None:
    assert keycloak_role.KEYCLOAK_ROLE_RESOURCE == {
        "group": API_GROUP,
        "version": API_VERSION,
        "plural": KEYCLOAK_ROLE_PLURAL,
    }


def test_main_imports_keycloak_role_handler_module() -> None:
    assert keycloak_role in main.REGISTERED_HANDLER_MODULES


def test_patch_keycloak_role_status_reports_invalid_spec_without_external_calls() -> None:
    patch: dict[str, Any] = {}

    keycloak_role.patch_keycloak_role_status(
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
        "reason": keycloak_role.INVALID_SPEC_REASON,
        "message": (
            "Missing required KeycloakRole spec fields: targetRef.name, realm, name."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": keycloak_role.INVALID_SPEC_REASON,
        "message": "Drift detection was skipped because the KeycloakRole spec is invalid.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }


def test_patch_keycloak_role_status_reports_invalid_field_values() -> None:
    patch: dict[str, Any] = {}

    keycloak_role.patch_keycloak_role_status(
        spec=_role_spec(
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
        "reason": keycloak_role.INVALID_SPEC_REASON,
        "message": (
            "Invalid KeycloakRole spec fields: managementPolicy must be one of: "
            "`ObserveOnly`, `Reconcile`; deletionPolicy must be one of: "
            "`Delete`, `Orphan`; description must be a non-empty string."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }


def test_patch_keycloak_role_status_reports_target_resolution_failure() -> None:
    patch: dict[str, Any] = {}

    retry = keycloak_role.patch_keycloak_role_status(
        spec=_role_spec(),
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
    assert ready["reason"] == keycloak_role.TARGET_UNAVAILABLE_REASON
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": keycloak_role.TARGET_UNAVAILABLE_REASON,
        "message": (
            "Drift detection was skipped because the referenced KeycloakTarget could "
            "not be resolved."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert retry == reconciliation.RetryRequest(
        keycloak_role.TARGET_UNAVAILABLE_REASON,
        ready["message"],
    )


def test_patch_keycloak_role_status_observes_existing_matching_role() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        role_result=_existing_role(name="admin/editor", description="Admin role")
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    keycloak_role.patch_keycloak_role_status(
        spec=_role_spec(realm="example realm", name="admin/editor", description="Admin role"),
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
        "reason": keycloak_role.ROLE_OBSERVED_REASON,
        "message": "Keycloak realm role already matches desired state.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "False",
        "reason": keycloak_role.NO_DRIFT_DETECTED_REASON,
        "message": "Keycloak realm role has no modeled drift.",
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
    assert keycloak_client.requests == [
        ("GET", "realms/example%20realm/roles/admin%2Feditor", {})
    ]
    assert patch["status"]["remoteId"] == "role-uuid"
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password"})


def test_patch_keycloak_role_status_creates_missing_role() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakResourceNotFoundError("role missing")
    )
    patch: dict[str, Any] = {}

    keycloak_role.patch_keycloak_role_status(
        spec=_role_spec(description="Example role"),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["status"] == "True"
    assert conditions[CONDITION_READY]["reason"] == keycloak_role.ROLE_CREATED_REASON
    assert keycloak_client.requests == [
        ("GET", "realms/example/roles/example-role", {}),
        (
            "POST",
            "realms/example/roles",
            {"json": {"name": "example-role", "description": "Example role"}},
        ),
        ("GET", "realms/example/roles/example-role", {}),
    ]
    assert patch["status"]["remoteId"] == "role-uuid"


def test_patch_keycloak_role_status_observe_only_reports_missing_role_without_create() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakResourceNotFoundError("role missing")
    )
    patch: dict[str, Any] = {}

    keycloak_role.patch_keycloak_role_status(
        spec=_role_spec(management_policy=keycloak_role.MANAGEMENT_POLICY_OBSERVE_ONLY),
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
        "reason": keycloak_role.ROLE_MISSING_REASON,
        "message": (
            "Keycloak realm role is missing and was not created because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "True",
        "reason": keycloak_role.ROLE_MISSING_REASON,
        "message": (
            "Keycloak realm role is missing and was not created because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert keycloak_client.requests == [("GET", "realms/example/roles/example-role", {})]
    assert patch["status"]["remoteId"] is None


def test_patch_keycloak_role_status_updates_description_drift_preserving_fields() -> None:
    keycloak_client = FakeKeycloakClient(
        role_result=_existing_role(description="Old description", composite=True)
    )
    patch: dict[str, Any] = {}

    keycloak_role.patch_keycloak_role_status(
        spec=_role_spec(description="Example role"),
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
        "reason": keycloak_role.ROLE_UPDATED_REASON,
        "message": "Keycloak realm role was updated.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert keycloak_client.requests == [
        ("GET", "realms/example/roles/example-role", {}),
        (
            "PUT",
            "realms/example/roles/example-role",
            {
                "json": {
                    "id": "role-uuid",
                    "name": "example-role",
                    "description": "Example role",
                    "composite": True,
                }
            },
        ),
    ]
    assert patch["status"]["remoteId"] == "role-uuid"


def test_patch_keycloak_role_status_observe_only_reports_description_drift() -> None:
    keycloak_client = FakeKeycloakClient(
        role_result=_existing_role(description="Old description", composite=True)
    )
    patch: dict[str, Any] = {}

    keycloak_role.patch_keycloak_role_status(
        spec=_role_spec(
            description="Example role",
            management_policy=keycloak_role.MANAGEMENT_POLICY_OBSERVE_ONLY,
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
        "status": "True",
        "reason": keycloak_role.ROLE_DRIFT_DETECTED_REASON,
        "message": (
            "Keycloak realm role has modeled drift and was not changed because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "True",
        "reason": keycloak_role.ROLE_DRIFT_DETECTED_REASON,
        "message": (
            "Keycloak realm role differs from desired state and was not changed "
            "because managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert keycloak_client.requests == [("GET", "realms/example/roles/example-role", {})]
    assert patch["status"]["remoteId"] == "role-uuid"


def test_patch_keycloak_role_status_reports_auth_failure_without_secret_values() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_role.patch_keycloak_role_status(
        spec=_role_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_role.AUTHENTICATION_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert conditions[CONDITION_READY]["reason"] == keycloak_role.AUTHENTICATION_FAILED_REASON
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_role_status_reports_request_failure_without_secret_values() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakRequestError("failed for kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_role.patch_keycloak_role_status(
        spec=_role_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_role.REQUEST_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert conditions[CONDITION_READY]["reason"] == keycloak_role.REQUEST_FAILED_REASON
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_delete_keycloak_role_resource_orphan_noop_without_external_calls() -> None:
    keycloak_role.delete_keycloak_role_resource(
        spec=_role_spec(),
        namespace="apps",
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
    )


def test_delete_keycloak_role_resource_delete_removes_existing_role() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        role_result=_existing_role(name="admin/editor"),
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)

    keycloak_role.delete_keycloak_role_resource(
        spec=_role_spec(
            name="admin/editor",
            deletion_policy=keycloak_role.DELETION_POLICY_DELETE,
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
        ("GET", "realms/example/roles/admin%2Feditor", {}),
        ("DELETE", "realms/example/roles/admin%2Feditor", {}),
    ]


def test_delete_keycloak_role_resource_delete_missing_role_noop() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakResourceNotFoundError("role missing")
    )

    keycloak_role.delete_keycloak_role_resource(
        spec=_role_spec(deletion_policy=keycloak_role.DELETION_POLICY_DELETE),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == [("GET", "realms/example/roles/example-role", {})]


def test_delete_keycloak_role_resource_invalid_spec_is_permanent_failure() -> None:
    with pytest.raises(kopf.PermanentError) as exc_info:
        keycloak_role.delete_keycloak_role_resource(
            spec={"targetRef": {}},
            namespace="apps",
            target_resolver=_failing_target_resolver,
            keycloak_client_factory=_failing_keycloak_client_factory,
        )

    assert str(exc_info.value) == "KeycloakRole deletion skipped because spec is invalid."


def test_delete_keycloak_role_resource_auth_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_role.delete_keycloak_role_resource(
            spec=_role_spec(deletion_policy=keycloak_role.DELETION_POLICY_DELETE),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakRole deletion failed because Keycloak authentication failed."
    )
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert {"kc-admin", "secret-password", "token"}.isdisjoint(
        set(str(exc_info.value).split())
    )


def test_delete_keycloak_role_resource_request_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        delete_error=KeycloakRequestError("failed for kc-admin secret-password token")
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_role.delete_keycloak_role_resource(
            spec=_role_spec(deletion_policy=keycloak_role.DELETION_POLICY_DELETE),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakRole deletion failed while calling the Keycloak Admin API."
    )
    assert keycloak_client.requests == [
        ("GET", "realms/example/roles/example-role", {}),
        ("DELETE", "realms/example/roles/example-role", {}),
    ]
    assert {"kc-admin", "secret-password", "token"}.isdisjoint(
        set(str(exc_info.value).split())
    )


def test_patch_keycloak_role_status_preserves_stable_transition_time() -> None:
    patch: dict[str, Any] = {}

    keycloak_role.patch_keycloak_role_status(
        spec=_role_spec(),
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
    assert ready["reason"] == keycloak_role.ROLE_OBSERVED_REASON
    assert ready["lastTransitionTime"] == "2026-05-22T09:30:45Z"


def _target_resolver() -> FakeTargetResolver:
    return FakeTargetResolver(
        keycloak_role.TargetConnection(
            url="https://keycloak.example.test",
            username="kc-admin",
            password="secret-password",
        )
    )


def _role_spec(
    *,
    realm: str = "example",
    name: str = "example-role",
    description: str | None = None,
    management_policy: str | None = None,
    deletion_policy: str | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "targetRef": {"name": "example-keycloak"},
        "realm": realm,
        "name": name,
    }
    if description is not None:
        spec["description"] = description
    if management_policy is not None:
        spec["managementPolicy"] = management_policy
    if deletion_policy is not None:
        spec["deletionPolicy"] = deletion_policy

    return spec


def _existing_role(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "role-uuid",
        "name": "example-role",
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
) -> keycloak_role.TargetConnection:
    raise AssertionError(f"unexpected target resolution: {namespace}/{target_name}")


def _unavailable_target_resolver(
    *,
    target_name: str,
    namespace: str | None,
) -> keycloak_role.TargetConnection:
    raise keycloak_role.TargetResolutionError(f"target unavailable: {namespace}/{target_name}")


def _failing_keycloak_client_factory(
    *,
    base_url: str,
    username: str,
    password: str,
) -> FakeKeycloakClient:
    raise AssertionError(f"unexpected Keycloak client: {base_url}, {username}, {password}")
