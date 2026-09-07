from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import kopf
import pytest

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_IDENTITY_PROVIDER_MAPPER_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import (
    keycloak_identity_provider_mapper,
    reconciliation,
)
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAuthenticationError,
    KeycloakRequestError,
)
from clouddicted_keycloak_config_operator.status import (
    CONDITION_DRIFT_DETECTED,
    CONDITION_READY,
    ready_condition,
)

NOW = datetime(2026, 5, 24, 11, 30, 45, tzinfo=UTC)
OLD_NOW = datetime(2026, 5, 24, 10, 30, 45, tzinfo=UTC)


@dataclass
class FakeTargetResolver:
    target: keycloak_identity_provider_mapper.TargetConnection

    def __post_init__(self) -> None:
        self.calls: list[dict[str, str | None]] = []

    def __call__(
        self,
        *,
        target_name: str,
        namespace: str | None,
    ) -> keycloak_identity_provider_mapper.TargetConnection:
        self.calls.append({"target_name": target_name, "namespace": namespace})
        return self.target


class FakeKeycloakClient:
    def __init__(
        self,
        *,
        providers_result: list[dict[str, Any]] | None = None,
        mappers_result: list[dict[str, Any]] | None = None,
        auth_error: Exception | None = None,
        get_error: Exception | None = None,
        post_error: Exception | None = None,
        put_error: Exception | None = None,
        delete_error: Exception | None = None,
    ) -> None:
        self.providers_result = (
            [_existing_provider()] if providers_result is None else providers_result
        )
        self.mappers_result = (
            [_existing_mapper()] if mappers_result is None else mappers_result
        )
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
            if path.endswith("/identity-provider/instances"):
                return self.providers_result
            if path.endswith("/mappers"):
                return self.mappers_result

        if method == "POST":
            if self.post_error is not None:
                raise self.post_error
            payload = kwargs.get("json")
            if isinstance(payload, dict) and isinstance(payload.get("name"), str):
                self.mappers_result.append(
                    {
                        "id": "created-mapper-uuid",
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


def test_keycloak_identity_provider_mapper_resource_registration_values() -> None:
    assert keycloak_identity_provider_mapper.KEYCLOAK_IDENTITY_PROVIDER_MAPPER_RESOURCE == {
        "group": API_GROUP,
        "version": API_VERSION,
        "plural": KEYCLOAK_IDENTITY_PROVIDER_MAPPER_PLURAL,
    }


def test_main_imports_keycloak_identity_provider_mapper_handler_module() -> None:
    assert keycloak_identity_provider_mapper in main.REGISTERED_HANDLER_MODULES


def test_patch_keycloak_identity_provider_mapper_status_reports_invalid_spec() -> None:
    patch: dict[str, Any] = {}

    keycloak_identity_provider_mapper.patch_keycloak_identity_provider_mapper_status(
        spec={"targetRef": {}, "identityProviderRef": {}},
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
        "reason": keycloak_identity_provider_mapper.INVALID_SPEC_REASON,
        "message": (
            "Missing required KeycloakIdentityProviderMapper spec fields: "
            "targetRef.name, realm, name, identityProviderRef.name, identityProviderMapper."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": keycloak_identity_provider_mapper.INVALID_SPEC_REASON,
        "message": (
            "Drift detection was skipped because the KeycloakIdentityProviderMapper spec is "
            "invalid."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }


def test_patch_keycloak_identity_provider_mapper_status_reports_invalid_field_values() -> None:
    patch: dict[str, Any] = {}
    spec = _mapper_spec(
        management_policy="InvalidPolicy",
        deletion_policy="InvalidPolicy",
    )
    spec["identityProviderRef"]["alias"] = "   "
    spec["config"] = {"claim": 123}

    keycloak_identity_provider_mapper.patch_keycloak_identity_provider_mapper_status(
        spec=spec,
        status={},
        patch=patch,
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
        now=NOW,
    )

    assert _conditions_by_type(patch)[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "False",
        "reason": keycloak_identity_provider_mapper.INVALID_SPEC_REASON,
        "message": (
            "Invalid KeycloakIdentityProviderMapper spec fields: managementPolicy must be "
            "one of: `ObserveOnly`, `Reconcile`; deletionPolicy must be one of: `Delete`, "
            "`Orphan`; identityProviderRef.alias must be a non-empty string; "
            "config must use non-empty string keys and string values."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }


def test_patch_keycloak_identity_provider_mapper_status_reports_target_resolution_failure() -> None:
    patch: dict[str, Any] = {}

    retry = keycloak_identity_provider_mapper.patch_keycloak_identity_provider_mapper_status(
        spec=_mapper_spec(),
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
    assert ready["reason"] == keycloak_identity_provider_mapper.TARGET_UNAVAILABLE_REASON
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": keycloak_identity_provider_mapper.TARGET_UNAVAILABLE_REASON,
        "message": (
            "Drift detection was skipped because the referenced KeycloakTarget could "
            "not be resolved."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert retry == reconciliation.RetryRequest(
        keycloak_identity_provider_mapper.TARGET_UNAVAILABLE_REASON,
        ready["message"],
    )


def test_patch_keycloak_identity_provider_mapper_status_reports_identity_provider_missing() -> None:
    keycloak_client = FakeKeycloakClient(providers_result=[])
    patch: dict[str, Any] = {}

    retry = keycloak_identity_provider_mapper.patch_keycloak_identity_provider_mapper_status(
        spec=_mapper_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    ready = conditions[CONDITION_READY]
    assert ready["status"] == "False"
    assert ready["reason"] == keycloak_identity_provider_mapper.IDENTITY_PROVIDER_MISSING_REASON
    assert ready["message"] == (
        "KeycloakIdentityProviderMapper is waiting for the referenced Keycloak identity provider."
    )
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": keycloak_identity_provider_mapper.IDENTITY_PROVIDER_MISSING_REASON,
        "message": (
            "Drift detection was skipped because the referenced Keycloak identity provider "
            "was not found."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert retry == reconciliation.RetryRequest(
        keycloak_identity_provider_mapper.IDENTITY_PROVIDER_MISSING_REASON,
        ready["message"],
    )
    assert patch["status"]["remoteId"] is None


def test_patch_keycloak_identity_provider_mapper_status_observes_existing_mapper() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        providers_result=[_existing_provider(alias="github-corp")],
        mappers_result=[
            _existing_mapper(
                name="email-claim",
                identityProviderAlias="github-corp",
                identityProviderMapper="oidc-user-attribute-idp-mapper",
                config={"claim": "email", "user.attribute": "email"},
            )
        ],
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    keycloak_identity_provider_mapper.patch_keycloak_identity_provider_mapper_status(
        spec=_mapper_spec(
            realm="corp-realm",
            name="email-claim",
            idp_name="github-corp",
            idp_alias="github-corp",
            mapper_type="oidc-user-attribute-idp-mapper",
            config={"claim": "email", "user.attribute": "email"},
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
        "reason": keycloak_identity_provider_mapper.IDENTITY_PROVIDER_MAPPER_OBSERVED_REASON,
        "message": "Keycloak identity provider mapper already matches desired state.",
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "False",
        "reason": keycloak_identity_provider_mapper.NO_DRIFT_DETECTED_REASON,
        "message": "Keycloak identity provider mapper has no modeled drift.",
        "lastTransitionTime": "2026-05-24T11:30:45Z",
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
        ("GET", "realms/corp-realm/identity-provider/instances", {}),
        ("GET", "realms/corp-realm/identity-provider/instances/github-corp/mappers", {}),
    ]
    assert patch["status"]["remoteId"] == "mapper-uuid"
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password"})


def test_patch_keycloak_identity_provider_mapper_status_creates_mapper() -> None:
    keycloak_client = FakeKeycloakClient(mappers_result=[])
    patch: dict[str, Any] = {}

    keycloak_identity_provider_mapper.patch_keycloak_identity_provider_mapper_status(
        spec=_mapper_spec(config={"claim": "email", "user.attribute": "email"}),
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
        == keycloak_identity_provider_mapper.IDENTITY_PROVIDER_MAPPER_CREATED_REASON
    )
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {}),
        ("GET", "realms/example/identity-provider/instances/github/mappers", {}),
        (
            "POST",
            "realms/example/identity-provider/instances/github/mappers",
            {
                "json": {
                    "name": "email-claim",
                    "identityProviderAlias": "github",
                    "identityProviderMapper": "oidc-user-attribute-idp-mapper",
                    "config": {
                        "claim": "email",
                        "user.attribute": "email",
                    },
                }
            },
        ),
        ("GET", "realms/example/identity-provider/instances/github/mappers", {}),
    ]
    assert patch["status"]["remoteId"] == "created-mapper-uuid"


def test_patch_keycloak_idp_mapper_status_observe_only_reports_missing_mapper() -> None:
    keycloak_client = FakeKeycloakClient(mappers_result=[])
    patch: dict[str, Any] = {}

    keycloak_identity_provider_mapper.patch_keycloak_identity_provider_mapper_status(
        spec=_mapper_spec(
            config={"claim": "email"},
            management_policy=keycloak_identity_provider_mapper.MANAGEMENT_POLICY_OBSERVE_ONLY,
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
        "reason": keycloak_identity_provider_mapper.IDENTITY_PROVIDER_MAPPER_MISSING_REASON,
        "message": (
            "Keycloak identity provider mapper is missing and was not created because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "True",
        "reason": keycloak_identity_provider_mapper.IDENTITY_PROVIDER_MAPPER_MISSING_REASON,
        "message": (
            "Keycloak identity provider mapper is missing and was not created because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {}),
        ("GET", "realms/example/identity-provider/instances/github/mappers", {}),
    ]
    assert patch["status"]["remoteId"] is None


def test_patch_keycloak_identity_provider_mapper_status_updates_drift_preserving_fields() -> None:
    keycloak_client = FakeKeycloakClient(
        mappers_result=[
            _existing_mapper(
                identityProviderMapper="oidc-user-attribute-idp-mapper",
                config={"claim": "old-claim", "custom.keep": "true"},
            )
        ],
    )
    patch: dict[str, Any] = {}

    keycloak_identity_provider_mapper.patch_keycloak_identity_provider_mapper_status(
        spec=_mapper_spec(config={"claim": "new-claim", "user.attribute": "email"}),
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
        "reason": keycloak_identity_provider_mapper.IDENTITY_PROVIDER_MAPPER_UPDATED_REASON,
        "message": "Keycloak identity provider mapper was updated.",
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {}),
        ("GET", "realms/example/identity-provider/instances/github/mappers", {}),
        (
            "PUT",
            "realms/example/identity-provider/instances/github/mappers/mapper-uuid",
            {
                "json": {
                    "id": "mapper-uuid",
                    "name": "email-claim",
                    "identityProviderAlias": "github",
                    "identityProviderMapper": "oidc-user-attribute-idp-mapper",
                    "config": {
                        "claim": "new-claim",
                        "custom.keep": "true",
                        "user.attribute": "email",
                    },
                }
            },
        ),
    ]
    assert patch["status"]["remoteId"] == "mapper-uuid"


def test_patch_keycloak_idp_mapper_status_observe_only_reports_modeled_drift() -> None:
    keycloak_client = FakeKeycloakClient(
        mappers_result=[
            _existing_mapper(
                identityProviderMapper="oidc-role-idp-mapper",
                config={"claim": "roles", "role": "admin"},
            )
        ],
    )
    patch: dict[str, Any] = {}

    keycloak_identity_provider_mapper.patch_keycloak_identity_provider_mapper_status(
        spec=_mapper_spec(
            mapper_type="oidc-role-idp-mapper",
            config={"claim": "roles", "role": "superadmin"},
            management_policy=keycloak_identity_provider_mapper.MANAGEMENT_POLICY_OBSERVE_ONLY,
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
        "reason": keycloak_identity_provider_mapper.IDENTITY_PROVIDER_MAPPER_DRIFT_DETECTED_REASON,
        "message": (
            "Keycloak identity provider mapper has modeled drift and was not changed "
            "because managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "True",
        "reason": keycloak_identity_provider_mapper.IDENTITY_PROVIDER_MAPPER_DRIFT_DETECTED_REASON,
        "message": (
            "Keycloak identity provider mapper differs from desired state and was not changed "
            "because managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {}),
        ("GET", "realms/example/identity-provider/instances/github/mappers", {}),
    ]
    assert patch["status"]["remoteId"] == "mapper-uuid"


def test_patch_keycloak_idp_mapper_status_reports_auth_failure_without_secrets() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_identity_provider_mapper.patch_keycloak_identity_provider_mapper_status(
        spec=_mapper_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_identity_provider_mapper.AUTHENTICATION_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert (
        conditions[CONDITION_READY]["reason"]
        == keycloak_identity_provider_mapper.AUTHENTICATION_FAILED_REASON
    )
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_identity_provider_mapper_status_reports_request_failure() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakRequestError("failed for kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_identity_provider_mapper.patch_keycloak_identity_provider_mapper_status(
        spec=_mapper_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_identity_provider_mapper.REQUEST_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert (
        conditions[CONDITION_READY]["reason"]
        == keycloak_identity_provider_mapper.REQUEST_FAILED_REASON
    )
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_delete_keycloak_idp_mapper_resource_orphan_noop_without_external_calls() -> None:
    result = keycloak_identity_provider_mapper.delete_keycloak_identity_provider_mapper_resource(
        spec=_mapper_spec(),
        namespace="apps",
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
    )
    assert result == keycloak_identity_provider_mapper.DELETION_POLICY_ORPHAN


def test_delete_keycloak_identity_provider_mapper_resource_delete_removes_existing_mapper() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        mappers_result=[_existing_mapper(name="email-claim")]
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)

    result = keycloak_identity_provider_mapper.delete_keycloak_identity_provider_mapper_resource(
        spec=_mapper_spec(
            name="email-claim",
            deletion_policy=keycloak_identity_provider_mapper.DELETION_POLICY_DELETE,
        ),
        namespace="apps",
        target_resolver=resolver,
        keycloak_client_factory=keycloak_client_factory,
    )

    assert result == keycloak_identity_provider_mapper.DELETION_POLICY_DELETE
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
        ("GET", "realms/example/identity-provider/instances", {}),
        ("GET", "realms/example/identity-provider/instances/github/mappers", {}),
        ("DELETE", "realms/example/identity-provider/instances/github/mappers/mapper-uuid", {}),
    ]


def test_delete_keycloak_identity_provider_mapper_resource_delete_missing_provider_noop() -> None:
    keycloak_client = FakeKeycloakClient(providers_result=[])

    result = keycloak_identity_provider_mapper.delete_keycloak_identity_provider_mapper_resource(
        spec=_mapper_spec(
            deletion_policy=keycloak_identity_provider_mapper.DELETION_POLICY_DELETE
        ),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert result == keycloak_identity_provider_mapper.DELETION_POLICY_DELETE
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {}),
    ]


def test_delete_keycloak_identity_provider_mapper_resource_delete_missing_mapper_noop() -> None:
    keycloak_client = FakeKeycloakClient(mappers_result=[])

    result = keycloak_identity_provider_mapper.delete_keycloak_identity_provider_mapper_resource(
        spec=_mapper_spec(
            deletion_policy=keycloak_identity_provider_mapper.DELETION_POLICY_DELETE
        ),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert result == keycloak_identity_provider_mapper.DELETION_POLICY_DELETE
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {}),
        ("GET", "realms/example/identity-provider/instances/github/mappers", {}),
    ]


def test_delete_keycloak_identity_provider_mapper_resource_delete_missing_id_safe_failure() -> None:
    keycloak_client = FakeKeycloakClient(mappers_result=[_existing_mapper(id=None)])

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_identity_provider_mapper.delete_keycloak_identity_provider_mapper_resource(
            spec=_mapper_spec(
                deletion_policy=keycloak_identity_provider_mapper.DELETION_POLICY_DELETE
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakIdentityProviderMapper deletion failed while calling the Keycloak Admin API."
    )
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {}),
        ("GET", "realms/example/identity-provider/instances/github/mappers", {}),
    ]


def test_delete_keycloak_idp_mapper_resource_invalid_spec_is_permanent_failure() -> None:
    with pytest.raises(kopf.PermanentError) as exc_info:
        keycloak_identity_provider_mapper.delete_keycloak_identity_provider_mapper_resource(
            spec={"targetRef": {}},
            namespace="apps",
            target_resolver=_failing_target_resolver,
            keycloak_client_factory=_failing_keycloak_client_factory,
        )

    assert str(exc_info.value) == (
        "KeycloakIdentityProviderMapper deletion skipped because spec is invalid."
    )


def test_delete_keycloak_idp_mapper_resource_target_unavailable_is_temporary() -> None:
    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_identity_provider_mapper.delete_keycloak_identity_provider_mapper_resource(
            spec=_mapper_spec(
                deletion_policy=keycloak_identity_provider_mapper.DELETION_POLICY_DELETE
            ),
            namespace="apps",
            target_resolver=_unavailable_target_resolver,
            keycloak_client_factory=_failing_keycloak_client_factory,
        )

    assert str(exc_info.value) == (
        "KeycloakIdentityProviderMapper deletion is waiting for the referenced KeycloakTarget."
    )


def test_delete_keycloak_identity_provider_mapper_resource_auth_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_identity_provider_mapper.delete_keycloak_identity_provider_mapper_resource(
            spec=_mapper_spec(
                deletion_policy=keycloak_identity_provider_mapper.DELETION_POLICY_DELETE
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakIdentityProviderMapper deletion failed because Keycloak authentication failed."
    )
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert {"kc-admin", "secret-password", "token"}.isdisjoint(
        set(str(exc_info.value).split())
    )


def test_delete_keycloak_identity_provider_mapper_resource_request_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        delete_error=KeycloakRequestError("failed for kc-admin secret-password token")
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_identity_provider_mapper.delete_keycloak_identity_provider_mapper_resource(
            spec=_mapper_spec(
                deletion_policy=keycloak_identity_provider_mapper.DELETION_POLICY_DELETE
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakIdentityProviderMapper deletion failed while calling the Keycloak Admin API."
    )
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {}),
        ("GET", "realms/example/identity-provider/instances/github/mappers", {}),
        ("DELETE", "realms/example/identity-provider/instances/github/mappers/mapper-uuid", {}),
    ]
    assert {"kc-admin", "secret-password", "token"}.isdisjoint(
        set(str(exc_info.value).split())
    )


def test_patch_keycloak_identity_provider_mapper_status_preserves_stable_transition_time() -> None:
    patch: dict[str, Any] = {}

    keycloak_identity_provider_mapper.patch_keycloak_identity_provider_mapper_status(
        spec=_mapper_spec(),
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
    expected_reason = (
        keycloak_identity_provider_mapper.IDENTITY_PROVIDER_MAPPER_OBSERVED_REASON
    )
    assert ready["reason"] == expected_reason
    assert ready["lastTransitionTime"] == "2026-05-24T10:30:45Z"


def test_reconcile_and_delete_kopf_handlers(monkeypatch: pytest.MonkeyPatch) -> None:
    body = kopf.Body({"metadata": {"name": "test-mapper", "namespace": "default"}})
    patch: dict[str, Any] = {}
    event_mock = MagicMock()
    monkeypatch.setattr(kopf, "event", event_mock)

    # Test reconcile handler
    keycloak_identity_provider_mapper.reconcile_keycloak_identity_provider_mapper(
        body=body,
        spec={"targetRef": {}},  # Invalid spec, will not retry, will set conditions
        status={},
        patch=patch,
        namespace="default",
    )
    assert "conditions" in patch["status"]

    # Test delete handler with Orphan
    keycloak_identity_provider_mapper.delete_keycloak_identity_provider_mapper(
        body=body,
        spec=_mapper_spec(deletion_policy="Orphan"),
        namespace="default",
    )
    event_mock.assert_called_with(
        body,
        type="Normal",
        reason=keycloak_identity_provider_mapper.IDENTITY_PROVIDER_MAPPER_ORPHANED_REASON,
        message=(
            "Keycloak identity provider mapper was left in Keycloak because "
            "deletionPolicy is Orphan."
        ),
    )


def _target_resolver() -> FakeTargetResolver:
    return FakeTargetResolver(
        keycloak_identity_provider_mapper.TargetConnection(
            url="https://keycloak.example.test",
            username="kc-admin",
            password="secret-password",
        )
    )


def _mapper_spec(
    *,
    realm: str = "example",
    name: str = "email-claim",
    idp_name: str = "github",
    idp_alias: str | None = None,
    mapper_type: str = "oidc-user-attribute-idp-mapper",
    config: dict[str, str] | None = None,
    management_policy: str | None = None,
    deletion_policy: str | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "targetRef": {"name": "example-keycloak"},
        "realm": realm,
        "name": name,
        "identityProviderRef": {"name": idp_name},
        "identityProviderMapper": mapper_type,
    }
    if idp_alias is not None:
        spec["identityProviderRef"]["alias"] = idp_alias
    if config is not None:
        spec["config"] = config
    if management_policy is not None:
        spec["managementPolicy"] = management_policy
    if deletion_policy is not None:
        spec["deletionPolicy"] = deletion_policy

    return spec


def _existing_provider(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "internalId": "provider-uuid",
        "alias": "github",
        "providerId": "github",
    }
    payload.update(overrides)
    return payload


def _existing_mapper(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "mapper-uuid",
        "name": "email-claim",
        "identityProviderAlias": "github",
        "identityProviderMapper": "oidc-user-attribute-idp-mapper",
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
) -> keycloak_identity_provider_mapper.TargetConnection:
    raise AssertionError(f"unexpected target resolution: {namespace}/{target_name}")


def _unavailable_target_resolver(
    *,
    target_name: str,
    namespace: str | None,
) -> keycloak_identity_provider_mapper.TargetConnection:
    raise keycloak_identity_provider_mapper.TargetResolutionError(
        f"target unavailable: {namespace}/{target_name}"
    )


def _failing_keycloak_client_factory(
    *,
    base_url: str,
    username: str,
    password: str,
) -> FakeKeycloakClient:
    raise AssertionError(f"unexpected Keycloak client: {base_url}, {username}, {password}")
