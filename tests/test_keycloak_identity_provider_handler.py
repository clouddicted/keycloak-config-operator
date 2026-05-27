import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import kopf
import pytest

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_IDENTITY_PROVIDER_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import (
    keycloak_identity_provider,
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

NOW = datetime(2026, 5, 25, 10, 30, 45, tzinfo=UTC)
OLD_NOW = datetime(2026, 5, 25, 9, 30, 45, tzinfo=UTC)


@dataclass
class FakeTargetResolver:
    target: keycloak_identity_provider.TargetConnection

    def __post_init__(self) -> None:
        self.calls: list[dict[str, str | None]] = []

    def __call__(
        self,
        *,
        target_name: str,
        namespace: str | None,
    ) -> keycloak_identity_provider.TargetConnection:
        self.calls.append({"target_name": target_name, "namespace": namespace})
        return self.target


class FakeKeycloakClient:
    def __init__(
        self,
        *,
        providers_result: list[dict[str, Any]] | None = None,
        auth_error: Exception | None = None,
        get_error: Exception | None = None,
        post_error: Exception | None = None,
        put_error: Exception | None = None,
        delete_error: Exception | None = None,
    ) -> None:
        self.providers_result = (
            [_existing_identity_provider()]
            if providers_result is None
            else providers_result
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
            return _matching_provider(self.providers_result, _path_tail(path))

        if method == "POST":
            if self.post_error is not None:
                raise self.post_error
            payload = kwargs.get("json")
            if isinstance(payload, dict) and isinstance(payload.get("alias"), str):
                self.providers_result.append(
                    {
                        "internalId": "created-provider-uuid",
                        **payload,
                    }
                )
            return None

        if method == "PUT":
            if self.put_error is not None:
                raise self.put_error
            payload = kwargs.get("json")
            if isinstance(payload, dict) and isinstance(payload.get("alias"), str):
                alias = payload["alias"]
                for index, provider in enumerate(self.providers_result):
                    if provider.get("alias") == alias:
                        self.providers_result[index] = payload
                        break
            return None

        if method == "DELETE":
            if self.delete_error is not None:
                raise self.delete_error
            alias = _path_tail(path)
            self.providers_result = [
                provider
                for provider in self.providers_result
                if provider.get("alias") != alias
            ]
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


class FakeSecret:
    def __init__(self, data: dict[str, str]) -> None:
        self.data = data


class FakeCoreV1Api:
    def __init__(self, secrets: dict[tuple[str, str], FakeSecret] | None = None) -> None:
        self.secrets = {} if secrets is None else secrets
        self.calls: list[tuple[str, str]] = []

    def read_namespaced_secret(self, *, name: str, namespace: str) -> FakeSecret:
        self.calls.append((namespace, name))
        return self.secrets[(namespace, name)]


def test_keycloak_identity_provider_resource_registration_values() -> None:
    assert keycloak_identity_provider.KEYCLOAK_IDENTITY_PROVIDER_RESOURCE == {
        "group": API_GROUP,
        "version": API_VERSION,
        "plural": KEYCLOAK_IDENTITY_PROVIDER_PLURAL,
    }


def test_main_imports_keycloak_identity_provider_handler_module() -> None:
    assert keycloak_identity_provider in main.REGISTERED_HANDLER_MODULES


def test_patch_keycloak_identity_provider_status_reports_invalid_spec() -> None:
    patch: dict[str, Any] = {}

    keycloak_identity_provider.patch_keycloak_identity_provider_status(
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
        "reason": keycloak_identity_provider.INVALID_SPEC_REASON,
        "message": (
            "Missing required KeycloakIdentityProvider spec fields: "
            "targetRef.name, realm, alias, providerId."
        ),
        "lastTransitionTime": "2026-05-25T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": keycloak_identity_provider.INVALID_SPEC_REASON,
        "message": (
            "Drift detection was skipped because the KeycloakIdentityProvider spec "
            "is invalid."
        ),
        "lastTransitionTime": "2026-05-25T10:30:45Z",
    }


def test_patch_keycloak_identity_provider_status_reports_invalid_field_values() -> None:
    patch: dict[str, Any] = {}
    spec = _identity_provider_spec(
        management_policy="Apply",
        deletion_policy="Remove",
        enabled="true",
        display_name="",
    )
    spec["config"] = {"clientId": 3}

    keycloak_identity_provider.patch_keycloak_identity_provider_status(
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
        "reason": keycloak_identity_provider.INVALID_SPEC_REASON,
        "message": (
            "Invalid KeycloakIdentityProvider spec fields: managementPolicy must be "
            "one of: `ObserveOnly`, `Reconcile`; deletionPolicy must be one of: "
            "`Delete`, `Orphan`; enabled must be a boolean; displayName must be a "
            "non-empty string; config must use non-empty string keys and string "
            "values."
        ),
        "lastTransitionTime": "2026-05-25T10:30:45Z",
    }


def test_patch_keycloak_identity_provider_status_reports_invalid_config_secret_refs() -> None:
    patch: dict[str, Any] = {}
    spec = _identity_provider_spec()
    spec["configSecretRefs"] = {"clientSecret": {"name": ""}}

    keycloak_identity_provider.patch_keycloak_identity_provider_status(
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
        "reason": keycloak_identity_provider.INVALID_SPEC_REASON,
        "message": (
            "Invalid KeycloakIdentityProvider spec fields: configSecretRefs values "
            "must include name."
        ),
        "lastTransitionTime": "2026-05-25T10:30:45Z",
    }


def test_patch_keycloak_identity_provider_status_reports_target_resolution_failure() -> None:
    patch: dict[str, Any] = {}

    retry = keycloak_identity_provider.patch_keycloak_identity_provider_status(
        spec=_identity_provider_spec(),
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
    assert ready["reason"] == keycloak_identity_provider.TARGET_UNAVAILABLE_REASON
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": keycloak_identity_provider.TARGET_UNAVAILABLE_REASON,
        "message": (
            "Drift detection was skipped because the referenced KeycloakTarget could "
            "not be resolved."
        ),
        "lastTransitionTime": "2026-05-25T10:30:45Z",
    }
    assert retry == reconciliation.RetryRequest(
        keycloak_identity_provider.TARGET_UNAVAILABLE_REASON,
        ready["message"],
    )


def test_patch_keycloak_identity_provider_status_observes_existing_provider() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        providers_result=[
            _existing_identity_provider(
                alias="example oidc",
                providerId="oidc",
                displayName="Example OIDC",
                config={"clientId": "example-client"},
            )
        ],
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    keycloak_identity_provider.patch_keycloak_identity_provider_status(
        spec=_identity_provider_spec(
            realm="example realm",
            alias="example oidc",
            display_name="Example OIDC",
            config={"clientId": "example-client"},
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
        "reason": keycloak_identity_provider.IDENTITY_PROVIDER_OBSERVED_REASON,
        "message": "Keycloak identity provider already matches desired state.",
        "lastTransitionTime": "2026-05-25T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "False",
        "reason": keycloak_identity_provider.NO_DRIFT_DETECTED_REASON,
        "message": "Keycloak identity provider has no modeled drift.",
        "lastTransitionTime": "2026-05-25T10:30:45Z",
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
        ("GET", "realms/example%20realm/identity-provider/instances", {})
    ]
    assert patch["status"]["remoteId"] == "provider-uuid"
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password"})


def test_patch_keycloak_identity_provider_status_creates_missing_provider() -> None:
    keycloak_client = FakeKeycloakClient(providers_result=[])
    patch: dict[str, Any] = {}

    keycloak_identity_provider.patch_keycloak_identity_provider_status(
        spec=_identity_provider_spec(display_name="Example OIDC"),
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
        == keycloak_identity_provider.IDENTITY_PROVIDER_CREATED_REASON
    )
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {}),
        (
            "POST",
            "realms/example/identity-provider/instances",
            {
                "json": {
                    "alias": "example-oidc",
                    "providerId": "oidc",
                    "enabled": True,
                    "displayName": "Example OIDC",
                    "config": {
                        "clientId": "example-client",
                        "authorizationUrl": "https://idp.example.test/auth",
                    },
                }
            },
        ),
        ("GET", "realms/example/identity-provider/instances/example-oidc", {}),
    ]
    assert patch["status"]["remoteId"] == "created-provider-uuid"


def test_patch_keycloak_identity_provider_status_loads_secret_config() -> None:
    keycloak_client = FakeKeycloakClient(providers_result=[])
    core_v1_api = FakeCoreV1Api(
        {
            ("apps", "example-oidc-secret"): FakeSecret(
                data={"clientSecret": _b64("secret-from-kubernetes")}
            )
        }
    )
    patch: dict[str, Any] = {}

    keycloak_identity_provider.patch_keycloak_identity_provider_status(
        spec=_identity_provider_spec(
            display_name="Example OIDC",
            config_secret_refs={"clientSecret": {"name": "example-oidc-secret"}},
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        core_v1_api=core_v1_api,
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    assert core_v1_api.calls == [("apps", "example-oidc-secret")]
    assert keycloak_client.requests[1] == (
        "POST",
        "realms/example/identity-provider/instances",
        {
            "json": {
                "alias": "example-oidc",
                "providerId": "oidc",
                "enabled": True,
                "displayName": "Example OIDC",
                "config": {
                    "clientId": "example-client",
                    "authorizationUrl": "https://idp.example.test/auth",
                    "clientSecret": "secret-from-kubernetes",
                },
            }
        },
    )
    assert _condition_messages(patch).isdisjoint({"secret-from-kubernetes"})


def test_patch_keycloak_identity_provider_status_observe_only_reports_missing() -> None:
    keycloak_client = FakeKeycloakClient(providers_result=[])
    patch: dict[str, Any] = {}

    keycloak_identity_provider.patch_keycloak_identity_provider_status(
        spec=_identity_provider_spec(
            management_policy=keycloak_identity_provider.MANAGEMENT_POLICY_OBSERVE_ONLY
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
        "reason": keycloak_identity_provider.IDENTITY_PROVIDER_MISSING_REASON,
        "message": (
            "Keycloak identity provider is missing and was not created because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-25T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "True",
        "reason": keycloak_identity_provider.IDENTITY_PROVIDER_MISSING_REASON,
        "message": (
            "Keycloak identity provider is missing and was not created because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-25T10:30:45Z",
    }
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {})
    ]
    assert patch["status"]["remoteId"] is None


def test_patch_keycloak_identity_provider_status_updates_drift_preserving_config() -> None:
    keycloak_client = FakeKeycloakClient(
        providers_result=[
            _existing_identity_provider(
                displayName="Old OIDC",
                enabled=False,
                config={"clientId": "old-client", "keep": "true"},
            )
        ],
    )
    patch: dict[str, Any] = {}

    keycloak_identity_provider.patch_keycloak_identity_provider_status(
        spec=_identity_provider_spec(display_name="Example OIDC"),
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
        "reason": keycloak_identity_provider.IDENTITY_PROVIDER_UPDATED_REASON,
        "message": "Keycloak identity provider was updated.",
        "lastTransitionTime": "2026-05-25T10:30:45Z",
    }
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {}),
        (
            "PUT",
            "realms/example/identity-provider/instances/example-oidc",
            {
                "json": {
                    "internalId": "provider-uuid",
                    "alias": "example-oidc",
                    "providerId": "oidc",
                    "enabled": True,
                    "displayName": "Example OIDC",
                    "config": {
                        "clientId": "example-client",
                        "keep": "true",
                        "authorizationUrl": "https://idp.example.test/auth",
                    },
                }
            },
        ),
        ("GET", "realms/example/identity-provider/instances/example-oidc", {}),
    ]
    assert patch["status"]["remoteId"] == "provider-uuid"


def test_patch_keycloak_identity_provider_status_observe_only_reports_drift() -> None:
    keycloak_client = FakeKeycloakClient(
        providers_result=[
            _existing_identity_provider(
                displayName="Old OIDC",
                config={"clientId": "old-client"},
            )
        ],
    )
    patch: dict[str, Any] = {}

    keycloak_identity_provider.patch_keycloak_identity_provider_status(
        spec=_identity_provider_spec(
            display_name="Example OIDC",
            management_policy=keycloak_identity_provider.MANAGEMENT_POLICY_OBSERVE_ONLY,
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
        "reason": keycloak_identity_provider.IDENTITY_PROVIDER_DRIFT_DETECTED_REASON,
        "message": (
            "Keycloak identity provider has modeled drift and was not changed "
            "because managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-25T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "True",
        "reason": keycloak_identity_provider.IDENTITY_PROVIDER_DRIFT_DETECTED_REASON,
        "message": (
            "Keycloak identity provider differs from desired state and was not "
            "changed because managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-25T10:30:45Z",
    }
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {})
    ]
    assert patch["status"]["remoteId"] == "provider-uuid"


def test_patch_keycloak_identity_provider_status_reports_auth_failure_safely() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_identity_provider.patch_keycloak_identity_provider_status(
        spec=_identity_provider_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_identity_provider.AUTHENTICATION_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert (
        conditions[CONDITION_READY]["reason"]
        == keycloak_identity_provider.AUTHENTICATION_FAILED_REASON
    )
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_identity_provider_status_reports_request_failure_safely() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakRequestError("failed for kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_identity_provider.patch_keycloak_identity_provider_status(
        spec=_identity_provider_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_identity_provider.REQUEST_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert conditions[CONDITION_READY]["reason"] == keycloak_identity_provider.REQUEST_FAILED_REASON
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_identity_provider_status_reports_secret_failure_safely() -> None:
    keycloak_client = FakeKeycloakClient(providers_result=[])
    patch: dict[str, Any] = {}

    retry = keycloak_identity_provider.patch_keycloak_identity_provider_status(
        spec=_identity_provider_spec(
            config_secret_refs={"clientSecret": {"name": "missing-secret"}}
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        core_v1_api=FakeCoreV1Api({("apps", "missing-secret"): FakeSecret(data={})}),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_identity_provider.SECRET_UNAVAILABLE_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "False",
        "reason": keycloak_identity_provider.SECRET_UNAVAILABLE_REASON,
        "message": (
            "KeycloakIdentityProvider is not ready because a provider config Secret "
            "could not be loaded."
        ),
        "lastTransitionTime": "2026-05-25T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED]["status"] == "Unknown"
    assert keycloak_client.requests == []
    assert _condition_messages(patch).isdisjoint({"missing-secret"})


def test_delete_keycloak_identity_provider_resource_orphan_noop() -> None:
    keycloak_identity_provider.delete_keycloak_identity_provider_resource(
        spec=_identity_provider_spec(),
        namespace="apps",
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
    )


def test_delete_keycloak_identity_provider_resource_delete_removes_provider() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        providers_result=[_existing_identity_provider(alias="example-oidc")]
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)

    keycloak_identity_provider.delete_keycloak_identity_provider_resource(
        spec=_identity_provider_spec(
            deletion_policy=keycloak_identity_provider.DELETION_POLICY_DELETE,
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
        ("GET", "realms/example/identity-provider/instances", {}),
        ("DELETE", "realms/example/identity-provider/instances/example-oidc", {}),
    ]


def test_delete_keycloak_identity_provider_resource_delete_missing_provider_noop() -> None:
    keycloak_client = FakeKeycloakClient(providers_result=[])

    keycloak_identity_provider.delete_keycloak_identity_provider_resource(
        spec=_identity_provider_spec(
            deletion_policy=keycloak_identity_provider.DELETION_POLICY_DELETE
        ),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == [
        ("GET", "realms/example/identity-provider/instances", {})
    ]


def test_delete_keycloak_identity_provider_resource_invalid_spec_is_permanent_failure() -> None:
    with pytest.raises(kopf.PermanentError) as exc_info:
        keycloak_identity_provider.delete_keycloak_identity_provider_resource(
            spec={"targetRef": {}},
            namespace="apps",
            target_resolver=_failing_target_resolver,
            keycloak_client_factory=_failing_keycloak_client_factory,
        )

    assert str(exc_info.value) == (
        "KeycloakIdentityProvider deletion skipped because spec is invalid."
    )


def test_patch_keycloak_identity_provider_status_preserves_stable_transition_time() -> None:
    patch: dict[str, Any] = {}

    keycloak_identity_provider.patch_keycloak_identity_provider_status(
        spec=_identity_provider_spec(),
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
    assert ready["reason"] == keycloak_identity_provider.IDENTITY_PROVIDER_OBSERVED_REASON
    assert ready["lastTransitionTime"] == "2026-05-25T09:30:45Z"


def _target_resolver() -> FakeTargetResolver:
    return FakeTargetResolver(
        keycloak_identity_provider.TargetConnection(
            url="https://keycloak.example.test",
            username="kc-admin",
            password="secret-password",
        )
    )


def _identity_provider_spec(
    *,
    realm: str = "example",
    alias: str = "example-oidc",
    provider_id: str = "oidc",
    enabled: bool | str | None = None,
    display_name: str | None = None,
    config: dict[str, str] | None = None,
    config_secret_refs: dict[str, dict[str, str]] | None = None,
    management_policy: str | None = None,
    deletion_policy: str | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "targetRef": {"name": "example-keycloak"},
        "realm": realm,
        "alias": alias,
        "providerId": provider_id,
        "config": config
        if config is not None
        else {
            "clientId": "example-client",
            "authorizationUrl": "https://idp.example.test/auth",
        },
    }
    if enabled is not None:
        spec["enabled"] = enabled
    if display_name is not None:
        spec["displayName"] = display_name
    if config_secret_refs is not None:
        spec["configSecretRefs"] = config_secret_refs
    if management_policy is not None:
        spec["managementPolicy"] = management_policy
    if deletion_policy is not None:
        spec["deletionPolicy"] = deletion_policy

    return spec


def _existing_identity_provider(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "internalId": "provider-uuid",
        "alias": "example-oidc",
        "providerId": "oidc",
        "enabled": True,
        "config": {
            "clientId": "example-client",
            "authorizationUrl": "https://idp.example.test/auth",
        },
    }
    payload.update(overrides)
    return payload


def _matching_provider(
    providers: list[dict[str, Any]],
    alias: str,
) -> dict[str, Any] | None:
    for provider in providers:
        if provider.get("alias") == alias:
            return provider

    return None


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def _path_tail(path: str) -> str:
    return path.rsplit("/", 1)[-1].replace("%20", " ")


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
) -> keycloak_identity_provider.TargetConnection:
    raise AssertionError(f"unexpected target resolution: {namespace}/{target_name}")


def _unavailable_target_resolver(
    *,
    target_name: str,
    namespace: str | None,
) -> keycloak_identity_provider.TargetConnection:
    raise keycloak_identity_provider.TargetResolutionError(
        f"target unavailable: {namespace}/{target_name}"
    )


def _failing_keycloak_client_factory(
    *,
    base_url: str,
    username: str,
    password: str,
) -> FakeKeycloakClient:
    raise AssertionError(f"unexpected Keycloak client: {base_url}, {username}, {password}")
