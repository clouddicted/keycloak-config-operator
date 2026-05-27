import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import kopf
import pytest
from kubernetes.client.exceptions import ApiException

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_CLIENT_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import (
    keycloak_client as keycloak_client_handler,
)
from clouddicted_keycloak_config_operator.handlers import reconciliation
from clouddicted_keycloak_config_operator.keycloak_client import (
    KeycloakAuthenticationError,
    KeycloakRequestError,
)
from clouddicted_keycloak_config_operator.status import (
    CONDITION_DRIFT_DETECTED,
    CONDITION_READY,
    drift_detected_condition,
    ready_condition,
)

NOW = datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC)
OLD_NOW = datetime(2026, 5, 22, 9, 30, 45, tzinfo=UTC)


@dataclass
class FakeTargetResolver:
    target: keycloak_client_handler.TargetConnection

    def __post_init__(self) -> None:
        self.calls: list[dict[str, str | None]] = []

    def __call__(
        self,
        *,
        target_name: str,
        namespace: str | None,
    ) -> keycloak_client_handler.TargetConnection:
        self.calls.append({"target_name": target_name, "namespace": namespace})
        return self.target


class FakeKeycloakClient:
    def __init__(
        self,
        *,
        lookup_result: list[dict[str, Any]] | None = None,
        auth_error: Exception | None = None,
        get_error: Exception | None = None,
        post_error: Exception | None = None,
        put_error: Exception | None = None,
        delete_error: Exception | None = None,
    ) -> None:
        self.lookup_result = [] if lookup_result is None else lookup_result
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
            return self.lookup_result

        if method == "POST":
            if self.post_error is not None:
                raise self.post_error
            payload = kwargs.get("json")
            if isinstance(payload, dict) and isinstance(payload.get("clientId"), str):
                self.lookup_result.append(
                    {
                        "id": "created-client-uuid",
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


@dataclass
class FakeSecret:
    data: dict[str, str] | None


class FakeCoreV1Api:
    def __init__(
        self,
        secrets: dict[tuple[str, str], FakeSecret] | None = None,
        read_error: Exception | None = None,
    ) -> None:
        self.secrets = {} if secrets is None else secrets
        self.read_error = read_error
        self.calls: list[tuple[str, str]] = []

    def read_namespaced_secret(self, *, name: str, namespace: str) -> FakeSecret:
        self.calls.append((namespace, name))
        if self.read_error is not None:
            raise self.read_error

        return self.secrets[(namespace, name)]


def test_keycloak_client_resource_registration_values() -> None:
    assert keycloak_client_handler.KEYCLOAK_CLIENT_RESOURCE == {
        "group": API_GROUP,
        "version": API_VERSION,
        "plural": KEYCLOAK_CLIENT_PLURAL,
    }


def test_main_imports_keycloak_client_handler_module() -> None:
    assert keycloak_client_handler in main.REGISTERED_HANDLER_MODULES


def test_patch_keycloak_client_status_reports_invalid_spec_without_external_calls() -> None:
    patch: dict[str, Any] = {}

    keycloak_client_handler.patch_keycloak_client_status(
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
        "reason": keycloak_client_handler.INVALID_SPEC_REASON,
        "message": (
            "Missing required KeycloakClient spec fields: "
            "targetRef.name, realm, clientId."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": keycloak_client_handler.INVALID_SPEC_REASON,
        "message": "Drift detection was skipped because the KeycloakClient spec is invalid.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }


def test_patch_keycloak_client_status_requires_confidential_secret_ref() -> None:
    patch: dict[str, Any] = {}

    keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            client_type=keycloak_client_handler.CLIENT_TYPE_CONFIDENTIAL,
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
        "reason": keycloak_client_handler.INVALID_SPEC_REASON,
        "message": "Missing required KeycloakClient spec fields: secretRef.name.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }


def test_patch_keycloak_client_status_rejects_public_service_account() -> None:
    patch: dict[str, Any] = {}

    keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            client_type=keycloak_client_handler.CLIENT_TYPE_PUBLIC,
            service_accounts_enabled=True,
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
        "reason": keycloak_client_handler.INVALID_SPEC_REASON,
        "message": (
            "Invalid KeycloakClient spec fields: serviceAccountsEnabled can be true only "
            "for Confidential clients."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }


def test_patch_keycloak_client_status_reports_invalid_field_values() -> None:
    patch: dict[str, Any] = {}

    keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            client_type="Private",
            management_policy="Apply",
            deletion_policy="Remove",
            default_client_scopes=["profile", "profile"],
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
        "reason": keycloak_client_handler.INVALID_SPEC_REASON,
        "message": (
            "Invalid KeycloakClient spec fields: clientType must be one of: "
            "`Confidential`, `Public`; managementPolicy must be one of: "
            "`ObserveOnly`, `Reconcile`; deletionPolicy must be one of: "
            "`Delete`, `Orphan`; defaultClientScopes must not contain duplicate values."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }


def test_patch_keycloak_client_status_reports_invalid_recommended_settings() -> None:
    patch: dict[str, Any] = {}

    spec = _client_spec(
        enabled="yes",
        description="",
        implicit_flow_enabled="no",
        full_scope_allowed="all",
    )
    spec["frontchannelLogout"] = None

    keycloak_client_handler.patch_keycloak_client_status(
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
        "reason": keycloak_client_handler.INVALID_SPEC_REASON,
        "message": (
            "Invalid KeycloakClient spec fields: enabled must be a boolean; "
            "description must be a non-empty string; implicitFlowEnabled must be a "
            "boolean; fullScopeAllowed must be a boolean; frontchannelLogout must be "
            "a boolean."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }


def test_patch_keycloak_client_status_reports_target_resolution_failure() -> None:
    patch: dict[str, Any] = {}

    retry = keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(),
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
    assert ready["reason"] == keycloak_client_handler.TARGET_UNAVAILABLE_REASON
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": keycloak_client_handler.TARGET_UNAVAILABLE_REASON,
        "message": (
            "Drift detection was skipped because the referenced KeycloakTarget could "
            "not be resolved."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert retry == reconciliation.RetryRequest(
        keycloak_client_handler.TARGET_UNAVAILABLE_REASON,
        ready["message"],
    )


def test_patch_keycloak_client_status_observes_matching_public_client_without_put() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(lookup_result=[_existing_public_client()])
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    retry = keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(),
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
        "reason": keycloak_client_handler.CLIENT_OBSERVED_REASON,
        "message": "Keycloak public client already matches desired state.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "False",
        "reason": keycloak_client_handler.NO_DRIFT_DETECTED_REASON,
        "message": "Keycloak client has no modeled drift.",
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
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        )
    ]
    assert patch["status"]["remoteId"] == "client-uuid"
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password"})


def test_patch_keycloak_client_status_matches_scope_assignments_without_order_drift() -> None:
    keycloak_client = FakeKeycloakClient(
        lookup_result=[
            _existing_public_client(
                defaultClientScopes=["roles", "profile"],
                optionalClientScopes=["offline_access"],
            )
        ]
    )
    patch: dict[str, Any] = {}

    keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            default_client_scopes=["profile", "roles"],
            optional_client_scopes=["offline_access"],
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["reason"] == keycloak_client_handler.CLIENT_OBSERVED_REASON
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        )
    ]


def test_patch_keycloak_client_status_updates_drifted_public_client_preserving_fields() -> None:
    keycloak_client = FakeKeycloakClient(
        lookup_result=[
            _existing_public_client(
                enabled=False,
                name="Old display name",
                description="Old description",
                redirectUris=["https://old.example.com/*"],
                webOrigins=["https://old.example.com"],
                standardFlowEnabled=True,
                implicitFlowEnabled=True,
                directAccessGrantsEnabled=True,
                fullScopeAllowed=True,
                frontchannelLogout=False,
                rootUrl="https://old.example.com",
                baseUrl="/old",
                adminUrl="https://old.example.com/admin",
                defaultClientScopes=["profile"],
                optionalClientScopes=["address"],
            )
        ]
    )
    patch: dict[str, Any] = {}

    retry = keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            display_name="Example Web",
            description="Example web client",
            redirect_uris=["https://app.example.com/*"],
            web_origins=["https://app.example.com"],
            root_url="https://app.example.com",
            base_url="/",
            admin_url="https://app.example.com/admin",
            standard_flow_enabled=False,
            implicit_flow_enabled=False,
            direct_access_grants_enabled=False,
            full_scope_allowed=False,
            frontchannel_logout=True,
            default_client_scopes=["profile", "roles"],
            optional_client_scopes=["offline_access"],
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry is None
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "True",
        "reason": keycloak_client_handler.CLIENT_UPDATED_REASON,
        "message": "Keycloak public client was updated.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "False",
        "reason": keycloak_client_handler.NO_DRIFT_DETECTED_REASON,
        "message": "Keycloak client has no modeled drift.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        ),
        (
            "PUT",
            "realms/example/clients/client-uuid",
            {
                "json": {
                    "id": "client-uuid",
                    "clientId": "example-web",
                    "enabled": True,
                    "protocol": "openid-connect",
                    "publicClient": True,
                    "name": "Example Web",
                    "description": "Example web client",
                    "rootUrl": "https://app.example.com",
                    "baseUrl": "/",
                    "adminUrl": "https://app.example.com/admin",
                    "standardFlowEnabled": False,
                    "implicitFlowEnabled": False,
                    "directAccessGrantsEnabled": False,
                    "fullScopeAllowed": False,
                    "frontchannelLogout": True,
                    "redirectUris": ["https://app.example.com/*"],
                    "webOrigins": ["https://app.example.com"],
                    "defaultClientScopes": ["profile", "roles"],
                    "optionalClientScopes": ["offline_access"],
                }
            },
        ),
    ]
    assert patch["status"]["remoteId"] == "client-uuid"


def test_patch_keycloak_client_status_reports_observe_only_drift_without_put() -> None:
    keycloak_client = FakeKeycloakClient(
        lookup_result=[
            _existing_public_client(
                enabled=False,
                name="Old display name",
            )
        ]
    )
    patch: dict[str, Any] = {}

    retry = keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            management_policy=keycloak_client_handler.MANAGEMENT_POLICY_OBSERVE_ONLY,
            display_name="Example Web",
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry is None
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "True",
        "reason": keycloak_client_handler.CLIENT_DRIFT_DETECTED_REASON,
        "message": (
            "Keycloak public client has modeled drift and was not changed because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "True",
        "reason": keycloak_client_handler.CLIENT_DRIFT_DETECTED_REASON,
        "message": (
            "Keycloak client differs from desired state and was not changed because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        )
    ]


def test_patch_keycloak_client_status_reports_observe_only_matching_client_without_drift() -> None:
    keycloak_client = FakeKeycloakClient(lookup_result=[_existing_public_client()])
    patch: dict[str, Any] = {}

    retry = keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            management_policy=keycloak_client_handler.MANAGEMENT_POLICY_OBSERVE_ONLY,
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry is None
    assert conditions[CONDITION_READY]["status"] == "True"
    assert conditions[CONDITION_READY]["reason"] == keycloak_client_handler.CLIENT_OBSERVED_REASON
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "False",
        "reason": keycloak_client_handler.NO_DRIFT_DETECTED_REASON,
        "message": "Keycloak client has no modeled drift.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        )
    ]


def test_patch_keycloak_client_status_reports_observe_only_missing_client_without_post() -> None:
    keycloak_client = FakeKeycloakClient()
    patch: dict[str, Any] = {}

    retry = keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            management_policy=keycloak_client_handler.MANAGEMENT_POLICY_OBSERVE_ONLY,
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry is None
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "False",
        "reason": keycloak_client_handler.CLIENT_MISSING_REASON,
        "message": (
            "Keycloak public client is missing and was not created because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "True",
        "reason": keycloak_client_handler.CLIENT_MISSING_REASON,
        "message": (
            "Keycloak client is missing and was not created because managementPolicy "
            "is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        )
    ]


def test_patch_keycloak_client_status_updates_confidential_client_without_secret_leak() -> None:
    keycloak_client = FakeKeycloakClient(
        lookup_result=[
            _existing_confidential_client(
                clientId="example-service",
                enabled=False,
                secret="existing-keycloak-secret",
                serviceAccountsEnabled=True,
            )
        ]
    )
    core_v1_api = _client_secret_core_v1_api()
    patch: dict[str, Any] = {}

    keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            client_id="example-service",
            client_type=keycloak_client_handler.CLIENT_TYPE_CONFIDENTIAL,
            secret_ref={"name": "example-client-secret"},
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        core_v1_api=core_v1_api,
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["status"] == "True"
    assert conditions[CONDITION_READY]["reason"] == keycloak_client_handler.CLIENT_UPDATED_REASON
    assert conditions[CONDITION_READY]["message"] == "Keycloak confidential client was updated."
    assert core_v1_api.calls == []
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-service"}},
        ),
        (
            "PUT",
            "realms/example/clients/client-uuid",
            {
                "json": {
                    "id": "client-uuid",
                    "clientId": "example-service",
                    "enabled": True,
                    "protocol": "openid-connect",
                    "publicClient": False,
                    "serviceAccountsEnabled": True,
                }
            },
        ),
    ]
    put_payload = keycloak_client.requests[1][2]["json"]
    assert "secret" not in put_payload
    assert _condition_messages(patch).isdisjoint(
        {"client-secret-value", "existing-keycloak-secret"}
    )


def test_patch_keycloak_client_status_reports_failure_for_drift_without_id() -> None:
    keycloak_client = FakeKeycloakClient(
        lookup_result=[
            _existing_public_client(id=None, enabled=False),
        ]
    )
    patch: dict[str, Any] = {}

    retry = keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_client_handler.REQUEST_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "False",
        "reason": keycloak_client_handler.REQUEST_FAILED_REASON,
        "message": (
            "KeycloakClient reconciliation failed while calling the Keycloak Admin API."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        )
    ]


def test_patch_keycloak_client_status_creates_missing_public_client() -> None:
    keycloak_client = FakeKeycloakClient()
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    core_v1_api = FakeCoreV1Api()
    patch: dict[str, Any] = {}

    keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            display_name="Example Web",
            redirect_uris=["https://app.example.com/*"],
            web_origins=["https://app.example.com"],
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        core_v1_api=core_v1_api,
        keycloak_client_factory=keycloak_client_factory,
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY]["status"] == "True"
    assert conditions[CONDITION_READY]["reason"] == keycloak_client_handler.CLIENT_CREATED_REASON
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        ),
        (
            "POST",
            "realms/example/clients",
            {
                "json": {
                    "clientId": "example-web",
                    "enabled": True,
                    "protocol": "openid-connect",
                    "publicClient": True,
                    "name": "Example Web",
                    "redirectUris": ["https://app.example.com/*"],
                    "webOrigins": ["https://app.example.com"],
                }
            },
        ),
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        ),
    ]
    assert patch["status"]["remoteId"] == "created-client-uuid"
    assert core_v1_api.calls == []


def test_patch_keycloak_client_status_creates_missing_confidential_client() -> None:
    keycloak_client = FakeKeycloakClient()
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    core_v1_api = _client_secret_core_v1_api()
    patch: dict[str, Any] = {}

    keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            client_id="example-service",
            client_type=keycloak_client_handler.CLIENT_TYPE_CONFIDENTIAL,
            secret_ref={"name": "example-client-secret"},
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        core_v1_api=core_v1_api,
        keycloak_client_factory=keycloak_client_factory,
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "True",
        "reason": keycloak_client_handler.CLIENT_CREATED_REASON,
        "message": "Keycloak confidential client was created.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert core_v1_api.calls == [("apps", "example-client-secret")]
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-service"}},
        ),
        (
            "POST",
            "realms/example/clients",
            {
                "json": {
                    "clientId": "example-service",
                    "enabled": True,
                    "protocol": "openid-connect",
                    "publicClient": False,
                    "secret": "client-secret-value",
                }
            },
        ),
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-service"}},
        ),
    ]
    assert patch["status"]["remoteId"] == "created-client-uuid"
    assert _condition_messages(patch).isdisjoint({"client-secret-value"})


def test_patch_keycloak_client_status_reports_missing_client_secret_without_secret_values() -> None:
    keycloak_client = FakeKeycloakClient()
    core_v1_api = FakeCoreV1Api(
        read_error=ApiException(reason="missing client-secret-value")
    )
    patch: dict[str, Any] = {}

    keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            client_type=keycloak_client_handler.CLIENT_TYPE_CONFIDENTIAL,
            secret_ref={"name": "example-client-secret"},
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        core_v1_api=core_v1_api,
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert conditions[CONDITION_READY] == {
        "type": CONDITION_READY,
        "status": "False",
        "reason": keycloak_client_handler.SECRET_UNAVAILABLE_REASON,
        "message": "KeycloakClient is not ready because the client Secret could not be loaded.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }
    assert core_v1_api.calls == [("apps", "example-client-secret")]
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        )
    ]
    assert _condition_messages(patch).isdisjoint({"client-secret-value"})


def test_patch_keycloak_client_status_reports_auth_failure_without_secret_values() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_client_handler.AUTHENTICATION_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert (
        conditions[CONDITION_READY]["reason"]
        == keycloak_client_handler.AUTHENTICATION_FAILED_REASON
    )
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_client_status_reports_request_failure_without_secret_values() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakRequestError("failed for kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_client_handler.REQUEST_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert conditions[CONDITION_READY]["reason"] == keycloak_client_handler.REQUEST_FAILED_REASON
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_client_status_reports_confidential_auth_failure_safely() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad client-secret-value token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            client_type=keycloak_client_handler.CLIENT_TYPE_CONFIDENTIAL,
            secret_ref={"name": "example-client-secret"},
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        core_v1_api=_client_secret_core_v1_api(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_client_handler.AUTHENTICATION_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert (
        conditions[CONDITION_READY]["reason"]
        == keycloak_client_handler.AUTHENTICATION_FAILED_REASON
    )
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert _condition_messages(patch).isdisjoint({"client-secret-value", "token"})


def test_patch_keycloak_client_status_reports_confidential_request_failure_safely() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakRequestError("failed for client-secret-value token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            client_type=keycloak_client_handler.CLIENT_TYPE_CONFIDENTIAL,
            secret_ref={"name": "example-client-secret"},
        ),
        status={},
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        core_v1_api=_client_secret_core_v1_api(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        now=NOW,
    )

    conditions = _conditions_by_type(patch)
    assert retry == reconciliation.RetryRequest(
        keycloak_client_handler.REQUEST_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert conditions[CONDITION_READY]["reason"] == keycloak_client_handler.REQUEST_FAILED_REASON
    assert _condition_messages(patch).isdisjoint({"client-secret-value", "token"})


def test_delete_keycloak_client_resource_orphan_noop_without_external_calls() -> None:
    keycloak_client_handler.delete_keycloak_client_resource(
        spec=_client_spec(),
        namespace="apps",
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
    )


def test_delete_keycloak_client_resource_delete_removes_existing_client() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(lookup_result=[_existing_public_client()])
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)

    keycloak_client_handler.delete_keycloak_client_resource(
        spec=_client_spec(
            deletion_policy=keycloak_client_handler.DELETION_POLICY_DELETE,
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
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        ),
        ("DELETE", "realms/example/clients/client-uuid", {}),
    ]


def test_delete_keycloak_client_resource_delete_missing_client_noop() -> None:
    keycloak_client = FakeKeycloakClient()

    keycloak_client_handler.delete_keycloak_client_resource(
        spec=_client_spec(
            deletion_policy=keycloak_client_handler.DELETION_POLICY_DELETE,
        ),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        )
    ]


def test_delete_keycloak_client_resource_delete_missing_id_safe_failure() -> None:
    keycloak_client = FakeKeycloakClient(
        lookup_result=[_existing_public_client(id=None)],
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_client_handler.delete_keycloak_client_resource(
            spec=_client_spec(
                deletion_policy=keycloak_client_handler.DELETION_POLICY_DELETE,
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakClient deletion failed while calling the Keycloak Admin API."
    )
    assert "secret-password" not in str(exc_info.value)
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        )
    ]


def test_delete_keycloak_client_resource_auth_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_client_handler.delete_keycloak_client_resource(
            spec=_client_spec(
                deletion_policy=keycloak_client_handler.DELETION_POLICY_DELETE,
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakClient deletion failed because Keycloak authentication failed."
    )
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert {"kc-admin", "secret-password", "token"}.isdisjoint(
        set(str(exc_info.value).split())
    )


def test_delete_keycloak_client_resource_request_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        lookup_result=[_existing_public_client()],
        delete_error=KeycloakRequestError("failed for kc-admin secret-password token"),
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_client_handler.delete_keycloak_client_resource(
            spec=_client_spec(
                deletion_policy=keycloak_client_handler.DELETION_POLICY_DELETE,
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakClient deletion failed while calling the Keycloak Admin API."
    )
    assert keycloak_client.requests == [
        (
            "GET",
            "realms/example/clients",
            {"params": {"clientId": "example-web"}},
        ),
        ("DELETE", "realms/example/clients/client-uuid", {}),
    ]
    assert {"kc-admin", "secret-password", "token"}.isdisjoint(
        set(str(exc_info.value).split())
    )


def test_patch_keycloak_client_status_preserves_stable_transition_time() -> None:
    patch: dict[str, Any] = {}

    keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(),
        status={
            "conditions": [
                ready_condition("True", "OldReady", "Old ready message.", now=OLD_NOW),
            ],
        },
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(
            FakeKeycloakClient(lookup_result=[_existing_public_client()])
        ),
        now=NOW,
    )

    ready = _conditions_by_type(patch)[CONDITION_READY]
    assert ready["reason"] == keycloak_client_handler.CLIENT_OBSERVED_REASON
    assert ready["lastTransitionTime"] == "2026-05-22T09:30:45Z"


def test_patch_keycloak_client_status_preserves_stable_drift_transition_time() -> None:
    patch: dict[str, Any] = {}

    keycloak_client_handler.patch_keycloak_client_status(
        spec=_client_spec(
            management_policy=keycloak_client_handler.MANAGEMENT_POLICY_OBSERVE_ONLY,
            display_name="Example Web",
        ),
        status={
            "conditions": [
                drift_detected_condition(
                    "True",
                    "OldDrift",
                    "Old drift message.",
                    now=OLD_NOW,
                ),
            ],
        },
        patch=patch,
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(
            FakeKeycloakClient(
                lookup_result=[
                    _existing_public_client(
                        enabled=False,
                        name="Old display name",
                    )
                ]
            )
        ),
        now=NOW,
    )

    drift = _conditions_by_type(patch)[CONDITION_DRIFT_DETECTED]
    assert drift["reason"] == keycloak_client_handler.CLIENT_DRIFT_DETECTED_REASON
    assert drift["lastTransitionTime"] == "2026-05-22T09:30:45Z"


def _target_resolver() -> FakeTargetResolver:
    return FakeTargetResolver(
        keycloak_client_handler.TargetConnection(
            url="https://keycloak.example.test",
            username="kc-admin",
            password="secret-password",
        )
    )


def _client_spec(
    *,
    client_id: str = "example-web",
    client_type: str | None = None,
    management_policy: str | None = None,
    deletion_policy: str | None = None,
    secret_ref: dict[str, str] | None = None,
    enabled: Any | None = None,
    display_name: str | None = None,
    description: str | None = None,
    redirect_uris: list[str] | None = None,
    web_origins: list[str] | None = None,
    root_url: str | None = None,
    base_url: str | None = None,
    admin_url: str | None = None,
    standard_flow_enabled: bool | None = None,
    implicit_flow_enabled: Any | None = None,
    direct_access_grants_enabled: bool | None = None,
    service_accounts_enabled: bool | None = None,
    full_scope_allowed: Any | None = None,
    frontchannel_logout: Any | None = None,
    default_client_scopes: list[str] | None = None,
    optional_client_scopes: list[str] | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "targetRef": {"name": "example-keycloak"},
        "realm": "example",
        "clientId": client_id,
    }
    if client_type is not None:
        spec["clientType"] = client_type
    if management_policy is not None:
        spec["managementPolicy"] = management_policy
    if deletion_policy is not None:
        spec["deletionPolicy"] = deletion_policy
    if secret_ref is not None:
        spec["secretRef"] = secret_ref
    if enabled is not None:
        spec["enabled"] = enabled
    if display_name is not None:
        spec["displayName"] = display_name
    if description is not None:
        spec["description"] = description
    if redirect_uris is not None:
        spec["redirectUris"] = redirect_uris
    if web_origins is not None:
        spec["webOrigins"] = web_origins
    if root_url is not None:
        spec["rootUrl"] = root_url
    if base_url is not None:
        spec["baseUrl"] = base_url
    if admin_url is not None:
        spec["adminUrl"] = admin_url
    if standard_flow_enabled is not None:
        spec["standardFlowEnabled"] = standard_flow_enabled
    if implicit_flow_enabled is not None:
        spec["implicitFlowEnabled"] = implicit_flow_enabled
    if direct_access_grants_enabled is not None:
        spec["directAccessGrantsEnabled"] = direct_access_grants_enabled
    if service_accounts_enabled is not None:
        spec["serviceAccountsEnabled"] = service_accounts_enabled
    if full_scope_allowed is not None:
        spec["fullScopeAllowed"] = full_scope_allowed
    if frontchannel_logout is not None:
        spec["frontchannelLogout"] = frontchannel_logout
    if default_client_scopes is not None:
        spec["defaultClientScopes"] = default_client_scopes
    if optional_client_scopes is not None:
        spec["optionalClientScopes"] = optional_client_scopes

    return spec


def _existing_public_client(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "client-uuid",
        "clientId": "example-web",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": True,
    }
    payload.update(overrides)
    return payload


def _existing_confidential_client(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "client-uuid",
        "clientId": "example-service",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
    }
    payload.update(overrides)
    return payload


def _client_secret_core_v1_api() -> FakeCoreV1Api:
    return FakeCoreV1Api(
        {
            ("apps", "example-client-secret"): FakeSecret(
                data={"clientSecret": _b64("client-secret-value")},
            )
        }
    )


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
) -> keycloak_client_handler.TargetConnection:
    raise AssertionError(f"unexpected target resolution: {namespace}/{target_name}")


def _unavailable_target_resolver(
    *,
    target_name: str,
    namespace: str | None,
) -> keycloak_client_handler.TargetConnection:
    raise keycloak_client_handler.TargetResolutionError(
        f"target unavailable: {namespace}/{target_name}"
    )


def _failing_keycloak_client_factory(
    *,
    base_url: str,
    username: str,
    password: str,
) -> FakeKeycloakClient:
    raise AssertionError(f"unexpected Keycloak client: {base_url}, {username}, {password}")


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")
