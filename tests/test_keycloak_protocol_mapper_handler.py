from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import kopf
import pytest

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_PROTOCOL_MAPPER_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import (
    keycloak_protocol_mapper,
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
    target: keycloak_protocol_mapper.TargetConnection

    def __post_init__(self) -> None:
        self.calls: list[dict[str, str | None]] = []

    def __call__(
        self,
        *,
        target_name: str,
        namespace: str | None,
    ) -> keycloak_protocol_mapper.TargetConnection:
        self.calls.append({"target_name": target_name, "namespace": namespace})
        return self.target


class FakeKeycloakClient:
    def __init__(
        self,
        *,
        clients_result: list[dict[str, Any]] | None = None,
        client_scopes_result: list[dict[str, Any]] | None = None,
        mapper_result: list[dict[str, Any]] | None = None,
        auth_error: Exception | None = None,
        get_error: Exception | None = None,
        post_error: Exception | None = None,
        put_error: Exception | None = None,
        delete_error: Exception | None = None,
    ) -> None:
        self.clients_result = [_existing_client()] if clients_result is None else clients_result
        self.client_scopes_result = (
            [_existing_client_scope()] if client_scopes_result is None else client_scopes_result
        )
        self.mapper_result = [_existing_mapper()] if mapper_result is None else mapper_result
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
            if path.endswith("/clients"):
                return self.clients_result
            if path.endswith("/client-scopes"):
                return self.client_scopes_result
            if path.endswith("/protocol-mappers/models"):
                return self.mapper_result

        if method == "POST":
            if self.post_error is not None:
                raise self.post_error
            payload = kwargs.get("json")
            if isinstance(payload, dict) and isinstance(payload.get("name"), str):
                self.mapper_result.append(
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


def test_keycloak_protocol_mapper_resource_registration_values() -> None:
    assert keycloak_protocol_mapper.KEYCLOAK_PROTOCOL_MAPPER_RESOURCE == {
        "group": API_GROUP,
        "version": API_VERSION,
        "plural": KEYCLOAK_PROTOCOL_MAPPER_PLURAL,
    }


def test_main_imports_keycloak_protocol_mapper_handler_module() -> None:
    assert keycloak_protocol_mapper in main.REGISTERED_HANDLER_MODULES


def test_patch_keycloak_protocol_mapper_status_reports_invalid_spec() -> None:
    patch: dict[str, Any] = {}

    keycloak_protocol_mapper.patch_keycloak_protocol_mapper_status(
        spec={"targetRef": {}, "parent": {}},
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
        "reason": keycloak_protocol_mapper.INVALID_SPEC_REASON,
        "message": (
            "Missing required KeycloakProtocolMapper spec fields: "
            "targetRef.name, realm, name, mapperType, parent.type."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": keycloak_protocol_mapper.INVALID_SPEC_REASON,
        "message": (
            "Drift detection was skipped because the KeycloakProtocolMapper spec is "
            "invalid."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }


def test_patch_keycloak_protocol_mapper_status_reports_invalid_field_values() -> None:
    patch: dict[str, Any] = {}
    spec = _mapper_spec(
        parent_type="Realm",
        protocol="",
        management_policy="Apply",
        deletion_policy="Remove",
    )
    spec["config"] = {"claim.name": 3}

    keycloak_protocol_mapper.patch_keycloak_protocol_mapper_status(
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
        "reason": keycloak_protocol_mapper.INVALID_SPEC_REASON,
        "message": (
            "Invalid KeycloakProtocolMapper spec fields: managementPolicy must be one "
            "of: `ObserveOnly`, `Reconcile`; deletionPolicy must be one of: "
            "`Delete`, `Orphan`; protocol must be a non-empty string; "
            "parent.type must be one of: `Client`, `ClientScope`; config must use "
            "non-empty string keys and string values."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }


def test_patch_keycloak_protocol_mapper_status_reports_target_resolution_failure() -> None:
    patch: dict[str, Any] = {}

    retry = keycloak_protocol_mapper.patch_keycloak_protocol_mapper_status(
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
    assert ready["reason"] == keycloak_protocol_mapper.TARGET_UNAVAILABLE_REASON
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": keycloak_protocol_mapper.TARGET_UNAVAILABLE_REASON,
        "message": (
            "Drift detection was skipped because the referenced KeycloakTarget could "
            "not be resolved."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert retry == reconciliation.RetryRequest(
        keycloak_protocol_mapper.TARGET_UNAVAILABLE_REASON,
        ready["message"],
    )


def test_patch_keycloak_protocol_mapper_status_observes_existing_client_mapper() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        clients_result=[_existing_client(id="client uuid", clientId="app/client")],
        mapper_result=[
            _existing_mapper(
                name="email/claim",
                protocol="openid-connect",
                protocolMapper="oidc-usermodel-property-mapper",
                config={"claim.name": "email"},
            )
        ],
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)
    patch: dict[str, Any] = {}

    keycloak_protocol_mapper.patch_keycloak_protocol_mapper_status(
        spec=_mapper_spec(
            realm="example realm",
            name="email/claim",
            parent_type=keycloak_protocol_mapper.PARENT_TYPE_CLIENT,
            parent_name="app/client",
            config={"claim.name": "email"},
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
        "reason": keycloak_protocol_mapper.PROTOCOL_MAPPER_OBSERVED_REASON,
        "message": "Keycloak protocol mapper already matches desired state.",
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "False",
        "reason": keycloak_protocol_mapper.NO_DRIFT_DETECTED_REASON,
        "message": "Keycloak protocol mapper has no modeled drift.",
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
        (
            "GET",
            "realms/example%20realm/clients",
            {"params": {"clientId": "app/client"}},
        ),
        (
            "GET",
            "realms/example%20realm/clients/client%20uuid/protocol-mappers/models",
            {},
        ),
    ]
    assert patch["status"]["remoteId"] == "mapper-uuid"
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password"})


def test_patch_keycloak_protocol_mapper_status_creates_client_scope_mapper() -> None:
    keycloak_client = FakeKeycloakClient(mapper_result=[])
    patch: dict[str, Any] = {}

    keycloak_protocol_mapper.patch_keycloak_protocol_mapper_status(
        spec=_mapper_spec(config={"claim.name": "email", "access.token.claim": "true"}),
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
        == keycloak_protocol_mapper.PROTOCOL_MAPPER_CREATED_REASON
    )
    assert keycloak_client.requests == [
        ("GET", "realms/example/client-scopes", {}),
        (
            "GET",
            "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models",
            {},
        ),
        (
            "POST",
            "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models",
            {
                "json": {
                    "name": "email",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-property-mapper",
                    "config": {
                        "claim.name": "email",
                        "access.token.claim": "true",
                    },
                }
            },
        ),
        (
            "GET",
            "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models",
            {},
        ),
    ]
    assert patch["status"]["remoteId"] == "created-mapper-uuid"


def test_patch_keycloak_protocol_mapper_status_observe_only_reports_missing_mapper() -> None:
    keycloak_client = FakeKeycloakClient(mapper_result=[])
    patch: dict[str, Any] = {}

    keycloak_protocol_mapper.patch_keycloak_protocol_mapper_status(
        spec=_mapper_spec(
            config={"claim.name": "email"},
            management_policy=keycloak_protocol_mapper.MANAGEMENT_POLICY_OBSERVE_ONLY,
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
        "reason": keycloak_protocol_mapper.PROTOCOL_MAPPER_MISSING_REASON,
        "message": (
            "Keycloak protocol mapper is missing and was not created because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "True",
        "reason": keycloak_protocol_mapper.PROTOCOL_MAPPER_MISSING_REASON,
        "message": (
            "Keycloak protocol mapper is missing and was not created because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert keycloak_client.requests == [
        ("GET", "realms/example/client-scopes", {}),
        (
            "GET",
            "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models",
            {},
        ),
    ]
    assert patch["status"]["remoteId"] is None


def test_patch_keycloak_protocol_mapper_status_updates_drift_preserving_fields() -> None:
    keycloak_client = FakeKeycloakClient(
        mapper_result=[
            _existing_mapper(
                protocol="saml",
                protocolMapper="old-mapper",
                consentRequired=True,
                config={"claim.name": "old", "custom.keep": "true"},
            )
        ],
    )
    patch: dict[str, Any] = {}

    keycloak_protocol_mapper.patch_keycloak_protocol_mapper_status(
        spec=_mapper_spec(config={"claim.name": "email", "access.token.claim": "true"}),
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
        "reason": keycloak_protocol_mapper.PROTOCOL_MAPPER_UPDATED_REASON,
        "message": "Keycloak protocol mapper was updated.",
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert keycloak_client.requests == [
        ("GET", "realms/example/client-scopes", {}),
        (
            "GET",
            "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models",
            {},
        ),
        (
            "PUT",
            (
                "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models/"
                "mapper-uuid"
            ),
            {
                "json": {
                    "id": "mapper-uuid",
                    "name": "email",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-property-mapper",
                    "consentRequired": True,
                    "config": {
                        "claim.name": "email",
                        "custom.keep": "true",
                        "access.token.claim": "true",
                    },
                }
            },
        ),
    ]
    assert patch["status"]["remoteId"] == "mapper-uuid"


def test_patch_keycloak_protocol_mapper_status_observe_only_reports_modeled_drift() -> None:
    keycloak_client = FakeKeycloakClient(
        mapper_result=[
            _existing_mapper(
                protocol="saml",
                protocolMapper="old-mapper",
                consentRequired=True,
                config={"claim.name": "old", "custom.keep": "true"},
            )
        ],
    )
    patch: dict[str, Any] = {}

    keycloak_protocol_mapper.patch_keycloak_protocol_mapper_status(
        spec=_mapper_spec(
            config={"claim.name": "email", "access.token.claim": "true"},
            management_policy=keycloak_protocol_mapper.MANAGEMENT_POLICY_OBSERVE_ONLY,
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
        "reason": keycloak_protocol_mapper.PROTOCOL_MAPPER_DRIFT_DETECTED_REASON,
        "message": (
            "Keycloak protocol mapper has modeled drift and was not changed because "
            "managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert conditions[CONDITION_DRIFT_DETECTED] == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "True",
        "reason": keycloak_protocol_mapper.PROTOCOL_MAPPER_DRIFT_DETECTED_REASON,
        "message": (
            "Keycloak protocol mapper differs from desired state and was not changed "
            "because managementPolicy is ObserveOnly."
        ),
        "lastTransitionTime": "2026-05-24T11:30:45Z",
    }
    assert keycloak_client.requests == [
        ("GET", "realms/example/client-scopes", {}),
        (
            "GET",
            "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models",
            {},
        ),
    ]
    assert patch["status"]["remoteId"] == "mapper-uuid"


def test_patch_keycloak_protocol_mapper_status_reports_auth_failure_without_secret_values() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_protocol_mapper.patch_keycloak_protocol_mapper_status(
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
        keycloak_protocol_mapper.AUTHENTICATION_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert (
        conditions[CONDITION_READY]["reason"]
        == keycloak_protocol_mapper.AUTHENTICATION_FAILED_REASON
    )
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_patch_keycloak_protocol_mapper_status_reports_request_failure() -> None:
    keycloak_client = FakeKeycloakClient(
        get_error=KeycloakRequestError("failed for kc-admin secret-password token")
    )
    patch: dict[str, Any] = {}

    retry = keycloak_protocol_mapper.patch_keycloak_protocol_mapper_status(
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
        keycloak_protocol_mapper.REQUEST_FAILED_REASON,
        conditions[CONDITION_READY]["message"],
    )
    assert conditions[CONDITION_READY]["status"] == "False"
    assert (
        conditions[CONDITION_READY]["reason"] == keycloak_protocol_mapper.REQUEST_FAILED_REASON
    )
    assert _condition_messages(patch).isdisjoint({"kc-admin", "secret-password", "token"})


def test_delete_keycloak_protocol_mapper_resource_orphan_noop_without_external_calls() -> None:
    keycloak_protocol_mapper.delete_keycloak_protocol_mapper_resource(
        spec=_mapper_spec(),
        namespace="apps",
        target_resolver=_failing_target_resolver,
        keycloak_client_factory=_failing_keycloak_client_factory,
    )


def test_delete_keycloak_protocol_mapper_resource_delete_removes_existing_mapper() -> None:
    resolver = _target_resolver()
    keycloak_client = FakeKeycloakClient(
        mapper_result=[_existing_mapper(name="email/claim")]
    )
    keycloak_client_factory = FakeKeycloakClientFactory(keycloak_client)

    keycloak_protocol_mapper.delete_keycloak_protocol_mapper_resource(
        spec=_mapper_spec(
            name="email/claim",
            deletion_policy=keycloak_protocol_mapper.DELETION_POLICY_DELETE,
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
        (
            "GET",
            "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models",
            {},
        ),
        (
            "DELETE",
            (
                "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models/"
                "mapper-uuid"
            ),
            {},
        ),
    ]


def test_delete_keycloak_protocol_mapper_resource_delete_missing_mapper_noop() -> None:
    keycloak_client = FakeKeycloakClient(mapper_result=[])

    keycloak_protocol_mapper.delete_keycloak_protocol_mapper_resource(
        spec=_mapper_spec(deletion_policy=keycloak_protocol_mapper.DELETION_POLICY_DELETE),
        namespace="apps",
        target_resolver=_target_resolver(),
        keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
    )

    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == [
        ("GET", "realms/example/client-scopes", {}),
        (
            "GET",
            "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models",
            {},
        ),
    ]


def test_delete_keycloak_protocol_mapper_resource_delete_missing_id_safe_failure() -> None:
    keycloak_client = FakeKeycloakClient(mapper_result=[_existing_mapper(id=None)])

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_protocol_mapper.delete_keycloak_protocol_mapper_resource(
            spec=_mapper_spec(
                deletion_policy=keycloak_protocol_mapper.DELETION_POLICY_DELETE
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakProtocolMapper deletion failed while calling the Keycloak Admin API."
    )
    assert keycloak_client.requests == [
        ("GET", "realms/example/client-scopes", {}),
        (
            "GET",
            "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models",
            {},
        ),
    ]


def test_delete_keycloak_protocol_mapper_resource_invalid_spec_is_permanent_failure() -> None:
    with pytest.raises(kopf.PermanentError) as exc_info:
        keycloak_protocol_mapper.delete_keycloak_protocol_mapper_resource(
            spec={"targetRef": {}, "parent": {}},
            namespace="apps",
            target_resolver=_failing_target_resolver,
            keycloak_client_factory=_failing_keycloak_client_factory,
        )

    assert str(exc_info.value) == (
        "KeycloakProtocolMapper deletion skipped because spec is invalid."
    )


def test_delete_keycloak_protocol_mapper_resource_auth_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        auth_error=KeycloakAuthenticationError("bad kc-admin secret-password token")
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_protocol_mapper.delete_keycloak_protocol_mapper_resource(
            spec=_mapper_spec(
                deletion_policy=keycloak_protocol_mapper.DELETION_POLICY_DELETE
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakProtocolMapper deletion failed because Keycloak authentication failed."
    )
    assert keycloak_client.authenticate_calls == 1
    assert keycloak_client.requests == []
    assert {"kc-admin", "secret-password", "token"}.isdisjoint(
        set(str(exc_info.value).split())
    )


def test_delete_keycloak_protocol_mapper_resource_request_failure_is_safe() -> None:
    keycloak_client = FakeKeycloakClient(
        delete_error=KeycloakRequestError("failed for kc-admin secret-password token")
    )

    with pytest.raises(kopf.TemporaryError) as exc_info:
        keycloak_protocol_mapper.delete_keycloak_protocol_mapper_resource(
            spec=_mapper_spec(
                deletion_policy=keycloak_protocol_mapper.DELETION_POLICY_DELETE
            ),
            namespace="apps",
            target_resolver=_target_resolver(),
            keycloak_client_factory=FakeKeycloakClientFactory(keycloak_client),
        )

    assert str(exc_info.value) == (
        "KeycloakProtocolMapper deletion failed while calling the Keycloak Admin API."
    )
    assert keycloak_client.requests == [
        ("GET", "realms/example/client-scopes", {}),
        (
            "GET",
            "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models",
            {},
        ),
        (
            "DELETE",
            (
                "realms/example/client-scopes/client-scope-uuid/protocol-mappers/models/"
                "mapper-uuid"
            ),
            {},
        ),
    ]
    assert {"kc-admin", "secret-password", "token"}.isdisjoint(
        set(str(exc_info.value).split())
    )


def test_patch_keycloak_protocol_mapper_status_preserves_stable_transition_time() -> None:
    patch: dict[str, Any] = {}

    keycloak_protocol_mapper.patch_keycloak_protocol_mapper_status(
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
    assert ready["reason"] == keycloak_protocol_mapper.PROTOCOL_MAPPER_OBSERVED_REASON
    assert ready["lastTransitionTime"] == "2026-05-24T10:30:45Z"


def _target_resolver() -> FakeTargetResolver:
    return FakeTargetResolver(
        keycloak_protocol_mapper.TargetConnection(
            url="https://keycloak.example.test",
            username="kc-admin",
            password="secret-password",
        )
    )


def _mapper_spec(
    *,
    realm: str = "example",
    name: str = "email",
    mapper_type: str = "oidc-usermodel-property-mapper",
    parent_type: str = keycloak_protocol_mapper.PARENT_TYPE_CLIENT_SCOPE,
    parent_name: str = "example-profile",
    protocol: str | None = None,
    config: dict[str, str] | None = None,
    management_policy: str | None = None,
    deletion_policy: str | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "targetRef": {"name": "example-keycloak"},
        "realm": realm,
        "name": name,
        "mapperType": mapper_type,
        "parent": {"type": parent_type},
    }
    if parent_type == keycloak_protocol_mapper.PARENT_TYPE_CLIENT:
        spec["parent"]["clientRef"] = {"name": parent_name}
    else:
        spec["parent"]["clientScopeRef"] = {"name": parent_name}
    if protocol is not None:
        spec["protocol"] = protocol
    if config is not None:
        spec["config"] = config
    if management_policy is not None:
        spec["managementPolicy"] = management_policy
    if deletion_policy is not None:
        spec["deletionPolicy"] = deletion_policy

    return spec


def _existing_client(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "client-uuid",
        "clientId": "example-client",
    }
    payload.update(overrides)
    return payload


def _existing_client_scope(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "client-scope-uuid",
        "name": "example-profile",
    }
    payload.update(overrides)
    return payload


def _existing_mapper(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "mapper-uuid",
        "name": "email",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-property-mapper",
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
) -> keycloak_protocol_mapper.TargetConnection:
    raise AssertionError(f"unexpected target resolution: {namespace}/{target_name}")


def _unavailable_target_resolver(
    *,
    target_name: str,
    namespace: str | None,
) -> keycloak_protocol_mapper.TargetConnection:
    raise keycloak_protocol_mapper.TargetResolutionError(
        f"target unavailable: {namespace}/{target_name}"
    )


def _failing_keycloak_client_factory(
    *,
    base_url: str,
    username: str,
    password: str,
) -> FakeKeycloakClient:
    raise AssertionError(f"unexpected Keycloak client: {base_url}, {username}, {password}")
