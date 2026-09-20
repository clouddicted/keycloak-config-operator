import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from clouddicted_keycloak_config_operator import cli
from clouddicted_keycloak_config_operator.adoption import (
    AdoptionError,
    AdoptionResult,
    NameRegistry,
    discover_realm,
    format_report,
    kubernetes_name,
    render_yaml,
)

FIXTURE = Path(__file__).parent / "fixtures" / "adoption" / "responses.json"


class FixtureClient:
    def __init__(self) -> None:
        self.responses = json.loads(FIXTURE.read_text())
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.requests.append((method, path, kwargs))
        return copy.deepcopy(self.responses[path])


def test_discovery_renders_all_supported_kinds_deterministically_without_secrets() -> None:
    first = _discover()
    second = _discover()

    rendered = render_yaml(first)
    assert rendered == render_yaml(second)
    assert "must-never-render" not in rendered
    assert "another-value-that-must-never-render" not in rendered
    assert "**********" not in rendered
    assert "clientSecret" not in rendered

    documents = list(yaml.safe_load_all(rendered))
    assert {document["kind"] for document in documents} == {
        "KeycloakRealm",
        "KeycloakRole",
        "KeycloakClientScope",
        "KeycloakClient",
        "KeycloakClientRole",
        "KeycloakGroup",
        "KeycloakIdentityProvider",
        "KeycloakIdentityProviderMapper",
        "KeycloakProtocolMapper",
        "KeycloakGroupRoleMapping",
    }
    assert all(document["metadata"]["namespace"] == "apps" for document in documents)
    assert all(
        document["spec"]["managementPolicy"] == "ObserveOnly"
        for document in documents
    )
    assert all(
        document["spec"].get("deletionPolicy") == "Orphan"
        for document in documents
        if document["kind"] != "KeycloakRealm"
    )

    confidential = _document(documents, "KeycloakClient", "example-service")
    assert confidential["spec"]["clientType"] == "Confidential"
    assert "secretRef" not in confidential["spec"]
    assert "authentication" not in confidential["spec"]

    signed_jwt = _document(documents, "KeycloakClient", "example-signed-jwt")
    assert signed_jwt["spec"]["authentication"] == {
        "method": "SignedJwt",
        "signedJwt": {
            "jwksUrl": "https://service.example.com/.well-known/jwks.json",
            "signatureAlgorithm": "RS256",
        },
    }

    provider = _document(documents, "KeycloakIdentityProvider", "corporate")
    assert provider["spec"]["config"] == {
        "authorizationUrl": "https://login.example.com/authorize",
        "clientId": "corporate-client",
        "tokenUrl": "https://login.example.com/token",
    }


def test_discovery_excludes_builtins_and_reports_unsupported_and_secret_fields() -> None:
    result = _discover()
    report = format_report(result)

    assert result.skipped_builtins["KeycloakClient"] == 1
    assert result.skipped_builtins["KeycloakClientScope"] == 2
    assert result.skipped_builtins["KeycloakRole"] == 1
    assert "secret-omitted" in report
    assert "nested groups were skipped" in report
    assert "sslRequired" in report
    assert not result.errors


def test_discovery_uses_read_only_admin_api_requests() -> None:
    client = FixtureClient()
    discover_realm(
        client,
        realm="example",
        namespace="apps",
        target_ref="example-keycloak",
    )

    assert client.requests
    assert {method for method, _, _ in client.requests} == {"GET"}


def test_render_refuses_name_collisions_without_partial_output() -> None:
    result = AdoptionResult(realm="example")
    names = NameRegistry(result)
    assert names.assign("KeycloakRole", "reader role", "role:first") == "reader-role"
    assert names.assign("KeycloakRole", "reader_role", "role:second") == "reader-role"

    with pytest.raises(AdoptionError, match="render blocked"):
        render_yaml(result)


def test_render_refuses_duplicate_resource_identity() -> None:
    result = AdoptionResult(realm="example")
    names = NameRegistry(result)
    names.assign("KeycloakRole", "reader", "role:reader")
    names.assign("KeycloakRole", "reader", "role:reader")

    with pytest.raises(AdoptionError, match="render blocked"):
        render_yaml(result)


def test_render_refuses_unresolved_client_role_reference() -> None:
    client = FixtureClient()
    mapping_path = "realms/example/groups/group-team/role-mappings"
    client.responses[mapping_path]["clientMappings"]["client-web"]["mappings"][0][
        "name"
    ] = "missing-role"

    result = discover_realm(
        client,
        realm="example",
        namespace="apps",
        target_ref="example-keycloak",
    )

    assert "unresolved client role example-web/missing-role" in "\n".join(result.errors)
    with pytest.raises(AdoptionError, match="render blocked"):
        render_yaml(result)


@pytest.mark.parametrize(
    ("namespace", "target_ref", "match"),
    [
        ("Invalid_Namespace", "example-keycloak", "namespace"),
        ("apps", "Invalid_Target", "target reference"),
    ],
)
def test_discovery_rejects_invalid_kubernetes_references(
    namespace: str, target_ref: str, match: str
) -> None:
    with pytest.raises(AdoptionError, match=match):
        discover_realm(
            FixtureClient(),
            realm="example",
            namespace=namespace,
            target_ref=target_ref,
        )


def test_kubernetes_names_are_dns_safe_stable_and_bounded() -> None:
    assert kubernetes_name(" My Client_ID ") == "my-client-id"
    long_name = kubernetes_name("A" * 100, identity="client:a")
    assert len(long_name) <= 63
    assert long_name == kubernetes_name("A" * 100, identity="client:a")


def test_container_entrypoint_preserves_default_operator_mode() -> None:
    assert cli.operator_command(["--all-namespaces"]) == [
        "kopf",
        "run",
        "-m",
        "clouddicted_keycloak_config_operator.main",
        "--all-namespaces",
    ]


def test_container_entrypoint_dispatches_adoption_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: list[list[str]] = []

    def adoption_main(arguments: list[str]) -> int:
        received.append(arguments)
        return 23

    monkeypatch.setattr(cli.adoption, "main", adoption_main)

    assert cli.main(["adopt", "plan", "--realm", "example"]) == 23
    assert received == [["plan", "--realm", "example"]]


def test_container_entrypoint_executes_kopf_for_operator_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command: list[str] = []

    def execvp(executable: str, arguments: list[str]) -> None:
        command.extend([executable, *arguments])
        raise RuntimeError("exec intercepted")

    monkeypatch.setattr(cli.os, "execvp", execvp)

    with pytest.raises(RuntimeError, match="exec intercepted"):
        cli.main(["--all-namespaces"])
    assert command == [
        "kopf",
        "kopf",
        "run",
        "-m",
        "clouddicted_keycloak_config_operator.main",
        "--all-namespaces",
    ]


def _discover() -> AdoptionResult:
    return discover_realm(
        FixtureClient(),
        realm="example",
        namespace="apps",
        target_ref="example-keycloak",
    )


def _document(
    documents: list[dict[str, Any]], kind: str, name: str
) -> dict[str, Any]:
    return next(
        document
        for document in documents
        if document["kind"] == kind and document["metadata"]["name"] == name
    )
