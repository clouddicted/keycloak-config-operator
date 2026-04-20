import contextlib
import json
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("RUN_KIND_INTEGRATION") != "1",
        reason="set RUN_KIND_INTEGRATION=1 to run kind integration tests",
    ),
]

REPO_ROOT = Path(__file__).resolve().parents[2]
KIND_CONFIG = REPO_ROOT / "tests" / "kind" / "kind.yaml"
INSTALL_KUSTOMIZATION = REPO_ROOT / "config" / "install"
CRD = REPO_ROOT / "config" / "crd" / "keycloak.clouddicted.com_keycloaktargets.yaml"
REALM_CRD = REPO_ROOT / "config" / "crd" / "keycloak.clouddicted.com_keycloakrealms.yaml"
CLIENT_CRD = REPO_ROOT / "config" / "crd" / "keycloak.clouddicted.com_keycloakclients.yaml"
CLIENT_SCOPE_CRD = (
    REPO_ROOT / "config" / "crd" / "keycloak.clouddicted.com_keycloakclientscopes.yaml"
)
PROTOCOL_MAPPER_CRD = (
    REPO_ROOT / "config" / "crd" / "keycloak.clouddicted.com_keycloakprotocolmappers.yaml"
)
ROLE_CRD = REPO_ROOT / "config" / "crd" / "keycloak.clouddicted.com_keycloakroles.yaml"
REALM_SAMPLE = REPO_ROOT / "config" / "samples" / "keycloak_v1beta1_keycloakrealm.yaml"
CLIENT_SAMPLE = REPO_ROOT / "config" / "samples" / "keycloak_v1beta1_keycloakclient.yaml"
CLIENT_SCOPE_SAMPLE = (
    REPO_ROOT / "config" / "samples" / "keycloak_v1beta1_keycloakclientscope.yaml"
)
PROTOCOL_MAPPER_SAMPLE = (
    REPO_ROOT / "config" / "samples" / "keycloak_v1beta1_keycloakprotocolmapper.yaml"
)
ROLE_SAMPLE = REPO_ROOT / "config" / "samples" / "keycloak_v1beta1_keycloakrole.yaml"
CONFIDENTIAL_CLIENT_SAMPLE = (
    REPO_ROOT / "config" / "samples" / "keycloak_v1beta1_keycloakclient_confidential.yaml"
)
FIXTURES = REPO_ROOT / "tests" / "fixtures"
CLUSTER_NAME = os.getenv("KIND_CLUSTER_NAME", "clouddicted-keycloak-config-operator-it")
NAMESPACE = "keycloak-operator-test"
OPERATOR_NAMESPACE = "keycloak-config-operator-system"
OPERATOR_DEPLOYMENT = "keycloak-config-operator"
OPERATOR_IMAGE = os.getenv(
    "KIND_OPERATOR_IMAGE",
    "clouddicted-keycloak-config-operator:e2e",
)
TARGET_NAME = "example-keycloak"
KEYCLOAK_USERNAME = "fixture-admin"
KEYCLOAK_PASSWORD = "fixture-password"
PUBLIC_CLIENT_ID = "example-web"
CONFIDENTIAL_CLIENT_ID = "example-service"
CONFIDENTIAL_CLIENT_SECRET = "not-a-production-secret"
CLIENT_SCOPE_NAME = "example-profile"
PROTOCOL_MAPPER_NAME = "email"
ROLE_NAME = "example-admin"
READY_TIMEOUT = "180s"
KEYCLOAK_TIMEOUT_SECONDS = 240
RECONCILE_TIMEOUT_SECONDS = 180


def test_install_manifests_server_side_dry_run(kind_cluster_env: dict[str, str]) -> None:
    _run(
        ["kubectl", "apply", "-f", str(INSTALL_KUSTOMIZATION / "namespace.yaml")],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "apply",
            "--server-side",
            "--dry-run=server",
            "-k",
            str(INSTALL_KUSTOMIZATION),
        ],
        env=kind_cluster_env,
    )


def test_keycloak_target_fixture_server_side_dry_run(kind_cluster_env: dict[str, str]) -> None:
    _run(["kubectl", "apply", "--server-side", "-f", str(CRD)], env=kind_cluster_env)
    _run(["kubectl", "apply", "--server-side", "-f", str(REALM_CRD)], env=kind_cluster_env)
    _run(["kubectl", "apply", "--server-side", "-f", str(CLIENT_CRD)], env=kind_cluster_env)
    _run(["kubectl", "apply", "--server-side", "-f", str(ROLE_CRD)], env=kind_cluster_env)
    _run(
        ["kubectl", "apply", "--server-side", "-f", str(CLIENT_SCOPE_CRD)],
        env=kind_cluster_env,
    )
    _run(
        ["kubectl", "apply", "--server-side", "-f", str(PROTOCOL_MAPPER_CRD)],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "wait",
            "--for=condition=Established",
            "crd/keycloaktargets.keycloak.clouddicted.com",
            "--timeout=60s",
        ],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "wait",
            "--for=condition=Established",
            "crd/keycloakclientscopes.keycloak.clouddicted.com",
            "--timeout=60s",
        ],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "wait",
            "--for=condition=Established",
            "crd/keycloakprotocolmappers.keycloak.clouddicted.com",
            "--timeout=60s",
        ],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "wait",
            "--for=condition=Established",
            "crd/keycloakrealms.keycloak.clouddicted.com",
            "--timeout=60s",
        ],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "wait",
            "--for=condition=Established",
            "crd/keycloakclients.keycloak.clouddicted.com",
            "--timeout=60s",
        ],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "wait",
            "--for=condition=Established",
            "crd/keycloakroles.keycloak.clouddicted.com",
            "--timeout=60s",
        ],
        env=kind_cluster_env,
    )
    _run(["kubectl", "apply", "-f", str(FIXTURES / "namespace.yaml")], env=kind_cluster_env)
    _run(
        ["kubectl", "apply", "-f", str(FIXTURES / "keycloak-admin-secret.yaml")],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "apply",
            "--server-side",
            "--dry-run=server",
            "-f",
            str(FIXTURES / "keycloak.yaml"),
        ],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "apply",
            "--server-side",
            "--dry-run=server",
            "-f",
            str(CLIENT_SCOPE_SAMPLE),
        ],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "apply",
            "--server-side",
            "--dry-run=server",
            "-f",
            str(PROTOCOL_MAPPER_SAMPLE),
        ],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "apply",
            "--server-side",
            "--dry-run=server",
            "-f",
            str(CONFIDENTIAL_CLIENT_SAMPLE),
        ],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "apply",
            "--server-side",
            "--dry-run=server",
            "-f",
            str(CLIENT_SAMPLE),
        ],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "apply",
            "--server-side",
            "--dry-run=server",
            "-f",
            str(REALM_SAMPLE),
        ],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "apply",
            "--server-side",
            "--dry-run=server",
            "-f",
            str(ROLE_SAMPLE),
        ],
        env=kind_cluster_env,
    )
    _run(["kubectl", "get", "namespace", NAMESPACE], env=kind_cluster_env)
    _run(
        [
            "kubectl",
            "get",
            "secret",
            "keycloak-admin-credentials",
            "--namespace",
            NAMESPACE,
        ],
        env=kind_cluster_env,
    )
    _run(
        [
            "kubectl",
            "apply",
            "--server-side",
            "--dry-run=server",
            "-f",
            str(FIXTURES / "keycloak-target.yaml"),
        ],
        env=kind_cluster_env,
    )


def test_operator_reconciles_keycloak_entities_e2e(kind_cluster_env: dict[str, str]) -> None:
    realm = f"e2e-{int(time.time())}"

    _wait_for_crds(kind_cluster_env)
    _wait_for_deployment(kind_cluster_env, OPERATOR_NAMESPACE, OPERATOR_DEPLOYMENT)
    _assert_operator_uses_loaded_image(kind_cluster_env, OPERATOR_IMAGE)
    _wait_for_deployment(kind_cluster_env, NAMESPACE, "keycloak")

    with _port_forward_keycloak(kind_cluster_env) as keycloak_url:
        _apply_document(kind_cluster_env, _keycloak_target())
        _wait_for_ready(kind_cluster_env, "keycloaktargets", TARGET_NAME)

        _apply_document(kind_cluster_env, _keycloak_realm(realm))
        _wait_for_ready(kind_cluster_env, "keycloakrealms", "example-realm")
        _eventually(lambda: _assert_realm(keycloak_url, realm))

        _apply_document(kind_cluster_env, _keycloak_client_scope(realm))
        _wait_for_ready(kind_cluster_env, "keycloakclientscopes", CLIENT_SCOPE_NAME)
        _eventually(lambda: _assert_client_scope(keycloak_url, realm))

        _apply_document(kind_cluster_env, _keycloak_protocol_mapper(realm))
        _wait_for_ready(
            kind_cluster_env,
            "keycloakprotocolmappers",
            "example-profile-email",
        )
        _eventually(lambda: _assert_protocol_mapper(keycloak_url, realm))

        _apply_document(kind_cluster_env, _keycloak_role(realm))
        _wait_for_ready(kind_cluster_env, "keycloakroles", ROLE_NAME)
        _eventually(lambda: _assert_role(keycloak_url, realm))

        _apply_document(kind_cluster_env, _keycloak_public_client(realm))
        _wait_for_ready(kind_cluster_env, "keycloakclients", PUBLIC_CLIENT_ID)
        _eventually(lambda: _assert_public_client(keycloak_url, realm))

        _apply_document(kind_cluster_env, _confidential_client_secret())
        _apply_document(kind_cluster_env, _keycloak_confidential_client(realm))
        _wait_for_ready(kind_cluster_env, "keycloakclients", CONFIDENTIAL_CLIENT_ID)
        _eventually(lambda: _assert_confidential_client(keycloak_url, realm))


@pytest.fixture(scope="session")
def kind_cluster_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, str]]:
    _require_tool("kind")
    _require_tool("kubectl")

    if CLUSTER_NAME not in _kind_clusters(os.environ.copy()):
        pytest.fail(
            f"kind cluster {CLUSTER_NAME!r} was not found; "
            "run `.venv/bin/python tests/kind/e2e.py prepare` first."
        )

    kubeconfig = tmp_path_factory.mktemp("kind-kubeconfig") / "config"
    env = {**os.environ, "KUBECONFIG": str(kubeconfig)}
    _run(
        [
            "kind",
            "export",
            "kubeconfig",
            "--name",
            CLUSTER_NAME,
            "--kubeconfig",
            str(kubeconfig),
        ],
        env=env,
    )

    yield env


def _apply_crds(env: dict[str, str]) -> None:
    for crd in (CRD, REALM_CRD, CLIENT_CRD, ROLE_CRD, CLIENT_SCOPE_CRD, PROTOCOL_MAPPER_CRD):
        _run(["kubectl", "apply", "--server-side", "-f", str(crd)], env=env)

    _wait_for_crds(env)


def _wait_for_crds(env: dict[str, str]) -> None:
    for crd_name in (
        "keycloaktargets",
        "keycloakrealms",
        "keycloakclients",
        "keycloakroles",
        "keycloakclientscopes",
        "keycloakprotocolmappers",
    ):
        _run(
            [
                "kubectl",
                "wait",
                "--for=condition=Established",
                f"crd/{crd_name}.keycloak.clouddicted.com",
                f"--timeout={READY_TIMEOUT}",
            ],
            env=env,
        )


def _build_operator_image(image: str) -> None:
    _run(["docker", "build", "-t", image, "."], env=os.environ.copy())


def _load_operator_image(env: dict[str, str], image: str) -> None:
    _run(["kind", "load", "docker-image", image, "--name", CLUSTER_NAME], env=env)


def _apply_operator_install(env: dict[str, str], image: str) -> None:
    rendered = _run(["kubectl", "kustomize", str(INSTALL_KUSTOMIZATION)], env=env).stdout
    documents = [
        document
        for document in yaml.safe_load_all(rendered)
        if isinstance(document, dict)
    ]

    deployment = _document_by_kind(documents, "Deployment", OPERATOR_DEPLOYMENT)
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    container["image"] = image
    container["imagePullPolicy"] = "Never"

    _run_with_input(
        ["kubectl", "apply", "-f", "-"],
        env=env,
        input_text=yaml.safe_dump_all(documents, sort_keys=False),
    )


def _wait_for_deployment(env: dict[str, str], namespace: str, name: str) -> None:
    _run(
        [
            "kubectl",
            "rollout",
            "status",
            f"deployment/{name}",
            "--namespace",
            namespace,
            f"--timeout={READY_TIMEOUT}",
        ],
        env=env,
    )


def _assert_operator_uses_loaded_image(env: dict[str, str], image: str) -> None:
    result = _run(
        [
            "kubectl",
            "get",
            "deployment",
            OPERATOR_DEPLOYMENT,
            "--namespace",
            OPERATOR_NAMESPACE,
            "--output=json",
        ],
        env=env,
    )
    deployment = json.loads(result.stdout)
    [container] = deployment["spec"]["template"]["spec"]["containers"]

    assert container["image"] == image
    assert container["imagePullPolicy"] == "Never"


def _document_by_kind(
    documents: list[dict[str, Any]],
    kind: str,
    name: str,
) -> dict[str, Any]:
    for document in documents:
        metadata = document.get("metadata")
        if (
            document.get("kind") == kind
            and isinstance(metadata, dict)
            and metadata.get("name") == name
        ):
            return document

    raise AssertionError(f"{kind}/{name} was not rendered")


@contextlib.contextmanager
def _port_forward_keycloak(env: dict[str, str]) -> Iterator[str]:
    port = _free_port()
    process = subprocess.Popen(
        [
            "kubectl",
            "port-forward",
            "--namespace",
            NAMESPACE,
            "service/keycloak",
            f"{port}:8080",
            "--address",
            "127.0.0.1",
        ],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    try:
        _wait_for_port_forward(process, port)
        keycloak_url = f"http://127.0.0.1:{port}"
        _wait_for_keycloak(keycloak_url, process)
        yield keycloak_url
    finally:
        _terminate_process(process)


def _wait_for_port_forward(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"kubectl port-forward exited:\n{_process_output(process)}")

        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)

    raise AssertionError("timed out waiting for kubectl port-forward to listen")


def _wait_for_keycloak(base_url: str, process: subprocess.Popen[str]) -> None:
    _eventually(
        lambda: _admin_token_with_port_forward_check(base_url, process),
        timeout_seconds=KEYCLOAK_TIMEOUT_SECONDS,
    )


def _admin_token_with_port_forward_check(
    base_url: str,
    process: subprocess.Popen[str],
) -> str:
    if process.poll() is not None:
        raise AssertionError(f"kubectl port-forward exited:\n{_process_output(process)}")

    return _admin_token(base_url)


def _wait_for_ready(env: dict[str, str], plural: str, name: str) -> None:
    _run(
        [
            "kubectl",
            "wait",
            "--namespace",
            NAMESPACE,
            "--for=condition=Ready",
            f"{plural}.keycloak.clouddicted.com/{name}",
            f"--timeout={READY_TIMEOUT}",
        ],
        env=env,
    )


def _apply_document(env: dict[str, str], document: dict[str, Any]) -> None:
    _run_with_input(
        ["kubectl", "apply", "-f", "-"],
        env=env,
        input_text=json.dumps(document),
    )


def _keycloak_target() -> dict[str, Any]:
    return {
        "apiVersion": "keycloak.clouddicted.com/v1beta1",
        "kind": "KeycloakTarget",
        "metadata": {"name": TARGET_NAME, "namespace": NAMESPACE},
        "spec": {
            "url": f"http://keycloak.{NAMESPACE}.svc.cluster.local:8080",
            "adminCredentials": {
                "secretRef": {
                    "name": "keycloak-admin-credentials",
                    "usernameKey": "username",
                    "passwordKey": "password",
                },
            },
        },
    }


def _keycloak_realm(realm: str) -> dict[str, Any]:
    return {
        "apiVersion": "keycloak.clouddicted.com/v1beta1",
        "kind": "KeycloakRealm",
        "metadata": {"name": "example-realm", "namespace": NAMESPACE},
        "spec": {
            "targetRef": {"name": TARGET_NAME},
            "realm": realm,
            "displayName": "Example",
        },
    }


def _keycloak_client_scope(realm: str) -> dict[str, Any]:
    return {
        "apiVersion": "keycloak.clouddicted.com/v1beta1",
        "kind": "KeycloakClientScope",
        "metadata": {"name": CLIENT_SCOPE_NAME, "namespace": NAMESPACE},
        "spec": {
            "targetRef": {"name": TARGET_NAME},
            "realm": realm,
            "name": CLIENT_SCOPE_NAME,
            "description": "Example profile client scope",
        },
    }


def _keycloak_protocol_mapper(realm: str) -> dict[str, Any]:
    return {
        "apiVersion": "keycloak.clouddicted.com/v1beta1",
        "kind": "KeycloakProtocolMapper",
        "metadata": {"name": "example-profile-email", "namespace": NAMESPACE},
        "spec": {
            "targetRef": {"name": TARGET_NAME},
            "realm": realm,
            "name": PROTOCOL_MAPPER_NAME,
            "mapperType": "oidc-usermodel-property-mapper",
            "parent": {
                "type": "ClientScope",
                "clientScopeRef": {"name": CLIENT_SCOPE_NAME},
            },
            "config": {
                "user.attribute": "email",
                "claim.name": "email",
                "jsonType.label": "String",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
    }


def _keycloak_role(realm: str) -> dict[str, Any]:
    return {
        "apiVersion": "keycloak.clouddicted.com/v1beta1",
        "kind": "KeycloakRole",
        "metadata": {"name": ROLE_NAME, "namespace": NAMESPACE},
        "spec": {
            "targetRef": {"name": TARGET_NAME},
            "realm": realm,
            "name": ROLE_NAME,
            "description": "Example administrator role",
        },
    }


def _keycloak_public_client(realm: str) -> dict[str, Any]:
    return {
        "apiVersion": "keycloak.clouddicted.com/v1beta1",
        "kind": "KeycloakClient",
        "metadata": {"name": PUBLIC_CLIENT_ID, "namespace": NAMESPACE},
        "spec": {
            "targetRef": {"name": TARGET_NAME},
            "realm": realm,
            "clientId": PUBLIC_CLIENT_ID,
            "clientType": "Public",
            "displayName": "Example Web",
            "redirectUris": ["https://app.example.com/*"],
            "webOrigins": ["https://app.example.com"],
        },
    }


def _confidential_client_secret() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "example-service-client-secret", "namespace": NAMESPACE},
        "type": "Opaque",
        "stringData": {"clientSecret": CONFIDENTIAL_CLIENT_SECRET},
    }


def _keycloak_confidential_client(realm: str) -> dict[str, Any]:
    return {
        "apiVersion": "keycloak.clouddicted.com/v1beta1",
        "kind": "KeycloakClient",
        "metadata": {"name": CONFIDENTIAL_CLIENT_ID, "namespace": NAMESPACE},
        "spec": {
            "targetRef": {"name": TARGET_NAME},
            "realm": realm,
            "clientId": CONFIDENTIAL_CLIENT_ID,
            "clientType": "Confidential",
            "secretRef": {
                "name": "example-service-client-secret",
                "secretKey": "clientSecret",
            },
        },
    }


def _assert_realm(base_url: str, realm: str) -> None:
    realm_payload = _admin_get(base_url, f"realms/{realm}")
    assert realm_payload["realm"] == realm
    assert realm_payload["displayName"] == "Example"


def _assert_client_scope(base_url: str, realm: str) -> dict[str, Any]:
    client_scope = _client_scope(base_url, realm, CLIENT_SCOPE_NAME)
    assert client_scope["name"] == CLIENT_SCOPE_NAME
    assert client_scope["protocol"] == "openid-connect"
    assert client_scope["description"] == "Example profile client scope"
    return client_scope


def _assert_protocol_mapper(base_url: str, realm: str) -> None:
    client_scope = _assert_client_scope(base_url, realm)
    mappers = _admin_get(
        base_url,
        f"realms/{realm}/client-scopes/{client_scope['id']}/protocol-mappers/models",
    )
    mapper = _one_by_field(mappers, "name", PROTOCOL_MAPPER_NAME)

    assert mapper["protocol"] == "openid-connect"
    assert mapper["protocolMapper"] == "oidc-usermodel-property-mapper"
    assert mapper["config"]["user.attribute"] == "email"
    assert mapper["config"]["claim.name"] == "email"
    assert mapper["config"]["jsonType.label"] == "String"
    assert mapper["config"]["id.token.claim"] == "true"
    assert mapper["config"]["access.token.claim"] == "true"
    assert mapper["config"]["userinfo.token.claim"] == "true"


def _assert_role(base_url: str, realm: str) -> None:
    role = _admin_get(base_url, f"realms/{realm}/roles/{ROLE_NAME}")
    assert role["name"] == ROLE_NAME
    assert role["description"] == "Example administrator role"


def _assert_public_client(base_url: str, realm: str) -> None:
    client = _client(base_url, realm, PUBLIC_CLIENT_ID)
    assert client["clientId"] == PUBLIC_CLIENT_ID
    assert client["name"] == "Example Web"
    assert client["protocol"] == "openid-connect"
    assert client["publicClient"] is True
    assert client["redirectUris"] == ["https://app.example.com/*"]
    assert client["webOrigins"] == ["https://app.example.com"]


def _assert_confidential_client(base_url: str, realm: str) -> None:
    client = _client(base_url, realm, CONFIDENTIAL_CLIENT_ID)
    assert client["clientId"] == CONFIDENTIAL_CLIENT_ID
    assert client["protocol"] == "openid-connect"
    assert client["publicClient"] is False

    secret = _admin_get(base_url, f"realms/{realm}/clients/{client['id']}/client-secret")
    assert secret["value"] == CONFIDENTIAL_CLIENT_SECRET


def _client(base_url: str, realm: str, client_id: str) -> dict[str, Any]:
    clients = _admin_get(base_url, f"realms/{realm}/clients", params={"clientId": client_id})
    return _one_by_field(clients, "clientId", client_id)


def _client_scope(base_url: str, realm: str, name: str) -> dict[str, Any]:
    client_scopes = _admin_get(base_url, f"realms/{realm}/client-scopes")
    return _one_by_field(client_scopes, "name", name)


def _admin_get(base_url: str, path: str, params: dict[str, str] | None = None) -> Any:
    with httpx.Client(timeout=10.0, trust_env=False) as client:
        response = client.get(
            f"{base_url}/admin/{path.lstrip('/')}",
            headers={"Authorization": f"Bearer {_admin_token(base_url)}"},
            params=params,
        )
        response.raise_for_status()
        return response.json()


def _admin_token(base_url: str) -> str:
    with httpx.Client(timeout=10.0, trust_env=False) as client:
        response = client.post(
            f"{base_url}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": KEYCLOAK_USERNAME,
                "password": KEYCLOAK_PASSWORD,
            },
        )
        response.raise_for_status()
        token = response.json().get("access_token")
        assert isinstance(token, str) and token
        return token


def _one_by_field(items: Any, field: str, value: str) -> dict[str, Any]:
    assert isinstance(items, list)
    matches = [
        item
        for item in items
        if isinstance(item, dict) and item.get(field) == value
    ]
    assert len(matches) == 1
    return matches[0]


def _eventually(
    assertion: Any,
    *,
    timeout_seconds: int = RECONCILE_TIMEOUT_SECONDS,
    interval_seconds: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_seconds
    last_error: BaseException | None = None

    while time.monotonic() < deadline:
        try:
            return assertion()
        except (AssertionError, KeyError, httpx.HTTPError) as exc:
            last_error = exc
            time.sleep(interval_seconds)

    raise AssertionError("timed out waiting for expected e2e state") from last_error


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return

    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def _process_output(process: subprocess.Popen[str]) -> str:
    if process.stdout is None:
        return ""

    return process.stdout.read()


def _kind_clusters(env: dict[str, str]) -> set[str]:
    result = _run(["kind", "get", "clusters"], env=env)
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _require_tool(name: str) -> None:
    if shutil.which(name) is None:
        pytest.skip(f"{name} is required for kind integration tests")


def _run(args: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=True,
        env=env,
        text=True,
        capture_output=True,
    )


def _run_with_input(
    args: list[str],
    *,
    env: dict[str, str],
    input_text: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        input=input_text,
        check=True,
        env=env,
        text=True,
        capture_output=True,
    )
