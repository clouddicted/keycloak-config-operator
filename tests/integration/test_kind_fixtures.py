import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("RUN_KIND_INTEGRATION") != "1",
        reason="set RUN_KIND_INTEGRATION=1 to run kind integration tests",
    ),
]

REPO_ROOT = Path(__file__).resolve().parents[2]
KIND_CONFIG = REPO_ROOT / "tests" / "kind" / "kind.yaml"
CRD = REPO_ROOT / "config" / "crd" / "keycloak.clouddicted.com_keycloaktargets.yaml"
REALM_CRD = REPO_ROOT / "config" / "crd" / "keycloak.clouddicted.com_keycloakrealms.yaml"
CLIENT_CRD = REPO_ROOT / "config" / "crd" / "keycloak.clouddicted.com_keycloakclients.yaml"
REALM_SAMPLE = REPO_ROOT / "config" / "samples" / "keycloak_v1alpha1_keycloakrealm.yaml"
CLIENT_SAMPLE = REPO_ROOT / "config" / "samples" / "keycloak_v1alpha1_keycloakclient.yaml"
CONFIDENTIAL_CLIENT_SAMPLE = (
    REPO_ROOT / "config" / "samples" / "keycloak_v1alpha1_keycloakclient_confidential.yaml"
)
FIXTURES = REPO_ROOT / "tests" / "fixtures"
CLUSTER_NAME = os.getenv("KIND_CLUSTER_NAME", "clouddicted-keycloak-config-operator-it")
NAMESPACE = "keycloak-operator-test"


def test_keycloak_target_fixture_server_side_dry_run(kind_cluster_env: dict[str, str]) -> None:
    _run(["kubectl", "apply", "--server-side", "-f", str(CRD)], env=kind_cluster_env)
    _run(["kubectl", "apply", "--server-side", "-f", str(REALM_CRD)], env=kind_cluster_env)
    _run(["kubectl", "apply", "--server-side", "-f", str(CLIENT_CRD)], env=kind_cluster_env)
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


@pytest.fixture(scope="session")
def kind_cluster_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, str]]:
    _require_tool("kind")
    _require_tool("kubectl")

    kubeconfig = tmp_path_factory.mktemp("kind-kubeconfig") / "config"
    env = {**os.environ, "KUBECONFIG": str(kubeconfig)}
    cluster_exists = CLUSTER_NAME in _kind_clusters(env)

    if cluster_exists:
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
    else:
        _run(
            [
                "kind",
                "create",
                "cluster",
                "--name",
                CLUSTER_NAME,
                "--config",
                str(KIND_CONFIG),
                "--kubeconfig",
                str(kubeconfig),
            ],
            env=env,
        )

    try:
        yield env
    finally:
        if not cluster_exists:
            _run(["kind", "delete", "cluster", "--name", CLUSTER_NAME], env=env)


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
