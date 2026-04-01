"""Manage the local kind environment used by the e2e tests."""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tests.integration import test_kind_fixtures as e2e  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("prepare", help="build/load the operator image and deploy fixtures")
    subparsers.add_parser("cleanup", help="delete the prepared kind cluster")

    test_parser = subparsers.add_parser("test", help="run the kind integration/e2e tests")
    test_parser.add_argument(
        "pytest_args",
        nargs=argparse.REMAINDER,
        help="optional pytest arguments; defaults to the kind integration test path",
    )

    args = parser.parse_args()
    if args.command == "prepare":
        prepare()
    elif args.command == "test":
        run_tests(args.pytest_args)
    elif args.command == "cleanup":
        cleanup()


def prepare() -> None:
    _require_tools(("docker", "kind", "kubectl"))

    if e2e.CLUSTER_NAME not in _kind_clusters():
        e2e._run(
            [
                "kind",
                "create",
                "cluster",
                "--name",
                e2e.CLUSTER_NAME,
                "--config",
                str(e2e.KIND_CONFIG),
            ],
            env=os.environ.copy(),
        )
    else:
        e2e._run(
            ["kind", "export", "kubeconfig", "--name", e2e.CLUSTER_NAME],
            env=os.environ.copy(),
        )

    with _cluster_env() as env:
        e2e._build_operator_image(e2e.OPERATOR_IMAGE)
        e2e._load_operator_image(env, e2e.OPERATOR_IMAGE)
        e2e._apply_operator_install(env, e2e.OPERATOR_IMAGE)
        e2e._wait_for_crds(env)
        e2e._wait_for_deployment(env, e2e.OPERATOR_NAMESPACE, e2e.OPERATOR_DEPLOYMENT)

        e2e._run(["kubectl", "apply", "-f", str(e2e.FIXTURES / "namespace.yaml")], env=env)
        e2e._run(
            ["kubectl", "apply", "-f", str(e2e.FIXTURES / "keycloak-admin-secret.yaml")],
            env=env,
        )
        e2e._run(["kubectl", "apply", "-f", str(e2e.FIXTURES / "keycloak.yaml")], env=env)
        e2e._wait_for_deployment(env, e2e.NAMESPACE, "keycloak")

    print(f"Prepared kind cluster {e2e.CLUSTER_NAME!r} with image {e2e.OPERATOR_IMAGE!r}.")
    print(f"Inspect it with: kubectl --context kind-{e2e.CLUSTER_NAME} get pods -A")


def run_tests(pytest_args: Sequence[str]) -> None:
    _require_tools(("kind", "kubectl"))
    _require_cluster()

    args = list(pytest_args) or ["tests/integration/test_kind_fixtures.py", "-q"]
    env = {
        **os.environ,
        "RUN_KIND_INTEGRATION": "1",
        "KIND_CLUSTER_NAME": e2e.CLUSTER_NAME,
        "KIND_OPERATOR_IMAGE": e2e.OPERATOR_IMAGE,
    }
    raise SystemExit(subprocess.run([sys.executable, "-m", "pytest", *args], env=env).returncode)


def cleanup() -> None:
    _require_tools(("kind",))
    _require_cluster()
    e2e._run(["kind", "delete", "cluster", "--name", e2e.CLUSTER_NAME], env=os.environ.copy())


@contextlib.contextmanager
def _cluster_env() -> Iterator[dict[str, str]]:
    with tempfile.TemporaryDirectory() as directory:
        kubeconfig = Path(directory) / "kubeconfig"
        env = {**os.environ, "KUBECONFIG": str(kubeconfig)}
        e2e._run(
            [
                "kind",
                "export",
                "kubeconfig",
                "--name",
                e2e.CLUSTER_NAME,
                "--kubeconfig",
                str(kubeconfig),
            ],
            env=env,
        )
        yield env


def _require_cluster() -> None:
    if e2e.CLUSTER_NAME not in _kind_clusters():
        raise SystemExit(
            f"kind cluster {e2e.CLUSTER_NAME!r} was not found; run `prepare` first."
        )


def _kind_clusters() -> set[str]:
    return e2e._kind_clusters(os.environ.copy())


def _require_tools(names: Sequence[str]) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        tools = ", ".join(missing)
        raise SystemExit(f"missing required tool(s): {tools}")


if __name__ == "__main__":
    main()
