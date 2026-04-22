from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
CONTRIBUTING = REPO_ROOT / "CONTRIBUTING.md"


def test_ci_workflow_tracks_gitflow_branches_and_tags() -> None:
    workflow = _load_workflow()

    events = workflow["on"]
    assert events["pull_request"]["branches"] == ["develop", "main"]
    assert events["push"]["branches"] == ["develop", "main"]
    assert events["push"]["tags"] == ["v*.*.*"]
    assert "workflow_dispatch" in events


def test_ci_workflow_runs_required_quality_gates() -> None:
    workflow = _load_workflow()
    jobs = workflow["jobs"]

    assert workflow["env"]["IMAGE_NAME"] == "ghcr.io/clouddicted/keycloak-config-operator"
    assert {"python", "helm", "image", "kind", "keycloak-compatibility", "release"} <= set(
        jobs,
    )
    assert workflow["env"]["KEYCLOAK_VERSION"] == "26.6.2"
    assert workflow["env"]["KEYCLOAK_COMPATIBILITY_VERSION"] == "26.5.3"
    assert "ruff check ." in _job_run_commands(jobs["python"])
    assert "pytest" in _job_run_commands(jobs["python"])
    assert "python -m build" in _job_run_commands(jobs["python"])
    assert 'helm lint "$CHART_PATH"' in _job_run_commands(jobs["helm"])
    assert "helm template keycloak-config-operator" in _job_run_commands(jobs["helm"])
    assert "python tests/kind/e2e.py prepare" in _job_run_commands(jobs["kind"])
    assert "python tests/kind/e2e.py test" in _job_run_commands(jobs["kind"])
    assert "kind delete cluster" in _job_run_commands(jobs["kind"])
    assert "if" not in jobs["kind"]
    assert jobs["kind"]["needs"] == ["python", "helm", "image"]
    assert jobs["keycloak-compatibility"]["if"] == (
        "github.event_name == 'workflow_dispatch' || "
        "(github.event_name == 'push' && github.ref_type == 'tag')"
    )
    assert jobs["keycloak-compatibility"]["strategy"]["matrix"]["keycloak-version"] == [
        workflow["env"]["KEYCLOAK_COMPATIBILITY_VERSION"],
    ]
    assert _step_env(
        jobs["keycloak-compatibility"],
        "Prepare kind cluster",
    )["KEYCLOAK_VERSION"] == "${{ matrix.keycloak-version }}"
    assert _step_env(
        jobs["keycloak-compatibility"],
        "Run kind tests",
    )["KEYCLOAK_VERSION"] == "${{ matrix.keycloak-version }}"


def test_release_job_publishes_image_and_chart_only_for_tags() -> None:
    release = _load_workflow()["jobs"]["release"]
    commands = _job_run_commands(release)
    uses = _job_uses(release)

    assert release["if"] == "github.event_name == 'push' && github.ref_type == 'tag'"
    assert release["needs"] == ["python", "helm", "image", "kind", "keycloak-compatibility"]
    assert release["permissions"] == {"contents": "write", "packages": "write"}
    assert "docker/login-action@v3" in uses
    assert "docker/build-push-action@v6" in uses
    assert "helm package" in commands
    assert "gh release create" in commands


def test_contributing_documents_minimal_gitflow_and_local_file_rules() -> None:
    text = CONTRIBUTING.read_text()

    assert "`develop` is the integration branch" in text
    assert "`main` is the stable release branch" in text
    assert "`feature/<short-name>`" in text
    assert "`hotfix/<short-name>`" in text
    assert "`chore/<short-name>`" in text
    assert "Wait for the CI workflow on `main` to pass" in text
    assert "including the `kind e2e tests` job" in text
    assert "Protect `develop` and `main` in GitHub" in text
    assert "Never commit `internal/` or `.codex`" in text
    assert "Do not add them to `.gitignore`" in text


def _load_workflow() -> dict[str, Any]:
    with WORKFLOW.open() as stream:
        workflow = yaml.safe_load(stream)

    assert isinstance(workflow, dict)
    return workflow


def _job_run_commands(job: dict[str, Any]) -> str:
    return "\n".join(
        step["run"]
        for step in job["steps"]
        if isinstance(step, dict) and isinstance(step.get("run"), str)
    )


def _job_uses(job: dict[str, Any]) -> set[str]:
    return {
        step["uses"]
        for step in job["steps"]
        if isinstance(step, dict) and isinstance(step.get("uses"), str)
    }


def _step_env(job: dict[str, Any], name: str) -> dict[str, str]:
    for step in job["steps"]:
        if isinstance(step, dict) and step.get("name") == name:
            env = step.get("env")
            assert isinstance(env, dict)
            return env

    raise AssertionError(f"step {name!r} was not found")
