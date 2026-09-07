import importlib.util
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
KIND_E2E_SCRIPT = REPO_ROOT / "tests" / "kind" / "e2e.py"
spec = importlib.util.spec_from_file_location("kind_e2e_script", KIND_E2E_SCRIPT)
assert spec is not None
assert spec.loader is not None
kind_e2e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kind_e2e)


def test_run_step_logs_label_and_command(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(
        args: list[str],
        *,
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        calls.append((args, env))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(kind_e2e.e2e, "_run", fake_run)

    result = kind_e2e._run_step("apply manifests", ["kubectl", "apply", "-f", "-"], env={})

    assert result.returncode == 0
    assert calls == [(["kubectl", "apply", "-f", "-"], {})]
    assert capsys.readouterr().out == (
        "[kind-e2e] apply manifests\n"
        "+ kubectl apply -f -\n"
    )


def test_run_tests_defaults_to_visible_pytest_output(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, str]]] = []

    monkeypatch.setattr(kind_e2e, "_require_tools", lambda names: None)
    monkeypatch.setattr(kind_e2e, "_require_cluster", lambda: None)

    def fake_subprocess_run(
        args: Sequence[str],
        *,
        env: dict[str, str],
        **_: Any,
    ) -> subprocess.CompletedProcess[str]:
        command = list(args)
        calls.append((command, env))
        return subprocess.CompletedProcess(args=command, returncode=0)

    monkeypatch.setattr(kind_e2e.subprocess, "run", fake_subprocess_run)

    with pytest.raises(SystemExit) as exc_info:
        kind_e2e.run_tests(())

    assert exc_info.value.code == 0
    [command, env] = calls[0]
    assert command[-3:] == ["tests/integration/test_kind_fixtures.py", "-vv", "-s"]
    assert env["RUN_KIND_INTEGRATION"] == "1"
    assert "[kind-e2e] running kind e2e tests" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("previous_version", "handled_version", "passes"),
    [("old", "783", True), ("783", "783", False), ("old", "old", False)],
)
def test_dependency_check_requires_new_consumed_trigger(
    monkeypatch: pytest.MonkeyPatch,
    previous_version: str,
    handled_version: str,
    passes: bool,
) -> None:
    e2e = kind_e2e.e2e
    source = f"core/secrets/{e2e.NAMESPACE}/example-oidc-secret"
    resource = {
        "metadata": {
            "resourceVersion": "785",
            "annotations": {
                e2e.DEPENDENCY_TRIGGER_ANNOTATION: f"{source}@783",
                e2e.LAST_HANDLED_ANNOTATION: json.dumps({
                    "metadata": {"annotations": {
                        e2e.DEPENDENCY_TRIGGER_ANNOTATION: f"{source}@{handled_version}",
                    }},
                }),
            },
        },
    }

    def fake_run(args: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        # No lookup of the source's current version: it can advance after fan-out.
        assert args[1:4] == ["get", "keycloakidentityproviders", "example-oidc"]
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(resource))

    monkeypatch.setattr(e2e, "_run", fake_run)

    def check() -> None:
        e2e._assert_dependency_trigger(
            {}, "keycloakidentityproviders", "example-oidc",
            source_group="core", source_plural="secrets", source_name="example-oidc-secret",
            previous_trigger=f"{source}@{previous_version}",
        )

    if passes:
        check()
    else:
        with pytest.raises(AssertionError):
            check()


def test_dependency_trigger_retries_after_consumed_update_without_fanout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    e2e = kind_e2e.e2e
    annotations: list[tuple[str, str, str, str]] = []
    handled: list[str] = []
    trigger_checks = 0

    monkeypatch.setattr(e2e, "_dependency_trigger", lambda *args: None)
    monkeypatch.setattr(
        e2e,
        "_annotate_resource",
        lambda env, plural, name, annotation, value: annotations.append(
            (plural, name, annotation, value)
        ),
    )
    monkeypatch.setattr(
        e2e,
        "_assert_annotation_handled",
        lambda env, plural, name, annotation, value: handled.append(value),
    )

    def assert_trigger(*args: Any, **kwargs: Any) -> None:
        nonlocal trigger_checks
        trigger_checks += 1
        if trigger_checks == 1:
            raise AssertionError("first source update was coalesced")

    monkeypatch.setattr(e2e, "_assert_dependency_trigger", assert_trigger)
    monkeypatch.setattr(e2e, "_eventually", lambda assertion, **kwargs: assertion())

    e2e._trigger_dependency_and_wait(
        {},
        source_plural="keycloakclients",
        source_name="example-web",
        dependent_plural="keycloakclientroles",
        dependent_name="example-web-reader",
        marker="e2e-realm",
    )

    assert [entry[-1] for entry in annotations] == ["e2e-realm-0", "e2e-realm-1"]
    assert handled == ["e2e-realm-0", "e2e-realm-1"]
    assert trigger_checks == 2


def test_deployment_wait_uses_separate_startup_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    e2e = kind_e2e.e2e
    calls = []
    monkeypatch.setattr(e2e, "_run", lambda args, **kwargs: calls.append(args))
    monkeypatch.setattr(e2e, "READY_TIMEOUT", "1s")
    monkeypatch.setattr(e2e, "DEPLOYMENT_TIMEOUT", "240s")
    e2e._wait_for_deployment({}, "test", "keycloak")
    assert calls[0][-1] == "--timeout=240s"


def test_operator_pod_lookup_ignores_terminating_and_unready_pods(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    e2e = kind_e2e.e2e
    response = {
        "items": [
            {
                "metadata": {"name": "old", "deletionTimestamp": "2026-09-07T10:00:00Z"},
                "status": {
                    "phase": "Running",
                    "conditions": [{"type": "Ready", "status": "True"}],
                },
            },
            {
                "metadata": {"name": "starting"},
                "status": {
                    "phase": "Running",
                    "conditions": [{"type": "Ready", "status": "False"}],
                },
            },
            {
                "metadata": {"name": "current"},
                "status": {
                    "phase": "Running",
                    "conditions": [{"type": "Ready", "status": "True"}],
                },
            },
        ]
    }
    calls = []

    def fake_run(args: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(response))

    monkeypatch.setattr(e2e, "_run", fake_run)
    assert e2e._operator_pod_name({}) == "current"
    assert calls[0][1:4] == ["get", "pods", "--namespace"]
    assert "app.kubernetes.io/name=keycloak-config-operator" in calls[0]


def test_restart_reconciliation_allows_one_masked_provider_reapply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    e2e = kind_e2e.e2e
    provider_path = "/admin/realms/e2e-example/identity-provider/instances/example-oidc"
    counts = e2e.Counter({
        ("GET", provider_path): 3,
        ("PUT", provider_path): 1,
    })
    monkeypatch.setattr(e2e, "_operator_pod_name", lambda env: "operator-current")
    monkeypatch.setattr(
        e2e,
        "_operator_admin_request_counts",
        lambda env, realm, *, operator_pod: counts,
    )
    assert e2e._assert_reconciliation_resumed({}, "e2e-example", provider_path) == (
        "operator-current"
    )


@pytest.mark.parametrize(
    "unexpected", ["", "PUT", "POST", "PATCH", "DELETE", "no-timer", "log-reset"],
)
def test_steady_reconciliation_log_check_detects_writes_and_missing_timers(unexpected: str) -> None:
    e2e = kind_e2e.e2e
    realm = "e2e-example"
    path = f"/admin/realms/{realm}/groups/group-id"

    def line(method: str, request_path: str) -> str:
        return f'HTTP Request: {method} http://keycloak:8080{request_path} "HTTP/1.1 200 OK"\n'

    baseline = line("PUT", path)
    logs = baseline
    if unexpected != "no-timer":
        logs += 3 * line("GET", path)
    # Authentication traffic and unrelated realms do not count as configuration writes.
    logs += line("POST", "/realms/master/protocol/openid-connect/token")
    logs += line("PUT", f"/admin/realms/{realm}-other")
    if unexpected in {"PUT", "POST", "PATCH", "DELETE"}:
        logs += line(unexpected, path)
    if unexpected == "log-reset":
        logs = logs.removeprefix(baseline)
    before = e2e._admin_request_counts(baseline, realm)
    after = e2e._admin_request_counts(logs, realm)
    if unexpected:
        with pytest.raises(AssertionError):
            e2e._assert_stable_request_counts(before, after, [path])
    else:
        e2e._assert_stable_request_counts(before, after, [path])
