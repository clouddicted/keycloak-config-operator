import importlib.util
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
