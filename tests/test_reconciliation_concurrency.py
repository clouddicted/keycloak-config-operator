"""Reproduce timer/event races using the registered handlers and shared Kopf memo."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError
from threading import Event
from typing import Any

import kopf
import pytest

from clouddicted_keycloak_config_operator.handlers import keycloak_client_role


def _timer() -> Any:
    return next(
        handler.fn
        for handler in kopf.get_default_registry()._spawning.get_all_handlers()
        if handler.id == "reconcile_keycloak_client_role"
    )


@pytest.mark.parametrize("timer_first", [False, True])
def test_timer_and_event_do_not_reconcile_same_role_concurrently(
    monkeypatch: pytest.MonkeyPatch,
    timer_first: bool,
) -> None:
    active = Event()
    release = Event()
    overlap = Event()

    def reconcile(**_: Any) -> None:
        if active.is_set():
            overlap.set()
            return
        active.set()
        assert release.wait(5)
        active.clear()

    monkeypatch.setattr(keycloak_client_role, "patch_keycloak_client_role_status", reconcile)
    event = keycloak_client_role.reconcile_keycloak_client_role
    first, second = (_timer(), event) if timer_first else (event, _timer())
    kwargs = {"body": {"metadata": {}}, "spec": {}, "status": {}, "memo": kopf.Memo()}

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_call = executor.submit(first, **kwargs, patch={})
        try:
            assert active.wait(2)
            second_call = executor.submit(second, **kwargs, patch={})
            if timer_first:
                # The update must wait for the running timer, not be dropped.
                with pytest.raises(TimeoutError):
                    second_call.result(timeout=0.1)
            else:
                # A redundant timer tick can finish without calling Keycloak.
                assert second_call.result(timeout=2) is None
            assert not overlap.is_set()
        finally:
            release.set()
        first_call.result(timeout=2)
        second_call.result(timeout=2)


def test_role_delete_waits_for_running_timer_and_prevents_recreation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = Event()
    release = Event()
    deleted = Event()
    calls: list[str] = []

    def reconcile(**_: Any) -> None:
        calls.append("reconcile")
        active.set()
        assert release.wait(5)
        active.clear()

    def delete(**_: Any) -> str:
        assert not active.is_set()
        calls.append("delete")
        deleted.set()
        return "Delete"

    monkeypatch.setattr(keycloak_client_role, "patch_keycloak_client_role_status", reconcile)
    monkeypatch.setattr(keycloak_client_role, "delete_keycloak_client_role_resource", delete)
    monkeypatch.setattr(keycloak_client_role, "_emit_delete_event", lambda *a, **k: None)
    body: dict[str, Any] = {"metadata": {}}
    memo = kopf.Memo()
    with ThreadPoolExecutor(max_workers=2) as executor:
        timer_call = executor.submit(_timer(), body=body, spec={}, status={}, patch={}, memo=memo)
        try:
            assert active.wait(2)
            body["metadata"]["deletionTimestamp"] = "2026-08-31T13:00:25Z"
            delete_call = executor.submit(
                keycloak_client_role.delete_keycloak_client_role, body=body, spec={}, memo=memo,
            )
            with pytest.raises(TimeoutError):
                delete_call.result(timeout=0.1)
            assert not deleted.is_set()
        finally:
            release.set()
        timer_call.result(timeout=2)
        delete_call.result(timeout=2)

    _timer()(body=body, spec={}, status={}, patch={}, memo=memo)
    keycloak_client_role.reconcile_keycloak_client_role(
        body=body, spec={}, status={}, patch={}, memo=memo,
    )
    assert calls == ["reconcile", "delete"]


def test_different_roles_can_still_reconcile_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = Event()
    release = Event()

    def reconcile(spec: dict[str, Any], **_: Any) -> None:
        if spec["name"] == "first":
            active.set()
            assert release.wait(5)

    monkeypatch.setattr(keycloak_client_role, "patch_keycloak_client_role_status", reconcile)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            _timer(), body={}, spec={"name": "first"}, status={}, patch={}, memo=kopf.Memo(),
        )
        try:
            assert active.wait(2)
            second = executor.submit(
                _timer(), body={}, spec={"name": "second"}, status={}, patch={}, memo=kopf.Memo(),
            )
            assert second.result(timeout=2) is None
        finally:
            release.set()
        first.result(timeout=2)


def test_retryable_failure_releases_resource_for_next_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def reconcile(**_: Any) -> None:
        calls.append("reconcile")
        if len(calls) == 1:
            raise kopf.TemporaryError("try again", delay=60)

    monkeypatch.setattr(keycloak_client_role, "patch_keycloak_client_role_status", reconcile)
    kwargs = {"body": {}, "spec": {}, "status": {}, "memo": kopf.Memo()}
    with pytest.raises(kopf.TemporaryError):
        keycloak_client_role.reconcile_keycloak_client_role(**kwargs, patch={})
    _timer()(**kwargs, patch={})
    assert calls == ["reconcile", "reconcile"]


def test_waiting_update_rechecks_live_deletion_timestamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = Event()
    release = Event()
    calls: list[str] = []

    def reconcile(**_: Any) -> None:
        calls.append("reconcile")
        active.set()
        assert release.wait(5)

    monkeypatch.setattr(keycloak_client_role, "patch_keycloak_client_role_status", reconcile)
    body: dict[str, Any] = {"metadata": {}}
    kwargs = {"body": body, "spec": {}, "status": {}, "memo": kopf.Memo()}
    with ThreadPoolExecutor(max_workers=2) as executor:
        timer_call = executor.submit(_timer(), **kwargs, patch={})
        try:
            assert active.wait(2)
            update_call = executor.submit(
                keycloak_client_role.reconcile_keycloak_client_role, **kwargs, patch={},
            )
            with pytest.raises(TimeoutError):
                update_call.result(timeout=0.1)
            body["metadata"]["deletionTimestamp"] = "2026-08-31T13:00:25Z"
        finally:
            release.set()
        timer_call.result(timeout=2)
        update_call.result(timeout=2)
    assert calls == ["reconcile"]
