from typing import Any

import pytest

from clouddicted_keycloak_config_operator.handlers import reconciliation
from clouddicted_keycloak_config_operator.status import CONDITION_READY, ready_condition


def test_emit_event_for_condition_reasons_emits_new_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, str, str]] = []

    monkeypatch.setattr(
        reconciliation.kopf,
        "event",
        lambda body, type, reason, message: events.append((type, reason, message)),
    )

    reconciliation.emit_event_for_condition_reasons(
        {"metadata": {"name": "example"}},
        previous_status={},
        patch={
            "status": {
                "conditions": [
                    ready_condition("True", "Created", "Object was created."),
                ],
            },
        },
        condition_type=CONDITION_READY,
        events={"Created": ("Normal", None)},
    )

    assert events == [("Normal", "Created", "Object was created.")]


def test_emit_event_for_condition_reasons_skips_unchanged_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, str, str]] = []
    existing_condition = ready_condition("True", "Observed", "Object is ready.")

    monkeypatch.setattr(
        reconciliation.kopf,
        "event",
        lambda body, type, reason, message: events.append((type, reason, message)),
    )

    reconciliation.emit_event_for_condition_reasons(
        {"metadata": {"name": "example"}},
        previous_status={"conditions": [existing_condition]},
        patch={"status": {"conditions": [dict(existing_condition)]}},
        condition_type=CONDITION_READY,
        events={"Observed": ("Normal", "Object was observed.")},
    )

    assert events == []


def test_emit_event_for_condition_reasons_ignores_unmapped_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_event(**_: Any) -> None:
        raise AssertionError("unexpected event")

    monkeypatch.setattr(reconciliation.kopf, "event", fail_event)

    reconciliation.emit_event_for_condition_reasons(
        {"metadata": {"name": "example"}},
        previous_status={},
        patch={
            "status": {
                "conditions": [
                    ready_condition("True", "Observed", "Object is ready."),
                ],
            },
        },
        condition_type=CONDITION_READY,
        events={"Created": ("Normal", None)},
    )


def test_configured_reconciliation_interval_defaults_to_ten_minutes() -> None:
    assert reconciliation.configured_reconciliation_interval_seconds({}) == 600


@pytest.mark.parametrize("value", ["0", "30", "3600"])
def test_configured_reconciliation_interval_accepts_non_negative_integers(
    value: str,
) -> None:
    assert reconciliation.configured_reconciliation_interval_seconds(
        {reconciliation.RECONCILIATION_INTERVAL_ENV: value}
    ) == int(value)


@pytest.mark.parametrize("value", ["-1", "1.5", "invalid"])
def test_configured_reconciliation_interval_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValueError, match="must be a non-negative integer"):
        reconciliation.configured_reconciliation_interval_seconds(
            {reconciliation.RECONCILIATION_INTERVAL_ENV: value}
        )


def test_reconciliation_initial_delay_is_stable_and_within_interval() -> None:
    first = reconciliation.reconciliation_initial_delay(
        uid="uid-1",
        namespace="apps",
        name="example",
        interval_seconds=600,
    )
    repeated = reconciliation.reconciliation_initial_delay(
        uid="uid-1",
        namespace="apps",
        name="example",
        interval_seconds=600,
    )
    other = reconciliation.reconciliation_initial_delay(
        uid="uid-2",
        namespace="apps",
        name="example",
        interval_seconds=600,
    )

    assert 0 <= first < 600
    assert first == repeated
    assert other != first
    assert reconciliation.reconciliation_initial_delay(interval_seconds=0) == 0


def test_discard_unchanged_status_patch_removes_noop_fields() -> None:
    conditions = [ready_condition("True", "Observed", "Object is ready.")]
    patch: dict[str, Any] = {
        "status": {
            "conditions": [dict(conditions[0])],
            "remoteId": "remote-id",
            "optionalField": None,
        }
    }

    reconciliation.discard_unchanged_status_patch(
        patch,
        {"conditions": conditions, "remoteId": "remote-id"},
    )

    assert patch == {}


def test_discard_unchanged_status_patch_keeps_changed_fields() -> None:
    patch: dict[str, Any] = {
        "status": {
            "remoteId": "new-id",
            "removedField": None,
        }
    }

    reconciliation.discard_unchanged_status_patch(
        patch,
        {"remoteId": "old-id", "removedField": "old-value"},
    )

    assert patch == {
        "status": {
            "remoteId": "new-id",
            "removedField": None,
        }
    }
