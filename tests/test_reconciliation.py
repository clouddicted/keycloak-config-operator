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
