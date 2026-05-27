from datetime import UTC, datetime, timedelta, timezone

from clouddicted_keycloak_config_operator.status.conditions import (
    CONDITION_AUTHENTICATED,
    CONDITION_DRIFT_DETECTED,
    CONDITION_READY,
    CONDITION_SECRET_READY,
    authenticated_condition,
    drift_detected_condition,
    drift_unknown_condition,
    ready_condition,
    secret_ready_condition,
    upsert_condition,
)


def test_condition_creation_uses_kubernetes_utc_timestamp() -> None:
    condition = ready_condition(
        "True",
        "Reconciled",
        "Realm is synchronized.",
        now=datetime(2026, 5, 22, 12, 30, 45, tzinfo=timezone(timedelta(hours=2))),
    )

    assert condition == {
        "type": CONDITION_READY,
        "status": "True",
        "reason": "Reconciled",
        "message": "Realm is synchronized.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }


def test_condition_helpers_use_expected_types() -> None:
    now = datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC)

    conditions = [
        ready_condition("True", "Ready", "Ready.", now=now),
        authenticated_condition("True", "Authenticated", "Authenticated.", now=now),
        secret_ready_condition("False", "SecretMissing", "Secret is missing.", now=now),
        drift_detected_condition("True", "DriftFound", "Drift was detected.", now=now),
    ]

    assert [condition["type"] for condition in conditions] == [
        CONDITION_READY,
        CONDITION_AUTHENTICATED,
        CONDITION_SECRET_READY,
        CONDITION_DRIFT_DETECTED,
    ]


def test_drift_unknown_condition_uses_drift_detected_type() -> None:
    condition = drift_unknown_condition(
        "TargetUnavailable",
        "Drift detection was skipped.",
        now=datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC),
    )

    assert condition == {
        "type": CONDITION_DRIFT_DETECTED,
        "status": "Unknown",
        "reason": "TargetUnavailable",
        "message": "Drift detection was skipped.",
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }


def test_upsert_condition_inserts_new_condition() -> None:
    condition = secret_ready_condition(
        "True",
        "SecretFound",
        "Secret exists.",
        now=datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC),
    )

    assert upsert_condition([], condition) == [condition]


def test_upsert_condition_keeps_stable_ordering() -> None:
    now = datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC)
    ready = ready_condition("True", "Ready", "Ready.", now=now)
    authenticated = authenticated_condition("True", "Authenticated", "Authenticated.", now=now)
    secret_ready = secret_ready_condition("True", "SecretFound", "Secret exists.", now=now)
    drift_detected = drift_detected_condition("False", "NoDrift", "No drift.", now=now)

    conditions = upsert_condition([drift_detected, ready], secret_ready)
    conditions = upsert_condition(conditions, authenticated)

    assert [condition["type"] for condition in conditions] == [
        CONDITION_READY,
        CONDITION_AUTHENTICATED,
        CONDITION_SECRET_READY,
        CONDITION_DRIFT_DETECTED,
    ]


def test_upsert_condition_preserves_transition_time_when_status_is_unchanged() -> None:
    existing = ready_condition(
        "True",
        "Reconciled",
        "Old message.",
        now=datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC),
    )
    incoming = ready_condition(
        "True",
        "StillReconciled",
        "New message.",
        now=datetime(2026, 5, 22, 11, 30, 45, tzinfo=UTC),
    )

    [updated] = upsert_condition([existing], incoming)

    assert updated["reason"] == "StillReconciled"
    assert updated["message"] == "New message."
    assert updated["lastTransitionTime"] == "2026-05-22T10:30:45Z"


def test_upsert_condition_changes_transition_time_when_status_changes() -> None:
    existing = ready_condition(
        "False",
        "Waiting",
        "Waiting for reconciliation.",
        now=datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC),
    )
    incoming = ready_condition(
        "True",
        "Reconciled",
        "Realm is synchronized.",
        now=datetime(2026, 5, 22, 11, 30, 45, tzinfo=UTC),
    )

    [updated] = upsert_condition([existing], incoming)

    assert updated["status"] == "True"
    assert updated["lastTransitionTime"] == "2026-05-22T11:30:45Z"
