"""Helpers for operator status patches."""

from clouddicted_keycloak_config_operator.status.conditions import (
    CONDITION_AUTHENTICATED,
    CONDITION_DRIFT_DETECTED,
    CONDITION_READY,
    CONDITION_SECRET_READY,
    Condition,
    ConditionStatus,
    authenticated_condition,
    drift_detected_condition,
    ready_condition,
    secret_ready_condition,
    upsert_condition,
)

__all__ = [
    "CONDITION_AUTHENTICATED",
    "CONDITION_DRIFT_DETECTED",
    "CONDITION_READY",
    "CONDITION_SECRET_READY",
    "Condition",
    "ConditionStatus",
    "authenticated_condition",
    "drift_detected_condition",
    "ready_condition",
    "secret_ready_condition",
    "upsert_condition",
]
