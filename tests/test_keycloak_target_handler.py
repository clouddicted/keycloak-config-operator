import logging
from datetime import UTC, datetime

import kopf

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_TARGET_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import keycloak_target
from clouddicted_keycloak_config_operator.status import CONDITION_READY, ready_condition


def test_keycloak_target_resource_registration_values() -> None:
    assert keycloak_target.KEYCLOAK_TARGET_RESOURCE == {
        "group": API_GROUP,
        "version": API_VERSION,
        "plural": KEYCLOAK_TARGET_PLURAL,
    }


def test_main_imports_keycloak_target_handler_module() -> None:
    assert keycloak_target in main.REGISTERED_HANDLER_MODULES


def test_configure_sets_operator_settings() -> None:
    settings = kopf.OperatorSettings()

    main.configure(settings)

    assert settings.posting.level == logging.INFO
    assert settings.persistence.finalizer == f"{API_GROUP}/finalizer"
    assert isinstance(settings.persistence.progress_storage, kopf.AnnotationsProgressStorage)
    assert isinstance(settings.persistence.diffbase_storage, kopf.AnnotationsDiffBaseStorage)
    assert settings.persistence.diffbase_storage.ignored_fields == ["status"]


def test_patch_keycloak_target_status_sets_placeholder_ready_condition() -> None:
    patch: dict[str, object] = {}

    keycloak_target.patch_keycloak_target_status(
        spec={
            "url": "https://keycloak.example.com",
            "adminCredentials": {"secretRef": {"name": "keycloak-admin"}},
        },
        status={},
        patch=patch,
        now=datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC),
    )

    assert patch == {
        "status": {
            "conditions": [
                {
                    "type": CONDITION_READY,
                    "status": "Unknown",
                    "reason": keycloak_target.VALIDATION_PENDING_REASON,
                    "message": "Keycloak connectivity validation is not implemented yet.",
                    "lastTransitionTime": "2026-05-22T10:30:45Z",
                },
            ],
        },
    }


def test_patch_keycloak_target_status_reports_invalid_minimal_shape() -> None:
    patch: dict[str, object] = {}

    keycloak_target.patch_keycloak_target_status(
        spec={"adminCredentials": {"secretRef": {}}},
        status={},
        patch=patch,
        now=datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC),
    )

    assert patch["status"]["conditions"][0] == {
        "type": CONDITION_READY,
        "status": "False",
        "reason": keycloak_target.INVALID_SPEC_REASON,
        "message": (
            "Missing required KeycloakTarget spec fields: "
            "url, adminCredentials.secretRef.name."
        ),
        "lastTransitionTime": "2026-05-22T10:30:45Z",
    }


def test_patch_keycloak_target_status_preserves_stable_ready_transition_time() -> None:
    existing_ready = ready_condition(
        "Unknown",
        "OldReason",
        "Old message.",
        now=datetime(2026, 5, 22, 9, 30, 45, tzinfo=UTC),
    )
    patch: dict[str, object] = {}

    keycloak_target.patch_keycloak_target_status(
        spec={
            "url": "https://keycloak.example.com",
            "adminCredentials": {"secretRef": {"name": "keycloak-admin"}},
        },
        status={"conditions": [existing_ready]},
        patch=patch,
        now=datetime(2026, 5, 22, 10, 30, 45, tzinfo=UTC),
    )

    ready = patch["status"]["conditions"][0]
    assert ready["status"] == "Unknown"
    assert ready["reason"] == keycloak_target.VALIDATION_PENDING_REASON
    assert ready["lastTransitionTime"] == "2026-05-22T09:30:45Z"
