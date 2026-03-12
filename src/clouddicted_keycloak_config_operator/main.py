"""Kopf entrypoint for the Clouddicted Keycloak Config Operator."""

from __future__ import annotations

import logging
from typing import Any

import kopf

from clouddicted_keycloak_config_operator.constants import API_GROUP, OPERATOR_NAME
from clouddicted_keycloak_config_operator.handlers import (
    keycloak_client,
    keycloak_realm,
    keycloak_target,
)

logger = logging.getLogger(__name__)

REGISTERED_HANDLER_MODULES = (keycloak_target, keycloak_realm, keycloak_client)


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_: Any) -> None:
    """Configure process-wide Kopf settings before handlers start."""
    settings.posting.level = logging.INFO
    settings.persistence.finalizer = f"{API_GROUP}/finalizer"
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(prefix=API_GROUP)
    settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix=API_GROUP,
        ignored_fields=["status"],
    )
    logger.info("%s started", OPERATOR_NAME)
