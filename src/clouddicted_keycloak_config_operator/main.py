"""Kopf entrypoint for the Clouddicted Keycloak Config Operator."""

from __future__ import annotations

import logging
from typing import Any

import kopf

from clouddicted_keycloak_config_operator.constants import API_GROUP, OPERATOR_NAME
from clouddicted_keycloak_config_operator.handlers import (
    keycloak_client,
    keycloak_client_role,
    keycloak_client_scope,
    keycloak_identity_provider,
    keycloak_protocol_mapper,
    keycloak_realm,
    keycloak_role,
    keycloak_target,
)

LOG_RECORD_NAME = "keycloak-operator"
_KOPF_LOGGER_PREFIX = "kopf"
_KOPF_OBJECTS_LOGGER_NAME = "kopf.objects"
logger = logging.getLogger(LOG_RECORD_NAME)

REGISTERED_HANDLER_MODULES = (
    keycloak_target,
    keycloak_realm,
    keycloak_client,
    keycloak_client_role,
    keycloak_role,
    keycloak_client_scope,
    keycloak_protocol_mapper,
    keycloak_identity_provider,
)


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_: Any) -> None:
    """Configure process-wide Kopf settings before handlers start."""
    _configure_log_record_names()
    settings.posting.level = logging.INFO
    settings.persistence.finalizer = f"{API_GROUP}/finalizer"
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(prefix=API_GROUP)
    settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix=API_GROUP,
        ignored_fields=["status"],
    )
    logger.info("%s started", OPERATOR_NAME)


class OperatorLogRecordNameFilter(logging.Filter):
    """Present framework-originated logs under the operator name."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == _KOPF_LOGGER_PREFIX or record.name.startswith(
            f"{_KOPF_LOGGER_PREFIX}.",
        ):
            record.name = LOG_RECORD_NAME

        return True


def _configure_log_record_names() -> None:
    logging.getLogger(_KOPF_OBJECTS_LOGGER_NAME).setLevel(logging.WARNING)
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if not any(
            isinstance(log_filter, OperatorLogRecordNameFilter)
            for log_filter in handler.filters
        ):
            handler.addFilter(OperatorLogRecordNameFilter())
