"""Kopf entrypoint for the Clouddicted Keycloak Config Operator."""

from __future__ import annotations

import logging
from typing import Any

import kopf

from clouddicted_keycloak_config_operator.constants import OPERATOR_NAME

logger = logging.getLogger(__name__)


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_: Any) -> None:
    """Configure process-wide Kopf settings before handlers start."""
    settings.posting.level = logging.INFO
    logger.info("%s started", OPERATOR_NAME)
