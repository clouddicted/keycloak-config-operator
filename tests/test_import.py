import os
import subprocess
import sys

import kopf

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import OPERATOR_NAME
from clouddicted_keycloak_config_operator.handlers.reconciliation import (
    RECONCILIATION_INTERVAL_SECONDS,
)


def test_package_imports() -> None:
    assert OPERATOR_NAME == "clouddicted-keycloak-config-operator"


def test_every_handler_module_registers_periodic_reconciliation() -> None:
    timer_handlers = kopf.get_default_registry()._spawning.get_all_handlers()

    assert len(main.REGISTERED_HANDLER_MODULES) == 10
    assert len(timer_handlers) == len(main.REGISTERED_HANDLER_MODULES)
    assert {handler.fn.__module__ for handler in timer_handlers} == {
        module.__name__ for module in main.REGISTERED_HANDLER_MODULES
    }
    assert all(handler.interval == RECONCILIATION_INTERVAL_SECONDS for handler in timer_handlers)
    assert all(callable(handler.initial_delay) for handler in timer_handlers)


def test_zero_interval_disables_periodic_reconciliation() -> None:
    env = dict(os.environ)
    env["RECONCILIATION_INTERVAL_SECONDS"] = "0"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import kopf; "
                "import clouddicted_keycloak_config_operator.main; "
                "print(len(kopf.get_default_registry()._spawning.get_all_handlers()))"
            ),
        ],
        check=True,
        capture_output=True,
        env=env,
        text=True,
    )

    assert result.stdout.strip() == "0"
