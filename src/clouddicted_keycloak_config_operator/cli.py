"""Container and console entrypoint for the operator and adoption CLI."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

from clouddicted_keycloak_config_operator import adoption


def operator_command(arguments: Sequence[str]) -> list[str]:
    """Build the Kopf command used by the default container mode."""
    return [
        "kopf",
        "run",
        "-m",
        "clouddicted_keycloak_config_operator.main",
        *arguments,
    ]


def main(argv: Sequence[str] | None = None) -> int:
    """Run the adoption CLI or replace this process with Kopf."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "adopt":
        return adoption.main(arguments[1:])

    command = operator_command(arguments)
    os.execvp(command[0], command)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
