# Keycloak Config Operator

Minimal Kopf-based Kubernetes operator for managing Keycloak configuration.

## Development

Create a local environment and install the project:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
```

Run checks:

```bash
.venv/bin/ruff check .
.venv/bin/pytest
```

Run the operator locally:

```bash
.venv/bin/kopf run -m clouddicted_keycloak_config_operator.main --all-namespaces
```
