# Keycloak Config Operator

The Keycloak Config Operator is a Kopf-based Kubernetes operator for managing
selected Keycloak configuration through Kubernetes custom resources.

## What The Operator Manages

The operator currently manages:

- Keycloak targets
- Realms
- Clients
- Realm roles
- Client scopes
- Protocol mappers

See the [configuration support matrix](configuration-support.md) for the exact
entities, fields, and reconciliation behavior that are part of the supported
contract.

## Compatibility

See [compatibility](compatibility.md) for tested Keycloak versions and the support
policy.

## Install With Helm

```bash
helm upgrade --install keycloak-config-operator charts/keycloak-config-operator \
  --namespace keycloak-config-operator-system \
  --create-namespace
```

By default, the operator watches Keycloak resources in all namespaces. To restrict
the watch scope, set `watchNamespaces`.

```bash
helm upgrade --install keycloak-config-operator charts/keycloak-config-operator \
  --namespace keycloak-config-operator-system \
  --create-namespace \
  --set 'watchNamespaces[0]=team-a'
```

## Local Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev,docs]"
.venv/bin/ruff check .
.venv/bin/pytest
.venv/bin/mkdocs build --strict
```
