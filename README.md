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

Run the opt-in kind integration and e2e tests:

```bash
RUN_KIND_INTEGRATION=1 .venv/bin/pytest tests/integration/test_kind_fixtures.py -q
```

The e2e test builds the operator image, loads it into kind, deploys that same tag
with `imagePullPolicy: Never`, creates sample Keycloak CRs, and verifies the
created Keycloak entities through the Keycloak Admin API. Override the image tag
used by the test with `KIND_OPERATOR_IMAGE`.

Run the operator locally:

```bash
.venv/bin/kopf run -m clouddicted_keycloak_config_operator.main --all-namespaces
```

## Local Kubernetes Install

Install the CRDs, RBAC, ServiceAccount, and Deployment:

```bash
kubectl apply -k config/install
```

The default Deployment image is a placeholder for the first packaged release:
`ghcr.io/clouddicted/keycloak-config-operator:v0.1.0`. For local testing, replace it
with an image you built and loaded into the cluster:

```bash
kubectl -n keycloak-config-operator-system set image \
  deployment/keycloak-config-operator \
  manager=<your-operator-image>
```

Create Keycloak admin credentials before applying a `KeycloakTarget`:

```bash
kubectl create secret generic keycloak-admin-credentials \
  --from-literal=username=<admin-user> \
  --from-literal=password=<admin-password>
```

Apply only the CRDs:

```bash
kubectl apply -k config/crd
```

Apply the sample resources:

```bash
kubectl apply -k config/samples
```
