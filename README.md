# Keycloak Config Operator

Minimal Kopf-based Kubernetes operator for managing Keycloak configuration.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branch, commit, test, and release flow.

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

Run the opt-in kind integration and e2e tests in three independent steps:

```bash
.venv/bin/python tests/kind/e2e.py prepare
.venv/bin/python tests/kind/e2e.py test
.venv/bin/python tests/kind/e2e.py cleanup
```

The prepare step builds the operator image, loads it into kind, deploys that same
tag with `imagePullPolicy: Never`, and starts the Keycloak fixture. The test step
creates sample Keycloak CRs and verifies the created Keycloak entities through
the Keycloak Admin API. The cleanup step deletes the kind cluster. Override the
image tag with `KIND_OPERATOR_IMAGE`.

After prepare, inspect the cluster with:

```bash
kubectl --context kind-clouddicted-keycloak-config-operator-it get pods -A
```

Run the operator locally:

```bash
.venv/bin/kopf run -m clouddicted_keycloak_config_operator.main --all-namespaces
```

## Local Kubernetes Install

Install the CRDs, RBAC, ServiceAccount, and Deployment:

```bash
kubectl apply -k config/install
```

Install with Helm:

```bash
helm upgrade --install keycloak-config-operator charts/keycloak-config-operator \
  --namespace keycloak-config-operator-system \
  --create-namespace
```

The Helm chart installs CRDs from `charts/keycloak-config-operator/crds`.
By default, the operator watches Keycloak resources in all namespaces. To restrict
the watch scope, set `watchNamespaces`:

```bash
helm upgrade --install keycloak-config-operator charts/keycloak-config-operator \
  --namespace keycloak-config-operator-system \
  --create-namespace \
  --set 'watchNamespaces[0]=team-a' \
  --set 'watchNamespaces[1]=team-b'
```

When `watchNamespaces` is set, the chart creates namespace-scoped RBAC in each
listed namespace. Those namespaces must already exist or be managed separately.

For a local kind image, load the image into kind and install with the same tag:

```bash
helm upgrade --install keycloak-config-operator charts/keycloak-config-operator \
  --namespace keycloak-config-operator-system \
  --create-namespace \
  --set image.repository=clouddicted-keycloak-config-operator \
  --set image.tag=e2e \
  --set image.pullPolicy=Never
```

The default Deployment image is a placeholder for the first packaged release:
`ghcr.io/clouddicted/keycloak-config-operator:v0.1.0`. For local testing, replace it
with an image you built and loaded into the cluster:

```bash
kubectl -n keycloak-config-operator-system set image \
  deployment/keycloak-config-operator \
  manager=<your-operator-image>
```

For the plain Kubernetes manifests, all namespaces are watched by default. To
restrict the scope, replace the Deployment `--all-namespaces` argument with
repeated `--namespace <namespace>` arguments.

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
