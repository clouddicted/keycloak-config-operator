# Keycloak Config Operator

[![CI](https://github.com/clouddicted/keycloak-config-operator/actions/workflows/ci.yml/badge.svg)](https://github.com/clouddicted/keycloak-config-operator/actions/workflows/ci.yml)
[![Version](https://img.shields.io/github/v/tag/clouddicted/keycloak-config-operator?sort=semver&label=version)](https://github.com/clouddicted/keycloak-config-operator/tags)

Keycloak Config Operator is an open-source Kubernetes operator for managing
Keycloak configuration declaratively through custom resources. It helps DevOps
and platform teams automate Keycloak realms, clients, roles, client scopes,
protocol mappers, and target connections in a GitOps-friendly way.

Published documentation is available on GitHub Pages:
[clouddicted.github.io/keycloak-config-operator](https://clouddicted.github.io/keycloak-config-operator/).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branch, commit, test, and release flow.
See [docs/compatibility.md](docs/compatibility.md) for tested Keycloak versions and
[docs/configuration-support.md](docs/configuration-support.md) for supported
configuration entities and fields. See [docs/api-reference.md](docs/api-reference.md)
for the CRD schema reference.

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

The `v0.2.0` release serves Keycloak resources as `keycloak.clouddicted.com/v1beta1`.

Install the CRDs, RBAC, ServiceAccount, and Deployment:

```bash
kubectl apply -k config/install
```

Install a released chart from GitHub Container Registry:

```bash
helm upgrade --install keycloak-config-operator \
  oci://ghcr.io/clouddicted/charts/keycloak-config-operator \
  --version 0.2.0 \
  --namespace keycloak-config-operator-system \
  --create-namespace
```

Install from a local checkout:

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
`ghcr.io/clouddicted/keycloak-config-operator:v0.2.0`. For local testing, replace it
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

## License

See [LICENSE](LICENSE) and [NOTICE](NOTICE).
