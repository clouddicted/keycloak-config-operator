# Keycloak Config Operator

The Keycloak Config Operator manages selected Keycloak configuration from
Kubernetes custom resources. It lets teams keep Keycloak realms, identity
providers, clients, client roles, groups, group role mappings, realm roles,
client scopes, and protocol mappers close to the applications that use them.

## Why Use It

- Bring Keycloak configuration into the same GitOps workflow as your applications.
- Turn repeatable identity setup into reviewed, versioned Kubernetes manifests.
- Reduce manual console work and make environment rebuilds predictable.
- Give platform teams a clear contract for supported realms, identity providers,
  clients, roles, scopes, and mappers.

## How It Works

You describe the Keycloak state you want in Kubernetes. The operator watches
those declarations and talks to the Keycloak Admin API whenever a resource is
created, updated, or resumed at operator startup. Successful resources are not
periodically resynced in the current release.

Each resource reports its own status, so teams can use familiar Kubernetes tools
to understand whether configuration was applied, authentication failed, or a
dependency is not ready yet.

## Start Here

- [Getting started](getting-started.md) for a minimal working example.
- [Usage guide](usage.md) for install options, authentication modes, and deletion behavior.
- [Resources](resources/index.md) for practical CRD field explanations and examples.
- [API reference](api-reference.md) for the generated CRD schema.

Install the released Helm chart from GitHub Container Registry:

```bash
helm upgrade --install keycloak-config-operator \
  oci://ghcr.io/clouddicted/charts/keycloak-config-operator \
  --version 0.4.0 \
  --namespace keycloak-config-operator-system \
  --create-namespace
```

## Compatibility

See [compatibility](compatibility.md) for tested Keycloak versions and the support
policy.
