# Usage Guide

Use the operator by installing it once, then applying Keycloak custom resources
in the namespaces the operator watches.

## Prerequisites

- A Kubernetes cluster with access to the Keycloak Admin API URL.
- A Keycloak admin user with enough permissions to manage the target realm data.
- `kubectl` and `helm` configured for the cluster.

## Install The Operator

```bash
helm upgrade --install keycloak-config-operator \
  oci://ghcr.io/clouddicted/charts/keycloak-config-operator \
  --version 0.1.0 \
  --namespace keycloak-config-operator-system \
  --create-namespace
```

By default, the operator watches Keycloak resources in all namespaces. To limit
the watch scope, install with `watchNamespaces`.

```bash
helm upgrade --install keycloak-config-operator \
  oci://ghcr.io/clouddicted/charts/keycloak-config-operator \
  --version 0.1.0 \
  --namespace keycloak-config-operator-system \
  --create-namespace \
  --set 'watchNamespaces[0]=keycloak-config'
```

## Configure A Keycloak Target

Create a namespace for Keycloak configuration resources and store the admin
credentials in a Kubernetes Secret.

```bash
kubectl create namespace keycloak-config

kubectl create secret generic keycloak-admin-credentials \
  --namespace keycloak-config \
  --from-literal=username='<admin-user>' \
  --from-literal=password='<admin-password>'
```

Create a `KeycloakTarget`. The URL must be reachable from the operator pod.

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakTarget
metadata:
  name: production-keycloak
  namespace: keycloak-config
spec:
  url: https://keycloak.example.com
  adminCredentials:
    secretRef:
      name: keycloak-admin-credentials
      usernameKey: username
      passwordKey: password
```

Apply it and wait for the target to become ready.

```bash
kubectl apply -f keycloak-target.yaml
kubectl wait -n keycloak-config --for=condition=Ready \
  keycloaktarget/production-keycloak --timeout=120s
```

If the target is not ready, inspect the conditions. Authentication, secret, and
connectivity failures are reported on the resource.

```bash
kubectl describe -n keycloak-config keycloaktarget production-keycloak
```

## Manage Keycloak Configuration

Apply dependent resources in the same namespace. Each resource references the
target through `spec.targetRef.name`.

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakRealm
metadata:
  name: example-realm
  namespace: keycloak-config
spec:
  targetRef:
    name: production-keycloak
  realm: example
  displayName: Example
---
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakClient
metadata:
  name: example-web
  namespace: keycloak-config
spec:
  targetRef:
    name: production-keycloak
  realm: example
  clientId: example-web
  clientType: Public
  displayName: Example Web
  redirectUris:
    - https://app.example.com/*
  webOrigins:
    - https://app.example.com
```

Apply the resources and check their status.

```bash
kubectl apply -f keycloak-config.yaml

kubectl get -n keycloak-config \
  keycloakrealms,keycloakclients,keycloakroles,keycloakclientscopes,keycloakprotocolmappers
```

Ready resources have a `Ready=True` condition. If a resource depends on a target,
realm, client, or client scope that is not ready yet, the operator reports that in
the resource status and retries reconciliation.

## Deletion Behavior

Resource deletions leave existing Keycloak objects in place by default.
`KeycloakClient`, `KeycloakRole`, `KeycloakClientScope`, and
`KeycloakProtocolMapper` can delete the remote object when
`spec.deletionPolicy` is set to `Delete`; otherwise they use the default
`Orphan` behavior. `KeycloakRealm` deletion always leaves the remote realm in
place.

```yaml
spec:
  deletionPolicy: Delete
```

See the [configuration support matrix](configuration-support.md) for the exact
create, update, and delete behavior of each resource type.
