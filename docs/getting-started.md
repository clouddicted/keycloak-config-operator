# Getting Started

This page shows the smallest useful setup: install the operator, connect it to
Keycloak, create a realm, and create one public client.

## Install

```bash
helm upgrade --install keycloak-config-operator \
  oci://ghcr.io/clouddicted/charts/keycloak-config-operator \
  --version 0.1.0 \
  --namespace keycloak-config-operator-system \
  --create-namespace
```

## Create A Configuration Namespace

```bash
kubectl create namespace keycloak-config
```

## Add Keycloak Credentials

For a quick start, use an admin username and password stored in a Kubernetes
Secret.

```bash
kubectl create secret generic keycloak-admin-credentials \
  --namespace keycloak-config \
  --from-literal=username='<admin-user>' \
  --from-literal=password='<admin-password>'
```

## Create A Target

The target tells the operator how to reach Keycloak. When Keycloak runs in the
same cluster, use the internal Service URL instead of the public hostname.

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakTarget
metadata:
  name: example-keycloak
  namespace: keycloak-config
spec:
  url: http://keycloak.keycloak.svc.cluster.local:8080
  adminCredentials:
    secretRef:
      name: keycloak-admin-credentials
```

Apply it and wait until the connection is ready.

```bash
kubectl apply -f keycloak-target.yaml
kubectl wait -n keycloak-config --for=condition=Ready \
  keycloaktarget/example-keycloak --timeout=120s
```

## Create A Realm And Client

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakRealm
metadata:
  name: example-realm
  namespace: keycloak-config
spec:
  targetRef:
    name: example-keycloak
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
    name: example-keycloak
  realm: example
  clientId: example-web
  clientType: Public
  displayName: Example Web
  redirectUris:
    - https://app.example.com/*
  webOrigins:
    - https://app.example.com
```

```bash
kubectl apply -f keycloak-config.yaml
kubectl get -n keycloak-config keycloakrealms,keycloakclients
```

Both resources should eventually report `Ready=True`.

## Next Steps

- Use [ClientCredentials or BootstrapClientCredentials](resources/keycloak-target.md)
  for production-style access.
- Review [resource pages](resources/index.md) before adding roles, client
  scopes, or protocol mappers.
- Use the [configuration support matrix](configuration-support.md) to check
  supported create, update, and delete behavior.
