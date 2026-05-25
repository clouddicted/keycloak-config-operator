# KeycloakClient

`KeycloakClient` manages an application or service client inside a realm. Use it
for clients that should be created consistently across environments and reviewed
as part of application delivery.

## Choosing The Client Type

Use `Public` for browser and native applications that cannot keep a secret.

Use `Confidential` for backend services, machine-to-machine access, and clients
that can safely use a client secret. Store the desired client secret in a
Kubernetes Secret and reference it from the resource.

## Adoption And Drift

For new clients, use the default reconcile behavior. The operator creates the
client if it is missing and updates the fields it owns when they drift.

For existing production clients, start with `managementPolicy: ObserveOnly`. This
lets you see whether the declared configuration matches Keycloak before allowing
the operator to update anything.

When you are comfortable with the observed state, switch to the default
reconcile mode.

## Public Client Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakClient
metadata:
  name: example-web
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

## Confidential Client Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakClient
metadata:
  name: example-service
spec:
  targetRef:
    name: example-keycloak
  realm: example
  clientId: example-service
  clientType: Confidential
  secretRef:
    name: example-service-client-secret
    secretKey: clientSecret
```

## Lifecycle Choices

Keep the default `deletionPolicy: Orphan` for shared or production clients. This
prevents accidental remote deletion if a manifest is removed from Git or a
namespace is deleted.

Use `deletionPolicy: Delete` for clients that are fully owned by the Kubernetes
resource, especially in disposable environments.

## Operations

`.status.remoteId` contains the Keycloak internal client ID. Use it when checking
the object through the Keycloak Admin API.

`kubectl describe keycloakclient <name>` shows Events for creation, updates,
observe-only drift, missing observe-only clients, and deletion behavior.
