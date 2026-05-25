# KeycloakClient

`KeycloakClient` manages an application or service client inside a realm. Use it
for clients that should be created consistently across environments and reviewed
as part of application delivery.

## Choosing The Client Type

Use `Public` for browser and native applications that cannot keep a secret.

Use `Confidential` for backend services, machine-to-machine access, and clients
that can safely use a client secret. Store the desired client secret in a
Kubernetes Secret and reference it from the resource.

## URLs And Flows

For browser clients, declare the URLs and flows that are part of the application
contract. Common fields are:

- `rootUrl`, `baseUrl`, and `adminUrl` for Keycloak client URLs.
- `redirectUris` and `webOrigins` for browser integration.
- `standardFlowEnabled` for authorization code flow.
- `directAccessGrantsEnabled` for password grant access.

Only declare fields you want the operator to own. Omitted fields are left as
they are in Keycloak.

For confidential service clients, `serviceAccountsEnabled` enables service
account usage. The CRD rejects service accounts on public clients because
Keycloak only supports them for confidential clients.

## Client Scopes

Use `defaultClientScopes` and `optionalClientScopes` when the client needs
explicit scope assignments. Prefer attaching common mappers to a shared
`KeycloakClientScope`, then assigning that scope to the clients that need it.

Scope lists are reconciled when declared. During adoption, use
`managementPolicy: ObserveOnly` first if you are not sure which scopes are
already assigned in Keycloak.

Keep each scope list unique. Duplicate values usually hide a copy-paste mistake
and are rejected before the operator reconciles the client.

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
  rootUrl: https://app.example.com
  baseUrl: /
  standardFlowEnabled: true
  directAccessGrantsEnabled: false
  redirectUris:
    - https://app.example.com/*
  webOrigins:
    - https://app.example.com
  defaultClientScopes:
    - example-profile
  optionalClientScopes:
    - offline_access
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
  serviceAccountsEnabled: true
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
