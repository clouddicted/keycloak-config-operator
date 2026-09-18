# KeycloakClient

`KeycloakClient` manages an application or service client inside a realm. Use it
for clients that should be created consistently across environments and reviewed
as part of application delivery.

## Choosing The Client Type

Use `Public` for browser and native applications that cannot keep a secret.

Use `Confidential` for backend services, machine-to-machine access, and clients
that authenticate with a shared secret or a signed JWT.

## Client Authentication

Existing confidential clients continue to use client-secret authentication when
`authentication` is omitted. Store the desired client secret in a Kubernetes
Secret and reference it with `secretRef`.

Set `authentication.method: SignedJwt` when the application signs client
assertions with its private key. Keycloak needs only the corresponding public
material. Choose exactly one source:

- `signedJwt.certificateSecretRef` loads a PEM X.509 certificate from a
  Kubernetes Secret. The key defaults to `tls.crt`. Store only the certificate;
  the application private key does not belong in the operator's Secret.
- `signedJwt.jwksUrl` lets Keycloak fetch and rotate public keys from the
  application's JWKS endpoint.

`signedJwt.signatureAlgorithm` optionally restricts assertions to an algorithm
such as `RS256`. Omit it to use Keycloak's configured defaults.

## URLs And Flows

For browser clients, declare the URLs and flows that are part of the application
contract. Common fields are:

- `rootUrl`, `baseUrl`, and `adminUrl` for Keycloak client URLs.
- `redirectUris` and `webOrigins` for browser integration.
- `standardFlowEnabled` for authorization code flow.
- `implicitFlowEnabled` only for legacy clients that still require implicit
  flow.
- `directAccessGrantsEnabled` for password grant access.
- `frontchannelLogout` when browser logout must notify the client.
- `pkceCodeChallengeMethod` to require `S256` or `plain` PKCE challenges.
- `postLogoutRedirectUris` for redirects after OpenID Connect logout.
- `backchannelLogoutUrl`, `backchannelLogoutSessionRequired`, and
  `backchannelLogoutRevokeOfflineTokens` for back-channel logout.
- `useRefreshTokens` and `useRefreshTokensForClientCredentials` for refresh-token
  behavior.
- `consentRequired` when users must approve the client before access is granted.

Only declare fields you want the operator to own. Omitted fields are left as
they are in Keycloak.

Use `enabled: false` to keep a client defined but temporarily disabled in
Keycloak. This is useful for staged rollouts and incident response because the
client stays visible and reviewable in Git.

Set `fullScopeAllowed: false` when you want least-privilege scope assignment.
Then declare `defaultClientScopes` and `optionalClientScopes` explicitly.

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

All declared scopes must exist in the client's realm before the operator creates
or updates the client. If a scope is missing, reconciliation reports
`Ready=False` and `DriftDetected=True` with reason `ClientScopeMissing`, without
writing to the client. The blocked reconciliation completes so Kopf can
continue handling later changes. A managed `KeycloakClientScope` change triggers
an immediate check; periodic reconciliation covers independently created scopes.
Create the missing scope or correct the client's scope list to allow
reconciliation to continue.

## Adoption And Drift

For new clients, use the default reconcile behavior. The operator creates the
client if it is missing and updates the fields it owns when they drift.

For existing production clients, start with `managementPolicy: ObserveOnly`. This
lets you see whether the declared configuration matches Keycloak before allowing
the operator to update anything.

When you are comfortable with the observed state, switch to the default
reconcile mode.

After creating or updating a client, the operator reads it back and verifies
the modeled fields. If Keycloak accepts the request but the observed state still
differs, the operator reports `Ready=False` and `DriftDetected=True` with reason
`ClientNotConverged` and retries. A successful HTTP response alone does not mark
the client ready.

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
  enabled: true
  displayName: Example Web
  description: Example browser application
  rootUrl: https://app.example.com
  baseUrl: /
  standardFlowEnabled: true
  implicitFlowEnabled: false
  directAccessGrantsEnabled: false
  fullScopeAllowed: false
  frontchannelLogout: true
  consentRequired: false
  pkceCodeChallengeMethod: S256
  postLogoutRedirectUris:
    - https://app.example.com/signed-out
  backchannelLogoutUrl: https://app.example.com/backchannel-logout
  backchannelLogoutSessionRequired: true
  backchannelLogoutRevokeOfflineTokens: false
  useRefreshTokens: true
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

## Signed JWT Client Examples

Use a JWKS URL when the application publishes a rotating key set:

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakClient
metadata:
  name: example-signed-jwt-service
spec:
  targetRef:
    name: example-keycloak
  realm: example
  clientId: example-signed-jwt-service
  clientType: Confidential
  serviceAccountsEnabled: true
  authentication:
    method: SignedJwt
    signedJwt:
      jwksUrl: https://service.example.com/.well-known/jwks.json
      signatureAlgorithm: RS256
```

Reference a certificate Secret when the public certificate is distributed with
the application configuration:

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakClient
metadata:
  name: example-certificate-service
spec:
  targetRef:
    name: example-keycloak
  realm: example
  clientId: example-certificate-service
  clientType: Confidential
  authentication:
    method: SignedJwt
    signedJwt:
      certificateSecretRef:
        name: example-certificate-service
        secretKey: tls.crt
      signatureAlgorithm: RS256
```

The operator watches the referenced certificate Secret. A certificate rotation
triggers reconciliation and updates the managed Keycloak client attribute.

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
