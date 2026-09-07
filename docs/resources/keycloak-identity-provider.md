# KeycloakIdentityProvider

`KeycloakIdentityProvider` manages one identity provider instance inside a
realm. The first version is intentionally small: it creates, observes, updates,
and optionally deletes a provider by alias.

Use it when teams need a repeatable way to configure login through an external
OIDC, SAML, or social provider. Keep non-sensitive provider-specific settings in
`config` and sensitive values in `configSecretRefs`; Keycloak decides which keys
are meaningful for the selected `providerId`.

## Basic Shape

The alias is the lookup key. Pick a stable alias and avoid renaming it unless
you are ready to create a new provider instance.

`providerId` is the Keycloak provider type, for example `oidc`, `saml`,
`github`, or `google`. The operator does not validate provider-specific config
yet because each provider type has different requirements.

Only declare config keys you want the operator to own. During updates,
undeclared existing config keys are preserved. If the same key exists in both
`config` and `configSecretRefs`, the Secret value wins.

## Flow And Login Settings

The resource also supports core identity provider login and brokerage behavior:

- `trustEmail`: Set to `true` if emails provided by this identity provider are verified and trusted by your realm.
- `storeToken`: Set to `true` if the external identity token should be stored in Keycloak for the user.
- `linkOnly`: Set to `true` to forbid direct login with this identity provider; accounts can only be linked after the user is already authenticated.
- `hideOnLogin`: Set to `true` to hide the identity provider button on the login screen.
- `authenticateByDefault`: Set to `true` to automatically redirect users to this identity provider when they visit the login page.
- `updateProfileFirstLoginMode`: Accepts `"on"`, `"missing"`, or `"off"` only when the Keycloak Admin API exposes this legacy field. If the declared field is absent or null in the response, the operator reports `Ready=False` and `DriftDetected=Unknown` with reason `UnverifiableField` and stops updating that provider. Omit it on these servers and configure the appropriate first broker login flow instead. Quote `"on"` and `"off"` in YAML.
- `firstBrokerLoginFlowAlias`: Specify the authentication flow alias to run on first broker login (e.g. `first broker login`).

## Secrets

Use `configSecretRefs` for values such as OIDC client secrets. Each map key is
the Keycloak provider config key. The Secret key defaults to the same value, or
you can set `secretKey` explicitly.

Keep real Secret values out of Git. Store them with your normal Kubernetes
Secret management flow.

Keycloak can mask sensitive config values as `**********` in API responses.
After a successful write, the operator keeps fingerprints of the submitted config
in the resource's process-local memory, bound to the target URL and remote provider
identity. These fingerprints are never written to CR status or annotations.
Unchanged masked values do not cause repeated PUT requests; a changed Secret value
is applied on the next dependency event or periodic check. After an operator
restart, the provider is updated once to establish the write acknowledgment again.

An out-of-band change to a masked value cannot be detected through that API
response. In `ObserveOnly`, masked declared values produce
`DriftDetected=Unknown` with reason `MaskedConfigUnverifiable`, unless another
visible field already proves drift. No write is made in `ObserveOnly`.

Writes are followed by a detail read. If visible fields still differ, the operator
reports `Ready=False` and `DriftDetected=True` with reason
`IdentityProviderNotConverged` and retries using the failure retry delay.

## Adoption And Lifecycle

Use `managementPolicy: ObserveOnly` when adopting an existing identity provider.
The operator reports whether the provider exists and whether declared fields
match, without changing Keycloak.

Keep the default `deletionPolicy: Orphan` for shared or production providers.
Use `deletionPolicy: Delete` only when the Kubernetes resource fully owns the
remote provider lifecycle.

## Example

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: example-oidc-secret
type: Opaque
stringData:
  clientSecret: not-a-production-secret
---
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakIdentityProvider
metadata:
  name: example-oidc
spec:
  targetRef:
    name: example-keycloak
  realm: example
  alias: example-oidc
  providerId: oidc
  enabled: true
  displayName: Example OIDC
  trustEmail: true
  storeToken: false
  linkOnly: false
  hideOnLogin: false
  authenticateByDefault: false
  firstBrokerLoginFlowAlias: first broker login
  config:
    clientId: example-client
    authorizationUrl: https://idp.example.com/oauth2/authorize
    tokenUrl: https://idp.example.com/oauth2/token
    userInfoUrl: https://idp.example.com/oauth2/userinfo
    defaultScope: openid profile email
  configSecretRefs:
    clientSecret:
      name: example-oidc-secret
```

## Operations

`.status.remoteId` contains the Keycloak internal identity provider ID when
Keycloak returns one.

`kubectl describe keycloakidentityprovider <name>` shows Events for creation,
updates, observe-only drift, missing observe-only providers, and deletion
behavior.
