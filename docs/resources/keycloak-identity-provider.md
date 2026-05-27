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

## Secrets

Use `configSecretRefs` for values such as OIDC client secrets. Each map key is
the Keycloak provider config key. The Secret key defaults to the same value, or
you can set `secretKey` explicitly.

Keep real Secret values out of Git. Store them with your normal Kubernetes
Secret management flow.

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
