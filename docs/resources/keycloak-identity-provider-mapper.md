# KeycloakIdentityProviderMapper

`KeycloakIdentityProviderMapper` manages external identity claim, username,
attribute, and role mappings attached to an identity provider.

Use it when users authenticating through an external OIDC, SAML, or social provider
need their claims, attributes, or groups mapped into Keycloak user profiles or roles.

## Provider Reference And Identity

Each mapper belongs to a specific identity provider instance within a realm:

- `realm`: Keycloak realm containing the identity provider.
- `name`: Remote mapper name and lookup key under the identity provider.
- `identityProviderRef.name`: Name of the `KeycloakIdentityProvider` custom resource in the same namespace.
- `identityProviderRef.alias`: (Optional) Remote identity provider alias in Keycloak if it differs from the custom resource name.

The operator watches the parent `KeycloakIdentityProvider`. If the parent provider
is not yet present in Keycloak, the mapper enters a `Ready=False` state with reason
`IdentityProviderMissing` and automatically reconciles once the provider is created.

## Mapper Types And Config

`identityProviderMapper` specifies the Keycloak mapper provider ID. Common mapper types
include:

- `oidc-user-attribute-idp-mapper`: Maps external token claims to Keycloak user attributes.
- `oidc-role-idp-mapper`: Maps token claims or roles to Keycloak realm or client roles.
- `oidc-username-idp-mapper`: Maps a claim to the user's Keycloak username.
- `saml-user-attribute-idp-mapper`: Maps SAML assertion attributes to user attributes.
- `saml-role-idp-mapper`: Maps SAML assertion attributes to Keycloak roles.

Config keys correspond directly to Keycloak Admin API attributes. Good practice is to
inspect or configure the mapper in Keycloak once, then declare the required keys in
`spec.config`.

The operator reconciles declared keys in `spec.config` while preserving existing
undeclared keys in Keycloak.

## Attribute Mapper Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakIdentityProviderMapper
metadata:
  name: example-oidc-email-claim
spec:
  targetRef:
    name: example-keycloak
  realm: example
  name: email-claim
  identityProviderRef:
    name: example-oidc
  identityProviderMapper: oidc-user-attribute-idp-mapper
  config:
    claim: email
    user.attribute: email
```

## Role Mapper Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakIdentityProviderMapper
metadata:
  name: example-oidc-admin-role
spec:
  targetRef:
    name: example-keycloak
  realm: example
  name: admin-role
  identityProviderRef:
    name: example-oidc
  identityProviderMapper: oidc-role-idp-mapper
  config:
    claim: groups
    claim.value: /platform-admins
    role: admin
```

## Adoption And Lifecycle

- `managementPolicy: ObserveOnly`: Checks whether the mapper exists and detects modeled drift without modifying Keycloak.
- `deletionPolicy: Orphan` (default): Leaves the remote mapper in Keycloak when the Kubernetes resource is deleted.
- `deletionPolicy: Delete`: Removes the remote mapper via Keycloak's Admin API when the custom resource is deleted.

## Operations

`.status.remoteId` contains the remote mapper UUID once observed or created.

`kubectl describe keycloakidentityprovidermapper <name>` shows Kubernetes events for
creation, updates, drift detection, and deletion.

