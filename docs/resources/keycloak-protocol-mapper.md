# KeycloakProtocolMapper

`KeycloakProtocolMapper` manages a mapper attached to a client or client scope.
Use it when token claims or protocol behavior should be declared alongside the
application configuration.

Mappers are powerful and easy to overuse. Prefer a mapper on a client scope when
several clients need the same claim. Use a mapper directly on a client when the
claim is specific to that one client.

## Parent Choice

Attach to a `ClientScope` when the mapper should be reusable.

Attach to a `Client` when the mapper belongs to one application only.

Create the parent first. The operator resolves the parent object before it
creates or updates the mapper.

## Client Scope Mapper Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakProtocolMapper
metadata:
  name: example-profile-email
spec:
  targetRef:
    name: example-keycloak
  realm: example
  name: email
  mapperType: oidc-usermodel-property-mapper
  parent:
    type: ClientScope
    clientScopeRef:
      name: example-profile
  config:
    user.attribute: email
    claim.name: email
    jsonType.label: String
    id.token.claim: "true"
    access.token.claim: "true"
    userinfo.token.claim: "true"
```

## Client Mapper Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakProtocolMapper
metadata:
  name: example-web-audience
spec:
  targetRef:
    name: example-keycloak
  realm: example
  name: audience
  mapperType: oidc-audience-mapper
  parent:
    type: Client
    clientRef:
      name: example-web
  config:
    included.client.audience: example-web
    access.token.claim: "true"
```

## Config Practices

Mapper types and config keys are Keycloak Admin API values. The operator does
not try to invent a friendlier abstraction over them, because the valid keys
depend on the mapper type.

Good practice is to create or inspect the mapper in a non-production Keycloak
first, then move the relevant Admin API values into the manifest.

The operator reconciles declared config keys and preserves undeclared existing
keys. This makes adoption safer, but it also means removing a key from the
manifest does not necessarily remove it from Keycloak.

## Lifecycle Choices

Remote deletion is opt-in. Use `Delete` for mappers that are fully owned by the
resource. Keep `Orphan` for shared or manually managed mappers.

## Operations

`.status.remoteId` contains the Keycloak internal mapper ID. `kubectl describe`
shows Events for create, update, and delete/orphan decisions.
