# KeycloakProtocolMapper

`KeycloakProtocolMapper` manages a protocol mapper attached to a Keycloak client
or client scope.

## Fields

| Field | Description |
| --- | --- |
| `spec.targetRef.name` | `KeycloakTarget` name in the same namespace. |
| `spec.realm` | Realm containing the parent client or client scope. |
| `spec.name` | Mapper name. This is the remote lookup key. |
| `spec.mapperType` | Keycloak protocol mapper type. |
| `spec.protocol` | Protocol used by the mapper. Defaults to `openid-connect`. |
| `spec.config` | Mapper configuration key-value pairs. Desired keys are reconciled and undeclared existing keys are preserved. |
| `spec.parent.type` | `Client` or `ClientScope`. |
| `spec.parent.clientRef.name` | Parent `KeycloakClient` name when `type` is `Client`. |
| `spec.parent.clientScopeRef.name` | Parent `KeycloakClientScope` name when `type` is `ClientScope`. |
| `spec.deletionPolicy` | `Orphan` leaves the remote mapper. `Delete` removes it on resource deletion. |

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
spec:
  parent:
    type: Client
    clientRef:
      name: example-web
```

## Behavior

- Resolves the parent client or client scope first.
- Creates the mapper if it does not exist.
- Updates modeled fields and desired config keys when they differ.
- Preserves existing config keys that are not declared in `spec.config`.
- Deletes the remote mapper only when `deletionPolicy` is `Delete`.
