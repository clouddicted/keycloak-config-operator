# KeycloakClientScope

`KeycloakClientScope` manages a realm-level client scope.

## Fields

| Field | Description |
| --- | --- |
| `spec.targetRef.name` | `KeycloakTarget` name in the same namespace. |
| `spec.realm` | Realm containing the client scope. |
| `spec.name` | Keycloak client scope name. This is the remote lookup key. |
| `spec.description` | Optional client scope description. |
| `spec.protocol` | Protocol used by the scope. Defaults to `openid-connect`. |
| `spec.deletionPolicy` | `Orphan` leaves the remote client scope. `Delete` removes it on resource deletion. |

## Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakClientScope
metadata:
  name: example-profile
spec:
  targetRef:
    name: example-keycloak
  realm: example
  name: example-profile
  description: Example profile client scope
```

## Behavior

- Creates the client scope if it does not exist.
- Updates modeled fields when they differ.
- Deletes the remote client scope only when `deletionPolicy` is `Delete`.

Create client scopes before protocol mappers that reference them.
