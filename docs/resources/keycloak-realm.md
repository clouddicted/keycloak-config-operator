# KeycloakRealm

`KeycloakRealm` creates a Keycloak realm and reconciles selected realm fields.

## Fields

| Field | Description |
| --- | --- |
| `spec.targetRef.name` | `KeycloakTarget` name in the same namespace. |
| `spec.realm` | Keycloak realm name. This is the remote lookup key. |
| `spec.displayName` | Optional display name. Reconciled when set. |

## Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakRealm
metadata:
  name: example-realm
spec:
  targetRef:
    name: example-keycloak
  realm: example
  displayName: Example
```

## Behavior

- Creates the realm if it does not exist.
- Updates `displayName` when it differs.
- Does not delete the remote realm when the Kubernetes resource is deleted.

Realm deletion is intentionally not supported because it can remove a large
amount of Keycloak configuration and user data.
