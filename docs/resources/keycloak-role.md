# KeycloakRole

`KeycloakRole` manages a realm role.

## Fields

| Field | Description |
| --- | --- |
| `spec.targetRef.name` | `KeycloakTarget` name in the same namespace. |
| `spec.realm` | Realm containing the role. |
| `spec.name` | Keycloak role name. This is the remote lookup key. |
| `spec.description` | Optional role description. |
| `spec.deletionPolicy` | `Orphan` leaves the remote role. `Delete` removes it on resource deletion. |

## Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakRole
metadata:
  name: example-admin
spec:
  targetRef:
    name: example-keycloak
  realm: example
  name: example-admin
  description: Example administrator role
```

## Delete The Remote Role

Remote deletion is opt-in.

```yaml
spec:
  deletionPolicy: Delete
```

## Behavior

- Creates the role if it does not exist.
- Updates the description when it differs and is configured.
- Deletes the remote role only when `deletionPolicy` is `Delete`.
