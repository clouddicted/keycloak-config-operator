# KeycloakRole

`KeycloakRole` manages a realm role. Use it for application roles that should be
available consistently wherever the application is deployed.

Roles are usually referenced by applications, clients, mappers, or other
automation. Keeping them in Git makes role creation explicit and reviewable.

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

## Practices

- Create the realm before creating roles inside it.
- Use stable role names. Renaming a role is effectively creating a different
  remote object.
- Keep shared roles conservative and well documented. A role may be used by more
  clients than the manifest author expects.
- Use descriptions for human context in the Keycloak UI.

## Lifecycle Choices

The operator creates the role if it is missing and updates the description when
the declared value differs.

Remote deletion is opt-in. Keep the default `Orphan` policy for shared roles.
Use `Delete` only when the Kubernetes resource clearly owns the role.

```yaml
spec:
  deletionPolicy: Delete
```

## Operations

`.status.remoteId` contains the Keycloak internal role ID. `kubectl describe`
shows Events for create, update, and delete/orphan decisions.
