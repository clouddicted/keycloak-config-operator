# KeycloakClientRole

`KeycloakClientRole` manages a role owned by a Keycloak client. Use it for
application-specific permissions that should stay scoped to one client instead
of becoming realm-wide roles.

Client roles are useful when a service or application exposes its own
authorization model. They keep permissions close to the client that uses them
and make future service-account or group role mappings easier to review.

## Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakClientRole
metadata:
  name: example-web-reader
spec:
  targetRef:
    name: example-keycloak
  realm: example
  clientRef:
    name: example-web
  name: reader
  description: Example web client reader role
```

## Practices

- Create the realm and client before creating roles under that client.
- Use client roles for permissions that belong to a single application.
- Use realm roles for broad permissions shared across many clients.
- Keep role names stable. Renaming a role creates a different remote object.
- Use descriptions to make the role understandable in the Keycloak UI.

`clientRef.name` refers to the managed `KeycloakClient` name and is used as the
Keycloak client ID during reconciliation.

## Lifecycle Choices

The operator creates the client role if it is missing and updates the
description when the declared value differs.

Use `managementPolicy: ObserveOnly` when adopting existing client roles. The
operator checks whether the role exists and whether the modeled fields match,
but it does not create or update the remote role.

Remote deletion is opt-in. Keep the default `Orphan` policy for shared or
production roles. Use `Delete` when the Kubernetes resource clearly owns the
role.

```yaml
spec:
  deletionPolicy: Delete
```

## Operations

`.status.remoteId` contains the Keycloak internal client role ID.
`kubectl describe` shows Events for create, update, observe-only drift, and
delete/orphan decisions.
