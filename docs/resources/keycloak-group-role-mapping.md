# KeycloakGroupRoleMapping

`KeycloakGroupRoleMapping` assigns one role to one Keycloak group. Use it to
connect group membership to realm roles or client roles that are already managed
by the operator.

One resource represents one assignment. This keeps ownership clear: deleting the
resource with `deletionPolicy: Delete` removes only that declared assignment and
does not touch other roles on the group.

## Realm Role Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakGroupRoleMapping
metadata:
  name: example-users-admin
spec:
  targetRef:
    name: example-keycloak
  realm: example
  groupRef:
    name: example-users
  role:
    type: RealmRole
    roleRef:
      name: example-admin
```

## Client Role Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakGroupRoleMapping
metadata:
  name: example-users-web-reader
spec:
  targetRef:
    name: example-keycloak
  realm: example
  groupRef:
    name: example-users
  role:
    type: ClientRole
    clientRef:
      name: example-web
    roleRef:
      name: reader
```

## Practices

- Create the realm, group, and role before creating the mapping.
- Use one mapping resource per role assignment.
- Keep names descriptive enough to show the group and role being connected.
- Prefer group mappings for human access; prefer service accounts for
  machine-to-machine access.
- Avoid using one broad group for unrelated permissions.

`groupRef.name`, `role.roleRef.name`, and `role.clientRef.name` refer to
operator-managed resources in the same namespace. The operator uses those names
as Keycloak lookup keys.

## Lifecycle Choices

The operator assigns the role when the mapping is missing. It does not remove
roles that are assigned outside this resource.

Use `managementPolicy: ObserveOnly` when adopting existing mappings. The
operator checks whether the assignment exists, but it does not add it.

Remote removal is opt-in:

```yaml
spec:
  deletionPolicy: Delete
```

With `Delete`, the operator removes only this declared assignment. It does not
delete the group, role, client, or any other assignments.

## Operations

Status includes the Keycloak IDs used for the assignment:

- `.status.groupRemoteId`
- `.status.roleRemoteId`
- `.status.clientRemoteId` for client role mappings

`kubectl describe` shows Events when a mapping is assigned, missing in
observe-only mode, removed, or orphaned.
