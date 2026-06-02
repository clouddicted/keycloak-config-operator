# KeycloakGroup

`KeycloakGroup` manages a top-level group in a Keycloak realm. Use groups when
you want to organize users around teams, applications, or access profiles and
then attach permissions to that group.

Groups are a good fit for human access. Keep application permissions modeled as
roles, then map those roles to groups that represent who should receive them.

## Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakGroup
metadata:
  name: example-users
spec:
  targetRef:
    name: example-keycloak
  realm: example
  name: example-users
  attributes:
    team:
      - platform
```

## Practices

- Create the realm before creating groups in it.
- Use stable group names. Renaming a group means the operator looks for a
  different remote group.
- Keep groups focused on membership and access intent.
- Use attributes only for metadata you really need in Keycloak.
- Prefer separate groups for separate access levels instead of one broad group.

This first group resource manages top-level groups. Nested group management can
be added later without changing the basic top-level workflow.

## Lifecycle Choices

The operator creates the group if it is missing and updates declared attributes
when they differ.

Use `managementPolicy: ObserveOnly` when adopting existing groups. The operator
checks whether the group exists and whether the modeled fields match, but it
does not create or update the remote group.

Remote deletion is opt-in. Keep the default `Orphan` policy for production
groups. Use `Delete` only when the Kubernetes resource clearly owns the group
lifecycle.

```yaml
spec:
  deletionPolicy: Delete
```

## Operations

`.status.remoteId` contains the Keycloak internal group ID. `kubectl describe`
shows Events for create, update, observe-only drift, and delete/orphan
decisions.
