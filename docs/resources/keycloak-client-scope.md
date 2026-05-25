# KeycloakClientScope

`KeycloakClientScope` manages a realm-level client scope. Use scopes to define
reusable protocol behavior that can be shared by multiple clients.

Client scopes are especially useful when several applications need the same
claims or mapper setup. Model the scope once, then attach mappers to it.

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

## Practices

- Create client scopes before protocol mappers that reference them.
- Prefer small, purpose-specific scopes over broad scopes that mix unrelated
  claims.
- Use clear names that describe the claims or behavior the scope provides.
- Keep shared scopes stable. Changes can affect every client that uses them.

## Lifecycle Choices

The operator creates the client scope if it is missing and updates the modeled
fields when they drift.

Use `managementPolicy: ObserveOnly` during adoption if a scope already exists or
is shared. The operator reports missing scopes and modeled drift without
changing Keycloak.

Remote deletion is opt-in. Keep `Orphan` for shared scopes. Use `Delete` for
test scopes or scopes that are owned by one application lifecycle.

## Operations

`.status.remoteId` contains the Keycloak internal client scope ID. This ID is
also used by protocol mapper operations under the hood.
