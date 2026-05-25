# KeycloakRealm

`KeycloakRealm` creates a realm and reconciles the small set of realm fields the
operator currently owns.

Use it to make environment setup repeatable. For example, a test cluster can
create the realm before clients, roles, scopes, and mappers are applied.

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

## Practices

- Create the `KeycloakTarget` first and wait until it is ready.
- Keep the Kubernetes resource name close to the realm name. It makes Events and
  `kubectl get` output easier to read.
- Declare the realm before resources that live inside it.
- Use one realm per isolated application boundary or environment, not as a
  replacement for normal Keycloak authorization design.

## Lifecycle

The operator creates the realm if it does not exist and updates the modeled
fields when they drift.

For existing realms, use `managementPolicy: ObserveOnly` during adoption if you
want to verify the desired manifest before allowing the operator to change
Keycloak. In observe-only mode, missing realms and modeled drift are reported in
`.status.conditions` and Events, but the remote realm is not created or updated.

Realm deletion is intentionally not supported. Deleting a realm can remove a
large amount of configuration and user data, so that action should stay an
explicit Keycloak administration task.
