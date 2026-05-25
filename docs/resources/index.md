# Resources

The operator exposes one CRD for each supported Keycloak concept. All resources
are namespace-scoped.

## Resource Flow

Create a `KeycloakTarget` first. Every managed Keycloak object references that
target through `spec.targetRef.name`.

| Resource | Purpose |
| --- | --- |
| `KeycloakTarget` | Connection and authentication settings for a Keycloak instance. |
| `KeycloakRealm` | Realm creation and selected realm fields. |
| `KeycloakClient` | Public and confidential clients. |
| `KeycloakRole` | Realm roles. |
| `KeycloakClientScope` | Realm-level client scopes. |
| `KeycloakProtocolMapper` | Protocol mappers attached to clients or client scopes. |

## Common Patterns

- Use the same namespace for related resources.
- Apply `KeycloakTarget` first and wait for `Ready=True`.
- Create a realm before creating clients, roles, scopes, or mappers inside it.
- Keep `deletionPolicy: Orphan` unless you intentionally want the operator to
  delete remote Keycloak objects.

See the [generated API reference](../api-reference.md) for the full CRD schema.
