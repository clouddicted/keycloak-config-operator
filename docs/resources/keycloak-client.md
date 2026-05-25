# KeycloakClient

`KeycloakClient` manages a Keycloak client in a realm. It supports public and
confidential clients.

## Fields

| Field | Description |
| --- | --- |
| `spec.targetRef.name` | `KeycloakTarget` name in the same namespace. |
| `spec.realm` | Realm containing the client. |
| `spec.clientId` | Keycloak client ID. This is the remote lookup key. |
| `spec.clientType` | `Public` or `Confidential`. Defaults to `Public`. |
| `spec.managementPolicy` | `Reconcile` updates drift. `ObserveOnly` reports drift without changing Keycloak. |
| `spec.deletionPolicy` | `Orphan` leaves the remote client. `Delete` removes it on resource deletion. |
| `spec.displayName` | Stored as the Keycloak client name. |
| `spec.secretRef` | Secret containing the client secret for confidential clients. |
| `spec.redirectUris` | Redirect URI list. |
| `spec.webOrigins` | Web origin list. |

## Public Client Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakClient
metadata:
  name: example-web
spec:
  targetRef:
    name: example-keycloak
  realm: example
  clientId: example-web
  clientType: Public
  displayName: Example Web
  redirectUris:
    - https://app.example.com/*
  webOrigins:
    - https://app.example.com
```

## Confidential Client Example

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakClient
metadata:
  name: example-service
spec:
  targetRef:
    name: example-keycloak
  realm: example
  clientId: example-service
  clientType: Confidential
  secretRef:
    name: example-service-client-secret
    secretKey: clientSecret
```

## Behavior

- Creates the client if it does not exist.
- Updates modeled fields when `managementPolicy` is `Reconcile`.
- Reports drift without changing Keycloak when `managementPolicy` is `ObserveOnly`.
- Deletes the remote client only when `deletionPolicy` is `Delete`.
