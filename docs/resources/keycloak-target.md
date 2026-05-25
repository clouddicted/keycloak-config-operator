# KeycloakTarget

`KeycloakTarget` describes how the operator connects to a Keycloak Admin API.
Create it before any other Keycloak resource in the namespace.

## Fields

| Field | Description |
| --- | --- |
| `spec.url` | Base URL of the Keycloak instance. It must be reachable from the operator pod. |
| `spec.adminCredentials` | Simple username/password auth form. Useful for bootstrap and development. |
| `spec.auth` | Explicit auth configuration. Supports `Password`, `ClientCredentials`, and `BootstrapClientCredentials`. |

## Password Auth

Use this for simple bootstrap scenarios.

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakTarget
metadata:
  name: example-keycloak
spec:
  url: https://keycloak.example.com
  adminCredentials:
    secretRef:
      name: keycloak-admin-credentials
      usernameKey: username
      passwordKey: password
```

## Client Credentials

Use this when a confidential Keycloak client already exists and has service
account roles that allow the required Admin API operations.

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakTarget
metadata:
  name: example-keycloak
spec:
  url: https://keycloak.example.com
  auth:
    type: ClientCredentials
    realm: master
    clientCredentials:
      clientId: keycloak-config-operator
      secretRef:
        name: keycloak-operator-client
        clientSecretKey: clientSecret
```

## Bootstrap Client Credentials

Use this for a fresh Keycloak where the service-account client does not exist
yet. The operator uses the bootstrap admin credentials, creates the client,
stores its generated secret, and then authenticates with client credentials.

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakTarget
metadata:
  name: example-keycloak
spec:
  url: https://keycloak.example.com
  auth:
    type: BootstrapClientCredentials
    realm: master
    bootstrapAdminCredentials:
      secretRef:
        name: keycloak-admin-credentials
    clientCredentials:
      clientId: keycloak-config-operator
      secretRef:
        name: keycloak-operator-client
        clientSecretKey: clientSecret
```

## Status

Important conditions and fields:

- `Ready`: target is usable by dependent resources.
- `Authenticated`: the operator can authenticate to Keycloak.
- `BootstrapReady`: bootstrap client credentials are available when bootstrap is configured.
- `status.activeAuthMethod`: auth method currently used by the target.
- `status.clientCredentialsSecretRef`: generated client credentials Secret when bootstrap is used.
