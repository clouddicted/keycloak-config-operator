# KeycloakTarget

`KeycloakTarget` tells the operator how to reach a Keycloak Admin API. Create it
before any resource that manages a realm, client, role, scope, or mapper.

Prefer the in-cluster Kubernetes Service URL when Keycloak runs in the same
cluster. The operator runs inside Kubernetes, so an internal URL avoids public
Ingress routing, external DNS, public TLS termination, and firewall assumptions.
Use the scheme and port exposed by your Keycloak Service, for example
`http://keycloak.keycloak.svc.cluster.local:8080`.

## Recommended Bootstrap Flow

For a fresh Keycloak installation, start with bootstrap client credentials. The
operator uses an admin username and password once, creates a confidential client
for itself, stores the generated client secret in Kubernetes, and then switches
to client credentials for normal reconciliation.

This keeps the initial setup simple while avoiding long-term use of admin
password authentication by the operator.

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakTarget
metadata:
  name: example-keycloak
spec:
  url: http://keycloak.keycloak.svc.cluster.local:8080
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

After bootstrap, the target status points to the generated Secret through
`status.clientCredentialsSecretRef`. You can then remove the admin credentials
from the target spec and use direct client credentials.

## Existing Service Account Client

Use direct client credentials when a suitable confidential client already exists
in Keycloak.

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakTarget
metadata:
  name: example-keycloak
spec:
  url: http://keycloak.keycloak.svc.cluster.local:8080
  auth:
    type: ClientCredentials
    realm: master
    clientCredentials:
      clientId: keycloak-config-operator
      secretRef:
        name: keycloak-operator-client
        clientSecretKey: clientSecret
```

This is the preferred steady-state mode for production because the credential is
scoped to a client instead of a human admin account.

## Password Auth

Password auth is still useful for local development, throwaway environments, or
simple bootstrap scenarios.

```yaml
apiVersion: keycloak.clouddicted.com/v1beta1
kind: KeycloakTarget
metadata:
  name: example-keycloak
spec:
  url: http://keycloak.keycloak.svc.cluster.local:8080
  adminCredentials:
    secretRef:
      name: keycloak-admin-credentials
      usernameKey: username
      passwordKey: password
```

Avoid this mode as the long-term production setup when client credentials are
available.

## Operational Notes

- The URL must be reachable from the operator pod, not only from your laptop.
- Prefer the Keycloak Service DNS name over a public hostname when Keycloak is
  deployed in the same cluster.
- Keep credentials in Kubernetes Secrets and grant Secret access only to the
  namespaces the operator watches.
- Wait for `Ready=True` before applying dependent resources.
- Use `kubectl describe keycloaktarget <name>` to inspect authentication and
  bootstrap Events.
- `Authenticated=False` means the operator reached the Secret but Keycloak
  rejected the credentials or the endpoint connection.
