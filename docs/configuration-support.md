# Configuration Support Matrix

This page documents the Keycloak configuration contract managed by the operator.
It intentionally covers only fields exposed in the CRDs, not the full Keycloak
Admin API.

Status meanings:

- Supported: reconciled by the operator and covered by tests.
- Create-only: used when creating the remote object but not reconciled on existing objects.
- Partial: supported with documented limits.
- Unsupported: not exposed or not reconciled by this operator.

## Entity Overview

| Entity | CRD | Create | Update | Delete | E2E tested | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Keycloak target | `KeycloakTarget` | Observe only | Observe only | Not applicable | Yes | Verifies credentials and connectivity. |
| Realm | `KeycloakRealm` | Yes | Partial | No | Yes | Reconciles `spec.displayName` when set. |
| Client | `KeycloakClient` | Yes | Yes | Optional | Yes | Delete requires `spec.deletionPolicy: Delete`. |
| Realm role | `KeycloakRole` | Yes | Yes | Optional | Yes | Delete requires `spec.deletionPolicy: Delete`. |
| Client scope | `KeycloakClientScope` | Yes | Yes | Optional | Yes | Delete requires `spec.deletionPolicy: Delete`. |
| Protocol mapper | `KeycloakProtocolMapper` | Yes | Yes | Optional | Yes | Delete requires `spec.deletionPolicy: Delete`. Parent must be a managed client or client scope. |

## KeycloakTarget

| Field | Status | Notes |
| --- | --- | --- |
| `spec.url` | Supported | Base URL used for Keycloak Admin API calls. |
| `spec.auth` | Supported | Explicit authentication method. Supports `Password`, `ClientCredentials`, and `BootstrapClientCredentials`. |
| `spec.adminCredentials` | Supported | References admin credentials. |
| `spec.adminCredentials.secretRef.name` | Supported | Secret name containing credentials. |
| `spec.adminCredentials.secretRef.namespace` | Supported | Optional; defaults to the `KeycloakTarget` namespace. |
| `spec.adminCredentials.secretRef.usernameKey` | Supported | Optional; defaults to `username`. |
| `spec.adminCredentials.secretRef.passwordKey` | Supported | Optional; defaults to `password`. |

`spec.adminCredentials` is the simple legacy password form. New deployments can
use `spec.auth.type: ClientCredentials` with a pre-created service-account
client, or `spec.auth.type: BootstrapClientCredentials` to let the operator use
admin credentials once, create the service-account client, and store its client
secret in Kubernetes.

## KeycloakRealm

| Field | Status | Notes |
| --- | --- | --- |
| `spec.targetRef` | Supported | References a `KeycloakTarget` in the same namespace. |
| `spec.realm` | Supported | Realm name and remote lookup key. |
| `spec.managementPolicy` | Supported | `Reconcile` or `ObserveOnly`; defaults to `Reconcile`. |
| `spec.displayName` | Supported | Reconciled when set. |

## KeycloakClient

| Field | Status | Notes |
| --- | --- | --- |
| `spec.targetRef` | Supported | References a `KeycloakTarget` in the same namespace. |
| `spec.realm` | Supported | Realm containing the client. |
| `spec.clientId` | Supported | Client ID and remote lookup key. |
| `spec.clientType` | Supported | `Public` or `Confidential`; defaults to `Public`. |
| `spec.managementPolicy` | Supported | `Reconcile` or `ObserveOnly`; defaults to `Reconcile`. |
| `spec.deletionPolicy` | Supported | `Orphan` or `Delete`; defaults to `Orphan`. |
| `spec.displayName` | Supported | Reconciled to Keycloak client `name`. |
| `spec.rootUrl` | Supported | Reconciled when set. |
| `spec.baseUrl` | Supported | Reconciled when set. |
| `spec.adminUrl` | Supported | Reconciled when set. |
| `spec.standardFlowEnabled` | Supported | Reconciled when set. |
| `spec.directAccessGrantsEnabled` | Supported | Reconciled when set. |
| `spec.serviceAccountsEnabled` | Supported | Reconciled when set. Intended for confidential clients. |
| `spec.secretRef` | Supported | Required for confidential clients. |
| `spec.secretRef.name` | Supported | Secret name containing the client secret. |
| `spec.secretRef.namespace` | Supported | Optional; defaults to the client resource namespace. |
| `spec.secretRef.secretKey` | Supported | Optional key name containing the secret value. |
| `spec.redirectUris` | Supported | Reconciled list of redirect URIs. |
| `spec.webOrigins` | Supported | Reconciled list of web origins. |
| `spec.defaultClientScopes` | Supported | Reconciled list of default client scope assignments when set. |
| `spec.optionalClientScopes` | Supported | Reconciled list of optional client scope assignments when set. |

## KeycloakRole

| Field | Status | Notes |
| --- | --- | --- |
| `spec.targetRef` | Supported | References a `KeycloakTarget` in the same namespace. |
| `spec.realm` | Supported | Realm containing the role. |
| `spec.name` | Supported | Role name and remote lookup key. |
| `spec.description` | Supported | Reconciled when set. |
| `spec.deletionPolicy` | Supported | `Orphan` or `Delete`; defaults to `Orphan`. |

## KeycloakClientScope

| Field | Status | Notes |
| --- | --- | --- |
| `spec.targetRef` | Supported | References a `KeycloakTarget` in the same namespace. |
| `spec.realm` | Supported | Realm containing the client scope. |
| `spec.name` | Supported | Client scope name and remote lookup key. |
| `spec.description` | Supported | Reconciled when set. |
| `spec.protocol` | Supported | Defaults to `openid-connect`. |
| `spec.deletionPolicy` | Supported | `Orphan` or `Delete`; defaults to `Orphan`. |

## KeycloakProtocolMapper

| Field | Status | Notes |
| --- | --- | --- |
| `spec.targetRef` | Supported | References a `KeycloakTarget` in the same namespace. |
| `spec.realm` | Supported | Realm containing the parent object. |
| `spec.name` | Supported | Mapper name and remote lookup key. |
| `spec.mapperType` | Supported | Keycloak protocol mapper type. |
| `spec.protocol` | Supported | Defaults to `openid-connect`. |
| `spec.config` | Partial | Desired keys are reconciled; undeclared existing keys are preserved. |
| `spec.deletionPolicy` | Supported | `Orphan` or `Delete`; defaults to `Orphan`. |
| `spec.parent` | Supported | Selects a parent client or client scope. |
| `spec.parent.type` | Supported | `Client` or `ClientScope`. |
| `spec.parent.clientRef.name` | Supported | Required when parent type is `Client`. |
| `spec.parent.clientScopeRef.name` | Supported | Required when parent type is `ClientScope`. |

## Adding New Fields

When adding or changing a CRD field:

1. Implement reconciliation behavior.
2. Add unit tests for the field.
3. Add or update kind e2e coverage when the behavior affects Keycloak state.
4. Update this support matrix in the same commit.
