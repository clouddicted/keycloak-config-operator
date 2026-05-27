# Release Notes

## Unreleased

### Highlights

- Added `KeycloakClientRole` for managing roles owned by a specific Keycloak
  client, including observe-only mode and opt-in remote deletion.

### Documentation

- Added a `KeycloakClientRole` resource guide and API reference entry.

### Testing

- Added unit and kind e2e coverage that verifies client role creation, status,
  and deletion through the Keycloak Admin API.

## v0.3.0 - 2026-05-28

### Highlights

- Added basic `KeycloakIdentityProvider` support for creating, observing,
  updating, and optionally deleting identity provider instances.
- Added Secret-backed identity provider config through `spec.configSecretRefs`
  for values such as OIDC client secrets.
- Improved validation feedback for invalid custom resource specs.
- Standardized `Ready` and `DriftDetected` condition style across managed
  Keycloak resources.
- Extended `KeycloakClient` with additional common settings for URLs, flows,
  service accounts, and scope assignments.

### Documentation

- Added a `KeycloakIdentityProvider` resource guide and API reference entry.
- Updated the configuration support matrix and examples for identity provider
  secret-backed config.
- Bumped installation examples and release metadata to `v0.3.0`.

### Testing

- Added unit coverage for identity provider reconciliation, validation, secret
  loading, drift detection, and deletion behavior.
- Extended kind e2e tests to create an identity provider and verify it through
  the Keycloak Admin API.

### Upgrade Notes

- CRDs are still served as `keycloak.clouddicted.com/v1beta1`.
- Upgrade the CRDs before applying `KeycloakIdentityProvider` resources or
  resources using new `KeycloakClient` fields.
- Keep sensitive identity provider config in Kubernetes Secrets and reference
  it with `spec.configSecretRefs`.

## v0.2.0 - 2026-05-25

### Highlights

- Added `KeycloakTarget` client credentials authentication.
- Added bootstrap client credentials flow for fresh Keycloak installations.
- Added common `KeycloakClient` settings:
  - client URLs: `rootUrl`, `baseUrl`, `adminUrl`
  - flow toggles: `standardFlowEnabled`, `directAccessGrantsEnabled`
  - service-account toggle: `serviceAccountsEnabled`
  - scope assignments: `defaultClientScopes`, `optionalClientScopes`
- Added `status.remoteId` for managed Keycloak objects with stable internal IDs.
- Added Kubernetes Events for important lifecycle actions such as create, update,
  drift detection, bootstrap completion, delete, and orphan decisions.
- Added update support for realms and managed delete support for clients, roles,
  client scopes, and protocol mappers through `deletionPolicy: Delete`.

### Documentation

- Added practical resource guides for every CRD.
- Added generated CRD API reference using `mkdocs-crd-viewer`.
- Added usage and getting-started guides.
- Added versioned documentation publishing for `develop`, tags, and `latest`.
- Updated examples to prefer in-cluster Keycloak Service URLs.

### CI And Release

- Added GitHub Actions jobs for Python checks, Helm checks, docs builds, image
  builds, kind e2e tests, release publishing, Helm chart publishing, and
  versioned docs publishing.
- Added compatibility e2e coverage for the previous tested Keycloak minor
  version during tag releases and manual workflow runs.

### Fixes

- Fixed Kopf CRD discovery RBAC for cluster-scoped CRD watches.
- Improved retry handling and status reporting for failed reconciliations.
- Reduced framework-specific log noise in operator logs.
- Fixed `KeycloakClient` CRD scope assignment arrays so they are accepted by
  Kubernetes structural schema validation. Duplicate scope names are rejected by
  the operator during reconciliation instead of by CRD schema validation.

### Upgrade Notes

- CRDs are still served as `keycloak.clouddicted.com/v1beta1`.
- Upgrade the CRDs before applying resources that use new `KeycloakClient`
  fields.
- Remote deletion remains opt-in. Existing resources continue to default to
  `deletionPolicy: Orphan`.
- For production targets, prefer `ClientCredentials` or
  `BootstrapClientCredentials` over long-term password authentication.

## v0.1.0 - 2026-05-24

### Highlights

- Added the first public beta CRDs under `keycloak.clouddicted.com/v1beta1`.
- Added reconciliation for Keycloak targets, realms, clients, realm roles,
  client scopes, and protocol mappers.
- Added optional client deletion through `deletionPolicy: Delete`; other managed
  resources default to preserving remote Keycloak state.
- Added Kubernetes install manifests and a Helm chart for operator installation.
- Added namespace watch configuration for all namespaces or selected namespaces.
- Added kind e2e tests that build the operator image, load it into kind, deploy
  Keycloak, apply sample resources, and verify the resulting Keycloak
  configuration through the Admin API.

### Documentation

- Added README installation and development instructions.
- Added configuration support and Keycloak compatibility documentation.
- Added contributor guidance, security policy, Apache-2.0 license, and notice.

### CI And Release

- Added GitHub Actions for linting, unit tests, Helm validation, image builds,
  kind e2e tests, release publishing, and GitHub Pages documentation.

### Upgrade Notes

- This is the first released version. There is no upgrade path from an earlier
  release.
