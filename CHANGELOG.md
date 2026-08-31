# Release Notes

## Unreleased

## v0.5.0 - 2026-08-31

### Highlights

- Added periodic drift reconciliation for every supported custom resource,
  running every 600 seconds by default.
- Added dependency-triggered reconciliation when referenced Secrets, targets,
  clients, client roles, groups, realm roles, or client scopes change.
- Staggered the first periodic check for each resource to avoid a burst of
  Keycloak Admin API requests after operator startup.
- Avoided duplicate status writes and Kubernetes Events when a periodic check
  finds no changes.

### Configuration

- Added the Helm value `reconciliationIntervalSeconds` and the equivalent plain
  Deployment variable `RECONCILIATION_INTERVAL_SECONDS`.
- Set either configuration to `0` to disable periodic checks while retaining
  event-driven and failure-retry reconciliation.

### Documentation

- Added a reconciliation guide covering triggers, dependency fan-out, timing,
  namespace behavior, retries, and interval configuration.
- Updated the usage and resource guides to describe continuous reconciliation.

### Testing

- Added unit coverage for interval validation, deterministic staggering,
  no-change status suppression, timer registration, and disabled timers.
- Added unit coverage for dependency indexing, fan-out, duplicate suppression,
  natural-key references, and concurrent deletion handling.
- Extended the kind e2e scenario to verify periodic repair of out-of-band realm
  drift and reconciliation after Secret and client dependency changes.

### Upgrade Notes

- CRDs remain served as `keycloak.clouddicted.com/v1beta1`; this release does not
  change their schemas.
- Apply the updated RBAC before starting v0.5.0. The operator now requires
  `list` and `watch` access to Secrets in watched namespaces to detect Secret
  changes promptly.
- Existing installations begin periodic reconciliation at the 10-minute
  default. Set the interval to `0` to retain event-only successful-state checks.

## v0.4.0 - 2026-06-02

### Highlights

- Added `KeycloakClientRole` for managing roles owned by a specific Keycloak
  client, including observe-only mode and opt-in remote deletion.
- Added `KeycloakGroup` for managing top-level groups and optional group
  attributes.
- Added `KeycloakGroupRoleMapping` for assigning realm roles or client roles to
  groups.

### Documentation

- Added a `KeycloakClientRole` resource guide and API reference entry.
- Added a `KeycloakGroup` resource guide and API reference entry.
- Added a `KeycloakGroupRoleMapping` resource guide and API reference entry.
- Clarified current support gaps so users can distinguish supported CRD fields
  from broader Keycloak realm import/export settings.

### Testing

- Added unit and kind e2e coverage that verifies client role creation, status,
  and deletion through the Keycloak Admin API.
- Added unit and kind e2e coverage for group creation, status, attributes, and
  deletion.
- Added unit and kind e2e coverage for group role mapping assignment and
  removal.

### Release

- Bumped installation examples and release metadata to `v0.4.0`.

### Upgrade Notes

- CRDs are still served as `keycloak.clouddicted.com/v1beta1`.
- Upgrade the CRDs before applying `KeycloakClientRole`, `KeycloakGroup`, or
  `KeycloakGroupRoleMapping` resources.
- Remote deletion remains opt-in. New resources continue to default to
  `deletionPolicy: Orphan`.

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
