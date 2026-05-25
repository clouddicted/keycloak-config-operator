# Release Notes

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
