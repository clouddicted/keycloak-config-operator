# Compatibility

This page documents the Keycloak server versions this operator is tested with.
It does not replace the Keycloak project's own supported-platform policy.

## Policy

- The default kind e2e suite runs against the current tested Keycloak version.
- Release and manual compatibility runs also test one previous-minor version as
  a smoke check.
- Older Keycloak versions can work, but they are unsupported unless listed here.
- We do not test every archived Keycloak release. The Admin API surface is large,
  and testing every release would slow delivery without creating a useful support
  promise.

## Development Compatibility

<!-- BEGIN GENERATED DEVELOPMENT COMPATIBILITY -->
| Branch | Keycloak version | Status | Test scope | Notes |
| --- | --- | --- | --- | --- |
| `develop` | `26.6.2` | Default tested | PR, branch, tag, manual, and latest-version kind e2e | Default version from `tests/kind/keycloak-versions.json`. |
| `develop` | `26.5.3` | Compatibility tested | Tag, manual, and new-minor latest-version kind e2e | Previous-minor smoke coverage. |
<!-- END GENERATED DEVELOPMENT COMPATIBILITY -->

## Tested Versions

| Operator version | Keycloak version | Status | Test scope | Notes |
| --- | --- | --- | --- | --- |
| `0.7.0` | `26.6.2` | Supported | PR, branch, tag, and manual kind e2e | Default `KEYCLOAK_VERSION`. |
| `0.7.0` | `26.5.3` | Compatibility tested | Tag and manual kind e2e | Previous-minor smoke coverage. |
| `0.7.0` | `<26.5` | Unsupported | Not tested | Upgrade Keycloak or validate locally before use. |

## Latest Stable Version Automation

The `Latest Keycloak compatibility` workflow checks the latest stable upstream
release every night and can also test an exact version through a manual workflow
dispatch. It validates only immutable version tags such as `26.7.4`; mutable
`latest`, prerelease, and nightly tags do not create compatibility claims.

When a newer stable release passes the full kind e2e suite, automation creates or
updates one pull request from `automation/keycloak-latest` into `develop`. Newer
passing patches replace older unmerged patches in that pull request. A new minor
release is tested together with the latest patch of the immediately preceding
minor. Failed candidates leave the newest passing proposal unchanged and update
one diagnostic issue for that version.

Merging the pull request updates the development test defaults. A nightly pass is
reported as compatibility-tested; `Supported` remains a release decision. The
workflow never commits directly to `develop` or rewrites documentation for an
already published operator version.

## Local Compatibility Testing

Run the same e2e suite against a specific Keycloak image tag:

```bash
KEYCLOAK_VERSION=26.6.2 .venv/bin/python tests/kind/e2e.py prepare
KEYCLOAK_VERSION=26.6.2 .venv/bin/python tests/kind/e2e.py test
.venv/bin/python tests/kind/e2e.py cleanup
```

The fixture image is `quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}`.

Deployment startup has a separate four-minute budget, configurable with
`E2E_DEPLOYMENT_TIMEOUT` (default `240s`). `E2E_READY_TIMEOUT` remains `60s` for
CRD and resource readiness checks. This allows a cold Keycloak image to start
without extending ordinary reconciliation waits.

The suite checks that groups, identity providers, and clients settle, then
observes multiple timer cycles with no configuration writes while the resources
still exist. It repeats this check after restarting the operator. Authentication
POSTs and periodic GETs remain expected. Client fixtures are deleted before
their required scopes.

## References

- Keycloak downloads: https://www.keycloak.org/downloads
- Keycloak supported configurations: https://www.keycloak.org/server/supported-configurations
- Keycloak release notes: https://www.keycloak.org/docs/latest/release_notes/
