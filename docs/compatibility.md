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

## Tested Versions

| Operator version | Keycloak version | Status | Test scope | Notes |
| --- | --- | --- | --- | --- |
| `0.3.x` | `26.6.2` | Supported | PR, branch, tag, and manual kind e2e | Default `KEYCLOAK_VERSION`. |
| `0.3.x` | `26.5.3` | Compatibility tested | Tag and manual kind e2e | Previous-minor smoke coverage. |
| `0.3.x` | `<26.5` | Unsupported | Not tested | Upgrade Keycloak or validate locally before use. |

## Local Compatibility Testing

Run the same e2e suite against a specific Keycloak image tag:

```bash
KEYCLOAK_VERSION=26.6.2 .venv/bin/python tests/kind/e2e.py prepare
KEYCLOAK_VERSION=26.6.2 .venv/bin/python tests/kind/e2e.py test
.venv/bin/python tests/kind/e2e.py cleanup
```

The fixture image is `quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}`.

## References

- Keycloak downloads: https://www.keycloak.org/downloads
- Keycloak supported configurations: https://www.keycloak.org/server/supported-configurations
- Keycloak release notes: https://www.keycloak.org/docs/latest/release_notes/
