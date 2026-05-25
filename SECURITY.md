# Security Policy

## Supported Versions

This project is pre-1.0. Security fixes are provided for the latest released
minor line only.

| Version | Supported |
| --- | --- |
| `0.2.x` | Yes |
| `< 0.2.0` | No |

## Reporting a Vulnerability

Do not open a public issue for suspected security vulnerabilities.

Report vulnerabilities through GitHub private vulnerability reporting:

https://github.com/clouddicted/keycloak-config-operator/security/advisories/new

If private vulnerability reporting is unavailable, contact the maintainers
privately through GitHub and include enough detail to reproduce or assess the
issue. Do not include production credentials, tokens, private keys, or other
secrets in the report.

Useful report details include:

- affected operator version or commit
- Kubernetes and Keycloak versions
- affected CRD kind and namespace scope
- reproduction steps or proof of concept
- impact, such as secret exposure, privilege escalation, or unintended Keycloak
  configuration changes
- relevant logs with secrets redacted

## Response Process

Maintainers will acknowledge valid reports as soon as practical, assess impact,
and coordinate a fix and release. If a vulnerability affects released versions,
the fix should be published with release notes and upgrade guidance.

## Scope

Security-sensitive areas include:

- Kubernetes RBAC and namespace watch scope
- handling of Kubernetes Secrets and Keycloak credentials
- log, event, and status redaction
- reconciliation behavior that can create, update, or delete Keycloak objects
- container image and Helm chart release artifacts
