# Adopt Existing Keycloak Configuration

The operator image includes a read-only adoption CLI that inspects one existing
Keycloak realm and renders Kubernetes resources for the configuration the
operator understands. It does not change Keycloak or apply resources to a
cluster.

Generated resources use `managementPolicy: ObserveOnly` and, where supported,
`deletionPolicy: Orphan`. Review the generated YAML and its warnings before
applying it. The CLI never renders `KeycloakTarget`, Kubernetes `Secret`, or
secret values.

## Prerequisites

Create a confidential Keycloak client with service accounts enabled and grant
its service account read access to the realm configuration. Save its client
secret in a local file readable only by you. The examples below use Docker; the
same arguments work with Podman.

Set values for your environment:

```bash
export KEYCLOAK_URL='https://keycloak.example.com'
export AUTH_REALM='master'
export CLIENT_ID='keycloak-adoption'
export REALM='example'
export NAMESPACE='keycloak-config'
export TARGET_REF='production-keycloak'
```

The `KeycloakTarget` named by `TARGET_REF` must already exist, or you must create
it separately before applying the rendered resources. The CLI uses the URL and
credentials passed on the command line for discovery; `--target-ref` is only
written into the manifests.

## Preview The Adoption Plan

Mount the client secret file and run `adopt plan`:

```bash
docker run --rm \
  --mount type=bind,src="$PWD/client-secret",dst=/run/secrets/client-secret,readonly \
  ghcr.io/clouddicted/keycloak-config-operator:v0.9.0 \
  adopt plan \
  --url "$KEYCLOAK_URL" \
  --auth-realm "$AUTH_REALM" \
  --client-id "$CLIENT_ID" \
  --client-secret-file /run/secrets/client-secret \
  --realm "$REALM"
```

The plan lists discovered and rendered resources, skipped Keycloak built-ins,
unsupported fields, omitted secrets, and any references or names that cannot be
resolved safely.

TLS verification is enabled. For a private certificate authority, mount its CA
file and add `--ca-file /run/secrets/keycloak-ca.crt`.

## Render Manifests

After reviewing the plan, render deterministic multi-document YAML:

```bash
docker run --rm \
  --mount type=bind,src="$PWD/client-secret",dst=/run/secrets/client-secret,readonly \
  ghcr.io/clouddicted/keycloak-config-operator:v0.9.0 \
  adopt render \
  --url "$KEYCLOAK_URL" \
  --auth-realm "$AUTH_REALM" \
  --client-id "$CLIENT_ID" \
  --client-secret-file /run/secrets/client-secret \
  --realm "$REALM" \
  --namespace "$NAMESPACE" \
  --target-ref "$TARGET_REF" \
  --output - > adopted-keycloak.yaml
```

YAML is written to stdout. The report and warnings are written to stderr, so
shell redirection captures only the manifests. Repeating the command against an
unchanged realm produces the same output.

The command exits with:

| Code | Meaning |
| --- | --- |
| `0` | Discovery completed and the plan or complete YAML was produced. |
| `2` | Input, TLS, authentication, or Keycloak API discovery failed. |
| `3` | A name collision or unresolved reference made rendering unsafe. No partial YAML is emitted. |

## Review And Apply

Inspect the report and YAML. Add the omitted Secret references where needed,
especially identity-provider configuration. Confidential clients are valid
without a client secret while they remain `ObserveOnly`; add an authentication
configuration before changing one to `Reconcile`.

Validate and apply the file when it is ready:

```bash
kubectl apply --server-side --dry-run=server -f adopted-keycloak.yaml
kubectl apply -f adopted-keycloak.yaml
```

Promote resources from `ObserveOnly` to `Reconcile` gradually and in dependency
order: realm, client scopes, clients, roles and groups, then mappers and role
mappings. Unsupported Keycloak settings remain outside the operator's ownership.

## Initial Scope

Version 0.9 supports one explicitly named realm and client-credentials
authentication. It renders all currently managed resource kinds except
`KeycloakTarget`, excludes known Keycloak built-ins, and omits nested groups and
unsupported fields with warnings. Multiple realms, filters, directory output,
machine-readable reports, and password authentication are planned for a later
release.
