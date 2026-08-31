# Reconciliation

The operator combines event-driven reconciliation with periodic drift checks.
Event-driven checks apply expected changes promptly, while periodic checks repair
or report changes made directly through the Keycloak API or admin console.

## Reconciliation Triggers

A Keycloak custom resource is reconciled when:

- the resource is created or its spec, metadata, or generation changes;
- the operator starts and resumes the existing resource;
- a referenced Secret or supported operator CR changes; or
- its periodic drift-check timer fires.

Dependency-triggered reconciliation covers these references:

| Dependent resource | Sources that trigger it |
| --- | --- |
| Every resource except `KeycloakTarget` | Its `spec.targetRef` |
| `KeycloakTarget` | Admin password, bootstrap admin, client credentials, and legacy admin credential Secrets |
| `KeycloakIdentityProvider` | Secrets in `spec.configSecretRefs` |
| `KeycloakClient` | Its client Secret and declared default or optional `KeycloakClientScope` resources |
| `KeycloakClientRole` | Its `KeycloakClient` |
| `KeycloakGroupRoleMapping` | Its group, realm role, client role, and owning client |
| `KeycloakProtocolMapper` | Its parent client or client scope |

The operator patches a private
`keycloak.clouddicted.com/dependency-trigger` annotation on each affected
dependent. Its normal update handler then performs the reconciliation. Duplicate
events for the same source resource version are ignored.

Dependency events are immediate only when the operator watches the source
namespace. Cross-namespace Secret references still require read permission. If
such a Secret is outside the operator's watch scope, a dependent CR can read it
during its next ordinary or periodic check, but the Secret change does not
trigger that check by itself.

## Periodic Drift Checks

The default periodic interval is 600 seconds (10 minutes). Every managed CR has
its own timer. The first check is deterministically staggered across the first
interval using the resource identity, avoiding a burst of Keycloak requests
after operator startup. Subsequent checks run at the configured interval.

The timer calls the same idempotent handler used for create and update events:

- `managementPolicy: Reconcile` repairs fields owned by the operator.
- `managementPolicy: ObserveOnly` reports drift without modifying Keycloak.
- A check with unchanged desired and observed state produces no status patch and
  no duplicate Kubernetes event.

## Configure The Interval

For Helm, set `reconciliationIntervalSeconds` to a non-negative integer:

```bash
helm upgrade --install keycloak-config-operator \
  oci://ghcr.io/clouddicted/charts/keycloak-config-operator \
  --namespace keycloak-config-operator-system \
  --set reconciliationIntervalSeconds=300
```

For the plain Deployment, set the equivalent environment variable:

```yaml
env:
  - name: RECONCILIATION_INTERVAL_SECONDS
    value: "300"
```

A value of `0` disables periodic checks. Create, update, resume, dependency, and
failure-retry reconciliation remain enabled. Invalid values stop operator
startup with a configuration error instead of silently selecting an interval.

## Failure Retries

Retry timers are separate from periodic drift checks:

- retryable reconciliation failures are retried after 60 seconds; and
- failed remote deletion attempts are retried after 30 seconds.

Changing the periodic interval does not change either retry delay. A dependency
event or CR update can trigger another attempt before a pending retry fires.
