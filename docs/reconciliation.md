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
| `KeycloakIdentityProviderMapper` | Its parent identity provider, referenced by CR name or provider alias |
| `KeycloakClient` | Its client Secret and declared default or optional `KeycloakClientScope` resources |
| `KeycloakClientRole` | Its `KeycloakClient` |
| `KeycloakGroupRoleMapping` | Its group, realm role, client role, and owning client |
| `KeycloakProtocolMapper` | Its parent client or client scope |

The operator patches a private
`reconcile.keycloak.clouddicted.com/dependency-trigger` annotation on each affected
dependent. Its normal update handler then performs the reconciliation, including
when periodic checks are disabled. The annotation uses a separate prefix from
Kopf's bookkeeping so it participates in change detection. Changes propagate
through supported dependency chains, such as Secret → target → client.

The trigger records the source identity and resource version observed when the
dependent was enqueued. The source's current version may subsequently advance
because of status or bookkeeping writes; it need not equal the recorded version.
Duplicate events with the same current trigger are ignored. Status-only CR updates
do not fan out, and terminating dependents are removed from the dependency index.
Secrets use raw watch events without storing Kopf handler state on the Secret.

Dependency events are immediate only when the operator watches the source
namespace. Cross-namespace Secret references still require read permission. If
such a Secret is outside the operator's watch scope, a dependent CR can read it
during its next ordinary or periodic check, but the Secret change does not
trigger that check by itself.

## Periodic Drift Checks

The default periodic interval is 600 seconds (10 minutes). Every managed CR has
its own timer. The first check is deterministically staggered across the first
interval using the resource identity, avoiding a burst of Keycloak requests
after operator startup. Subsequent checks wait the configured interval after the
previous check finishes, so API latency adds to the time between checks.

The timer calls the same idempotent handler used for create and update events:

- `managementPolicy: Reconcile` repairs fields owned by the operator.
- `managementPolicy: ObserveOnly` reports drift without modifying Keycloak.
- A check with unchanged desired and observed state produces no status patch and
  no duplicate Kubernetes event.

Within one operator process, reconciliation and deletion calls for the same CR
are serialized. A timer tick is skipped if that CR is already being processed;
updates and deletions wait for the active call to finish. Different CRs can still
reconcile concurrently. Once deletion is observed, further create/update and timer
calls for that CR are skipped, preventing recreation during finalizer cleanup.

Unchanged visible fields do not cause configuration writes. Groups are compared
using their full detail response because search results can omit attributes.
Identity providers use in-memory write acknowledgments for masked config; they
reapply those values once after restart. Masked values cannot reveal out-of-band
changes. See [identity provider secrets](resources/keycloak-identity-provider.md#secrets).

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
