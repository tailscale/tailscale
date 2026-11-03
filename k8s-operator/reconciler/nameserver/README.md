# DNSConfig resolution diagnostics

`NameserverReady` reports provisioning readiness and remains the gate for DNS
record creation. `DNSResolutionReady` independently reports whether a sampled
managed name resolves to its expected addresses from the operator Pod.

The controller chooses a stable name from the nameserver's records ConfigMap and
checks each address family present for that name. It uses the operator's normal
resolver first. If that lookup fails or returns unexpected addresses, it queries
the nameserver Service directly to help distinguish a resolver-path problem
from a nameserver that also fails to answer. A successful normal lookup does not
require the operator to reach the nameserver directly.

Checks run every 30 seconds, with a five-second total probe budget and a
two-second budget per lookup. A confirmed resolver-path failure is reported after a two-minute
grace period to allow ConfigMap projection, DNS reloads and caching to converge.
A subsequent successful check reports recovery. Resource watch events do not
cause extra queries within the interval for an unchanged probe target.

| Condition status | Meaning |
| --- | --- |
| `Unknown` | There is no managed record, the nameserver is disabled or not provisioned, records are invalid/changing, a failed resolver lookup cannot be compared with the expected direct nameserver answer, or a confirmed mismatch is still within the grace period. |
| `False` | The sampled name persistently fails to resolve as expected from the operator, while the nameserver directly returns the expected addresses. The message suggests what to inspect. |
| `True` | The sampled name resolves to the expected addresses for each configured family. |

A nameserver that times out, returns no record or returns unexpected addresses
after a failed operator lookup remains Unknown, without a Warning event, even
after the grace period. An Unknown result resets the mismatch grace period.

A transition to a confirmed resolver-path failure emits a Warning event. Recovery from a reported failure
emits a Normal `DNSResolutionRecovered` event. Identical observations preserve
status and transition timestamps and do not produce repeated events. A changed
sample, Service IP, DNSConfig generation or controller restart starts a new
failure grace period. Cancelled reconciles do not cache a DNS observation.

Inspect the conditions and events with:

```sh
kubectl describe dnsconfig <name>
kubectl get dnsconfig <name> -o yaml
```

DNSConfig is cluster-scoped. When querying Events separately, include all
namespaces or the namespace used by the event recorder.

The result describes the operator's resolver path and one sampled name. It does
not establish reachability from every workload, validate all DNS records, or
check application traffic or tailnet access policy. The normal Go resolver can
also consult the operator Pod's hosts file; a successful lookup is not proof of a
specific CoreDNS forwarding configuration. A lookup timeout does not
identify a particular NetworkPolicy or forwarding mistake. The controller never
edits the cluster DNS configuration.

No CRD schema change is needed: the existing conditions list already supports
additional condition types. The new diagnostic does not gate proxy or DNS
record creation, avoiding a readiness dependency cycle.

The controller uses its existing Kubernetes permissions and dependencies. Each
poll still reconciles the nameserver Deployment; unchanged Services,
ServiceAccounts and the records ConfigMap are read without no-op update
requests. Reads use the controller's eventually consistent cache. Record changes
observed during a check discard its result; later changes are picked up on a
subsequent reconcile.

## Reproduce in kind

With Docker running, kubectl and Python 3 installed, run from the repository root:

```sh
bash k8s-operator/reconciler/nameserver/testdata/dnsconfig-resolution/run.sh
```

The script builds the production nameserver reconciler in a small test driver
and the real nameserver using the repository's Go toolchain. It creates an
isolated kind cluster, refuses to reuse an existing cluster of the same name,
and removes its cluster on exit. It does not require a tailnet or change the
current kubectl context. JSON snapshots, event counts and a summary are retained
in the printed artifact directory; set `RESULTS_DIR` to choose that directory.
The first run downloads the pinned kind, Go toolchain and container image.

The test starts with an unpullable nameserver image. With a managed record
present, the diagnostic must remain Unknown without warnings beyond the grace
period. Restoring the image allows the direct nameserver query to succeed;
missing cluster forwarding then becomes False with one warning. Adding the
forwarding rule produces True and one recovery event. Repeated checks preserve
status, and the failure-to-recovery phase does not restart either Pod.

This exercises synthetic A and AAAA records over IPv4 DNS transport. It runs the
production reconciler rather than the full tailnet-connected operator, and does
not test application traffic or IPv6-only clusters.
