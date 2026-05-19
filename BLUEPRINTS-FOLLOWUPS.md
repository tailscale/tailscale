# Blueprints — v2+ Follow-ups

Things explicitly out of scope for v1. Added here whenever the v1 implementation surfaces a tempting expansion.

## From the spec (deferred from day one)

- **Composability (`includes`).** Blueprint A includes Blueprint B's fields. No transitive `tag:bp//` inheritance; design TBD.
- **Blueprints as ACL destinations.** Grants directly targeting `blueprint:foo` rather than `tag:bp//foo`. Currently solved by the auto-generated tag.
- **Services auto-generating blueprints.** A `svc:` definition would imply a paired blueprint.
- **tsnet integration.** Embedding blueprint-bound behavior inside a tsnet-hosted Go program.
- **Versioning / rollback / per-node blueprint pins.** Today edits propagate everywhere.
- **Partial overrides.** Per-node opt-out of specific blueprint fields.
- **Per-deployment secrets.** Different secrets per environment for the same blueprint.
- **Super-ephemeral nodes.** Nodes that vanish on idle, not just on leave.
- **Separate wire protocol.** Blueprint propagation currently piggybacks on the existing map-poll.

## Surfaced during v1 build

* **`tailscale leave` does not blocking-wait for server-side reaping.**
  Today the client logs out and exits; the control plane reaps the
  registration via the ephemeral-node reaper, which can take a few
  minutes. Operators running scripted teardown may want a synchronous
  wait. Track for v1.1.
* **No GUI client surface.** The macOS/iOS/Windows clients don't
  display the bound-blueprint indicator. v1 is CLI-only by design,
  but the `tailcfg.Node.BlueprintID` field is on the wire so GUIs can
  add it whenever.
* **`tailscale set` rejection is CLI-only.** A caller hitting LocalAPI
  EditPrefs directly can still flip blueprint-owned fields. LocalAPI
  is loopback-only so the threat is "local root" rather than "remote
  attacker", but we may want to push the check into the daemon for
  defense in depth. Tracked for v1.1.
* **Client metric labels.** `clientmetric` doesn't support labels, so
  blueprint_join_attempts{result} is implemented as four flat
  counters on the corp side and as a pair of (success, failure)
  counters on the client. The fine-grained client-side breakdown
  would require either teaching `clientmetric` about labels or
  introducing several more counters.

## Surfaced during v2 build

* **`pref:funnel` permanently removed from the allowlist (v2.1).**
  Earlier drafts of the spec listed `pref:funnel` alongside
  accept-dns / accept-routes / ssh. v2.1 dropped it: funnel
  eligibility for blueprint-bound nodes flows through the
  existing `tailcfg.NodeAttrFunnel` attr via the `attrs:` block,
  not a Prefs bool. The compile-time allowlist (corp side) and
  the client-side reconciler are both authoritative on three
  prefs.
