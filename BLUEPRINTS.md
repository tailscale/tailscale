# Blueprints v1 — Client-Side Notes (tailscale/tailscale)

This file documents the OSS client surface of Blueprints. The
control-plane half lives in `tailscale/corp` (see corp's `BLUEPRINTS.md`).
The design rationale lives in the spec.

## What's in this repo for v1

| Piece | Path |
|---|---|
| `tag:bp//<id>` tag namespace | `tailcfg/tailcfg.go` (`BlueprintTagNamespacePrefix`, `IsBlueprintTag`, `BlueprintIDFromTag`) |
| `Node.BlueprintID`, `Node.BlueprintConfig` | `tailcfg/tailcfg.go` (and generated `Clone`/`View`) |
| Capver bump | `tailcfg/tailcfg.go` (139) |
| `Prefs.BlueprintID` + `MaskedPrefs.BlueprintIDSet` | `ipn/prefs.go` (`IsBlueprintBound`) |
| `tailscale join` subcommand | `cmd/tailscale/cli/join.go` |
| `tailscale leave` subcommand | `cmd/tailscale/cli/leave.go` |
| `tailscale join status` subcommand | `cmd/tailscale/cli/join_status.go` |
| `tailscale set` locked-field rejection | `cmd/tailscale/cli/blueprint_lock.go` |
| Shared projection renderer | `cmd/tailscale/cli/blueprint_render.go` |
| Wait-for-first-projection helper | `cmd/tailscale/cli/blueprint_wait.go` |
| Client metrics | spread across `blueprint_lock.go`, `join.go`, `leave.go` |

## Client metrics (clientmetric)

The `clientmetric` package does not support labels, so the spec's
labeled join-attempt metric is split into separate counters here:

| Metric | Type | Where |
|---|---|---|
| `cli_blueprint_join_success` | counter | `join.go` |
| `cli_blueprint_join_failure` | counter | `join.go` (all failure paths) |
| `cli_blueprint_join_projection_timeout` | counter | `join.go`; binding succeeded, the first-projection wait did not |
| `cli_blueprint_leave` | counter | `leave.go` |
| `cli_blueprint_set_rejected` | counter | `blueprint_lock.go` |
| `cli_blueprint_bound` | gauge | 1 while bound; 0 after leave |

The fine-grained failure-cause breakdown (blueprint_not_found,
scope_mismatch, auth_failed) is reported by the corp server-side
metric `counter_blueprint_join_attempts` and is not split on the
client.

## How `tailscale join` works

```
tailscale join --blueprint=bp:<id> --auth-key=<oauth-secret>
```

1. The CLI validates `<id>` (letter-start, alnum + dashes only).
2. It calls the standard `HookResolveAuthKey` to exchange the OAuth
   client secret for a one-shot auth key. **This is the same
   exchange path used by `tailscale up --auth-key=tskey-client-...`;
   the OAuth client just happens to be a blueprint-paired one.**
3. The CLI calls `LocalAPI.Start` with `Prefs.BlueprintID = <id>`
   and the resolved auth key. The daemon registers the node with
   the auto-generated `tag:bp//<id>` tag on it.
4. On every subsequent map poll, the control plane projects the
   bound Blueprint's config onto `Node.BlueprintConfig`, which the
   client applies on top of `Prefs`. Edits to the ACL reconverge
   on the next poll.
5. After kicking off the login, `join` polls `Status` for up to 30
   seconds waiting for the first map poll to deliver
   `Node.BlueprintConfig`, then prints the projection so the
   operator sees what the blueprint actually granted this node. If
   the deadline passes without a projection (`Status` was still in
   `Starting`, or the netmap arrived without `BlueprintConfig`), the
   command prints a one-liner pointing the operator at `tailscale
   join status` and exits 0. The binding itself is unaffected — only
   the display deadline lapsed — and the
   `cli_blueprint_join_projection_timeout` counter records the
   occurrence. Poll interval and timeout are package-level `var` in
   `join.go` (`joinProjectionPollInterval`,
   `joinProjectionPollTimeout`).

## How `tailscale leave` works

```
tailscale leave
```

1. Reads current prefs.
2. If `BlueprintID != ""`, captures a `Status` snapshot first so the
   bound `Self.BlueprintConfig` can be rendered after the logout —
   the operator sees what the node is releasing. The fetch is
   best-effort; if it fails the command falls back to the short
   `Detached from blueprint bp:<id> and logged out.` message.
3. Clears `BlueprintID` via `EditPrefs` (so a crash before logout
   still leaves the node in a sensible state).
4. Calls `LocalAPI.Logout`. Blueprint-bound nodes are ephemeral, so
   the control plane reaps the registration.
5. Bumps `cli_blueprint_leave`, sets `cli_blueprint_bound` to 0,
   prints the released projection.

## How `tailscale join status` works

```
tailscale join status [--json]
```

A read-only inspection subcommand under `joinCmd`. Fetches `Status`
once, then renders:

1. The local node's projected `BlueprintConfig` via the shared
   `renderBlueprintConfig` formatter (same output as `join` and
   `leave`). If the projection has not yet arrived, the renderer
   prints a `(projection not yet received)` line and the command
   still exits 0 — `Self.BlueprintID` from prefs is enough to know
   the binding is real.
2. The set of peers visible to this node bound to the same
   blueprint. `PeerStatus.BlueprintID` (populated from
   `tailcfg.Node.BlueprintID` in `peerStatusFromNode`) is the
   filter. The list is sorted by hostname; each row is
   `hostname <tab> tailscale-ip`. If zero peers are visible the
   command prints `No other peers bound to bp:<id> are visible to
   this node.` — the "visible" hedge is deliberate (the netmap
   reflects ACL visibility, not ground truth).

If the node is not blueprint-bound, the command writes
`this node is not blueprint-bound; ...` to **stderr** and exits 1.
Daemon-connect errors flow through `fixTailscaledConnectError` like
every other read-only CLI command.

`--json` emits a small `joinStatusJSON` envelope with
`BlueprintID`, `BlueprintConfig`, and a `BoundPeers` array of
`{HostName, TailscaleIPs}` entries. The shape mirrors `tailscale
status --json`'s "format may change between releases" contract.

`PeerStatus` gained two fields for this feature: `BlueprintID`
(populated for both Self and peers, used for filtering) and
`BlueprintConfig` (populated only on Self, deliberately filtered
out of the peer iteration path even if a peer's `Node` record
carries it).

## How the locked-field rejection works

`cmd/tailscale/cli/blueprint_lock.go` defines `checkBlueprintSetLocked`
which `runSet` calls right after fetching `curPrefs`:

- If `curPrefs.IsBlueprintBound()` is false, the check is a no-op.
- Otherwise, for each `MaskedPrefs.*Set` bit corresponding to a
  blueprint-owned field, return the spec's verbatim error message
  naming the first offending field.

Locked fields: `advertise-tags`, `advertise-routes`,
`advertise-connector`, `hostname`, `operator`, `ssh`, `accept-dns`.
(`advertise-exit-node` rides on `advertise-routes` and is covered
implicitly; `serves` / `funnel` are not yet Prefs fields and will
arrive in v2.)

## Local development / running tests

```
# Tag namespace, Node, BlueprintConfig:
./tool/go test ./tailcfg/...

# Prefs + binding helpers:
./tool/go test ./ipn/

# CLI locked-field rejection + join helpers:
./tool/go test ./cmd/tailscale/cli/

# Full client build:
./tool/go build ./...
```

End-to-end integration with the control plane (real `tailscale join`
against a tailcontrol-dev) requires the corp branch to be running.
See corp's `BLUEPRINTS.md` for the harness.

## Known limitations in v1

1. **The client trusts the control plane on blueprint binding.**
   `Prefs.BlueprintID` is purely local state; the daemon does not
   verify on each tick that the bound blueprint still exists. If
   the operator deletes a blueprint, bound nodes continue running
   with their last projected config until they reconnect.
2. **`tailscale set` rejection lives in the CLI**, not the daemon.
   A client that posts directly to LocalAPI `EditPrefs` can still
   change blueprint-owned fields. (LocalAPI is loopback-only, so
   the threat is "local root", not "external attacker".)
3. **No UI surfacing yet.** GUI clients don't display the
   blueprint binding; the CLI is the v1 interface.
