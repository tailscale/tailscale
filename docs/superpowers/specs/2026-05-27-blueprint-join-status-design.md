# Blueprint join/leave projection display + `tailscale join status`

Status: Draft for implementation
Branch: `kabir/blueprints-v2`
Scope: client-side (OSS `tailscale/tailscale`). No corp-side changes.

## Problem

Blueprint-bound nodes receive their configuration (tags, routes, serves,
attrs, prefs) from the control plane via `Node.BlueprintConfig` on each
map poll. The CLI today gives the operator no way to see what was
actually projected:

- `tailscale join` prints `Bound to blueprint bp:<id>` and exits before
  the first netmap arrives. The operator has no idea what they just
  signed up for.
- `tailscale leave` prints `Detached from blueprint bp:<id> and logged
  out.` with no information about what was being torn down.
- There is no way to inspect the current projection at runtime.
- There is no way to discover which other nodes share the blueprint.

## Goals

1. After a successful `tailscale join`, the operator sees the projected
   `BlueprintConfig` rendered as plain text.
2. During a `tailscale leave`, the operator sees the projection that is
   being released, before the node logs out.
3. A new `tailscale join status` subcommand renders the same
   projection on demand, plus a list of peers bound to the same
   blueprint (when visible to the local node per policy).
4. JSON output is supported on `join status` for scripting.

## Non-goals

- No new wire protocol or `tailcfg` fields. Everything needed is
  already on `Node.BlueprintID` / `Node.BlueprintConfig`.
- No GUI surface. CLI-only, matching v1's posture.
- No `tailscale status` integration. Operators who want blueprint info
  in `status` output can read the raw `Status` JSON; we are not
  modifying the `tailscale status` formatter in this patch.
- No `--peers=false`, `--active`, or other filter flags on
  `join status`. YAGNI.
- No services-reconcile work. `BlueprintConfig.ServeServices` is
  rendered as-is; how the daemon acts on it is a separate workstream.

## Design

### Architecture

Three commands share one formatter:

```
                            ┌── join.go         (block-with-timeout, then render)
LocalAPI ─ Status() ─ ipnstate ─┼── leave.go        (capture pre-logout, then render)
                            └── join_status.go  (render + peer list)
```

The shared formatter takes a `*ipnstate.Status` and writes a text block
describing `status.Self.BlueprintConfig`. Peer listing lives in
`join_status.go` only; join and leave do not list peers.

### Plumbing change: `ipnstate.PeerStatus.BlueprintID`

`PeerStatus` does not carry `BlueprintID` today. Add one field:

```go
// In ipn/ipnstate/ipnstate.go, struct PeerStatus:
BlueprintID string `json:",omitempty"`
```

Update `AddPeer` (the merge function in the same file) to copy
`BlueprintID` from the source `PeerStatus` when non-empty, following
the existing pattern used by every other string field on the struct.

Population: in the code path that constructs `PeerStatus` from
`tailcfg.Node` (located during implementation in `ipn/ipnlocal/` —
typically the `populatePeerStatus`-style helper), copy
`Node.BlueprintID` → `PeerStatus.BlueprintID`. Apply the same copy for
`Status.Self.BlueprintID` from `nm.SelfNode.BlueprintID`.

No `BlueprintConfig` is plumbed onto `PeerStatus`. Peers' projections
are not interesting to the local operator; only the binding identity
is.

### New subcommand: `tailscale join status`

Registered as `joinCmd.Subcommands = []*ffcli.Command{joinStatusCmd}`.
ffcli supports sub-subcommands; no change to the top-level command
list in `cli.go`.

```
tailscale join status [--json]
```

Flags:

- `--json` — emit machine-readable JSON. Format may change between
  releases (matching `tailscale status --json`'s contract).

Exit codes:

- `0` — running and bound; projection rendered.
- `0` — running and bound but `BlueprintConfig` not yet received (text
  notes "projection not yet received").
- `1` — not blueprint-bound. Stderr: `this node is not
  blueprint-bound; run 'tailscale join --blueprint=<id>
  --auth-key=...' to bind it.`
- `2` — daemon connect failure, via `fixTailscaledConnectError`.

### `join` changes

After `localClient.StartLoginInteractive(ctx)`, replace the existing
single-line success print with a wait loop:

- Poll `localClient.Status(ctx)` every 250 ms for up to 30 seconds.
- Success condition: `st.BackendState == ipn.Running.String()` AND
  `st.Self != nil` AND `st.Self.BlueprintID == id` AND
  `st.Self.BlueprintConfig != nil`.
- On success: print `Bound to blueprint bp:<id>.` followed by the
  projection block.
- On timeout: print `Bound to blueprint bp:<id>. Projection not yet
  received; run 'tailscale join status' to see it.`

Either path exits `0` and increments `metricBlueprintJoinSuccess` (the
binding succeeded; only the display wait may have lapsed). A new
counter `cli_blueprint_join_projection_timeout` records the
timeout-only case for observability.

The 250 ms interval and 30 s timeout are constants at the top of the
file. Make them package-level `const` so tests can override via a
helper rather than waiting in real time.

### `leave` changes

In `runLeave`, before the `localClient.EditPrefs` call that clears
`BlueprintID`:

- Call `localClient.Status(ctx)` once.
- If it fails: log internally and skip projection rendering (fall back
  to today's plain string). Leave is reversible — no point blocking on
  a status fetch.
- If it succeeds and the node is blueprint-bound: stash
  `st.Self.BlueprintConfig` for printing after logout.

After successful `Logout`, render `Detached from blueprint bp:<id>.
Released:` followed by the projection block. If the projection was
nil or fetch failed, fall back to today's `Detached from blueprint
bp:<id> and logged out.`

If the projection's id and the prefs' id disagree (extremely unlikely
race), trust prefs for the printed id and render the projection
content anyway. A short comment in the code documents the choice.

### Shared formatter

New unexported function in a new file `cmd/tailscale/cli/blueprint_render.go`:

```go
func renderBlueprintConfig(w io.Writer, id string, cfg *tailcfg.BlueprintConfig)
```

Output (newline-terminated; example with all buckets populated):

```
Blueprint:  bp:github-connector
  Tags:      tag:bp//github-connector, tag:prod
  Routes:    10.0.0.0/24, 10.0.1.0/24
  Apps:      app:github
  Services:  svc:webhook
  IPSets:    ipset:corp-internal
  Attrs:     nodeAttr:funnel
  Prefs:     pref:ssh, pref:accept-routes
```

Rules:

- Empty buckets are omitted entirely (no `Apps: (none)` lines).
- Order: Tags, Routes, Apps, Services, IPSets, Attrs, Prefs.
- Field labels are left-aligned in a 10-character column for visual
  scanning. Values are comma-separated.
- If `cfg == nil`, output is `Blueprint:  bp:<id>` followed by
  `  (projection not yet received)`.

For `join status`, the peer section follows the projection block:

```
Peers bound to bp:github-connector (2 visible):
  hostname-a    100.64.0.5
  hostname-b    100.64.0.7
```

If zero peers visible: `No other peers bound to bp:<id> are visible
to this node.`

The peer section is rendered whether or not the local projection has
arrived: the `BlueprintID` is known from `status.Self.BlueprintID`
(populated via the plumbing change above) even when
`status.Self.BlueprintConfig` is still nil. So a freshly-joined node
can list its blueprint-mates immediately while waiting for its own
projection.

The "visible" hedge is deliberate. The netmap reflects ACL visibility,
not ground truth; we must not claim there are no other bound peers
when we only know we cannot see them.

Peer iteration sorts by hostname for stable output. The Tailscale IP
column shows `ps.TailscaleIPs[0]` (matching `tailscale status`
conventions); blank if the peer has no IPs assigned yet.

### JSON output (`join status --json` only)

A small type defined locally in `cmd/tailscale/cli/join_status.go`:

```go
type joinStatusJSON struct {
    BlueprintID     string                  `json:"BlueprintID"`
    BlueprintConfig *tailcfg.BlueprintConfig `json:"BlueprintConfig,omitempty"`
    BoundPeers      []boundPeerJSON         `json:"BoundPeers"`
}

type boundPeerJSON struct {
    HostName     string       `json:"HostName"`
    TailscaleIPs []netip.Addr `json:"TailscaleIPs"`
}
```

Rationale for not re-exporting `ipnstate.PeerStatus`: we do not want
every `PeerStatus` field to bleed into this output and commit us to
maintaining the shape. Two fields satisfy the documented use case.

The `BoundPeers` slice is always present (possibly empty). The output
contract for `--json`, like `tailscale status --json`, is "format may
change between releases."

### Where the BlueprintID column moves through the stack

```
tailcfg.Node.BlueprintID            (already on the wire)
        │
        ▼
ipn/ipnlocal/<populatePeerStatus>   (this patch: add field copy)
        │
        ▼
ipnstate.PeerStatus.BlueprintID     (this patch: new field)
        │
        ▼
cmd/tailscale/cli/join_status.go    (this patch: filter & render)
```

The same path applies to `Status.Self.BlueprintID`; the only
difference is that `Self` also has `BlueprintConfig` populated, which
is what the projection renderer needs.

## Telemetry

Existing counters are unchanged. One new counter:

- `cli_blueprint_join_projection_timeout` — incremented when `join`'s
  wait loop times out without seeing a projection. Server-side join
  success is unaffected.

No new counters for `leave` or `join status`. The existing
`cli_blueprint_leave` already covers leave invocations; `join status`
is a read-only inspection and not worth a counter.

## Tests

- `cmd/tailscale/cli/join_status_test.go` (new) — table-driven.
  Inputs: synthetic `*ipnstate.Status` values covering:
  - bound + projection populated + peers
  - bound + projection populated + no peers visible
  - bound + projection nil
  - not bound (exit 1)
  Asserts exact text output via `strings.Builder` capture.
  JSON path asserted via `json.Unmarshal` round-trip into
  `joinStatusJSON`.

- `cmd/tailscale/cli/join_test.go` (extend) — cover the wait loop:
  - Inject a fake `localClient` sequence: first call returns
    `BackendState=Starting`, second returns Running with
    `BlueprintConfig` populated → expect projection block printed.
  - Inject a sequence that never sees `BlueprintConfig` → expect
    timeout message + `cli_blueprint_join_projection_timeout`
    incremented + exit 0.
  - Inject `BackendState=Running` with mismatched
    `Self.BlueprintID` → continue polling (do not declare success on
    a stale netmap).

- `cmd/tailscale/cli/leave_test.go` (new — none exists today) —
  - Bound + status fetch succeeds: projection rendered before
    `Detached from blueprint bp:<id>.`
  - Bound + status fetch fails: falls back to today's plain message.
  - Not bound: today's `Logged out. (Node was not blueprint-bound.)`

- `cmd/tailscale/cli/blueprint_render_test.go` (new) — pure formatter
  tests, no I/O. All-empty `BlueprintConfig`, single-bucket,
  all-buckets, nil. Asserts byte-exact output.

- `ipn/ipnstate/ipnstate_test.go` (extend) — `AddPeer` merge
  preserves `BlueprintID` from the source when set; does not
  overwrite an existing non-empty value with empty.

- `ipn/ipnlocal/` — extend whichever existing test covers
  `populatePeerStatus`-style construction to assert the
  `Node.BlueprintID → PeerStatus.BlueprintID` copy. If no such test
  exists, add a minimal one. (Located during implementation.)

Coverage target: ≥80% of new code, matching the v1 checklist bar.

## Edge cases

- **Daemon not running.** Standard `fixTailscaledConnectError` path
  on all three commands.
- **Not blueprint-bound.**
  - `join status`: exit 1, stderr message above.
  - `leave`: today's "Logged out. (Node was not blueprint-bound.)"
- **Bound but `BlueprintConfig` nil.** Renderer prints
  `Blueprint: bp:<id>` + `(projection not yet received)`. Exit 0.
- **Join timeout.** Described in `join` changes. Increment
  `cli_blueprint_join_projection_timeout`; do not increment failure.
- **Stale projection in `leave`.** Document and ship; do not block.
- **Peer with `BlueprintID` matching ours but no `TailscaleIPs`.**
  Rendered with blank IP column. Operator sees the hostname is
  there; daemon hasn't finished bringing it up.
- **Privacy / visibility.** No client-side enforcement needed. The
  netmap is the policy-filtered ground truth.

## Build variants

No new build-tag-gated behavior. Blueprints in v1 are
`HasBlueprints() = IsSaaS`-gated server-side; the OSS client
side is identical across variants and this patch keeps that
property. The new code compiles unconditionally.

## File inventory

New files:

- `cmd/tailscale/cli/join_status.go`
- `cmd/tailscale/cli/join_status_test.go`
- `cmd/tailscale/cli/blueprint_render.go`
- `cmd/tailscale/cli/blueprint_render_test.go`
- `cmd/tailscale/cli/leave_test.go`

Modified:

- `ipn/ipnstate/ipnstate.go` — add `PeerStatus.BlueprintID`, update
  `AddPeer` merge.
- `ipn/ipnstate/ipnstate_test.go` — `AddPeer` merge test.
- `ipn/ipnlocal/<file with populatePeerStatus>` — copy
  `Node.BlueprintID` → `PeerStatus.BlueprintID` (and same for Self).
- `cmd/tailscale/cli/join.go` — wait loop, post-success render,
  new counter, subcommand registration.
- `cmd/tailscale/cli/join_test.go` — wait-loop tests.
- `cmd/tailscale/cli/leave.go` — pre-logout status fetch, render
  on success.

## Commit shape

One commit, following the repo's commit-message style:

```
cmd/tailscale/cli, ipn/ipnstate: surface blueprint projection in join/leave/status

Adds a 'tailscale join status' subcommand that renders the
projected BlueprintConfig plus any peers visible to the local
node that are bound to the same blueprint. Extends 'tailscale
join' to wait briefly for the first projection and render it
before returning; extends 'tailscale leave' to print the
projection it is releasing before logging out.

ipn/ipnstate.PeerStatus grows a BlueprintID field, populated
from tailcfg.Node.BlueprintID, so the join-status renderer can
filter peers by their binding.

A new client counter cli_blueprint_join_projection_timeout
records the case where the join wait loop exits without seeing
a projection; the underlying join itself is unaffected.

Updates #cleanup

Signed-off-by: Kabir Sikand <kabir@tailscale.com>
```

(Issue reference will be looked up against maintner/git log
at commit time; `#cleanup` is the conservative default until a
matching tracked issue is confirmed.)
