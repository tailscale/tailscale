# Path Policy Routing — Design & Implementation Plan

**Feature:** Custom routing rules in cloud control config for
policy-driven path selection with multi-hop peer relays.
**Tracks:** [#17765](https://github.com/tailscale/tailscale/issues/17765)
— FR: Policy-based Routing (primary)
**Related:** [#18206](https://github.com/tailscale/tailscale/issues/18206)
— FR: Path-aware address-family policy (satisfied as a subset)
**Status:** Prototype implemented — Phases 1–5 complete in client
code; pending control-plane integration and maintainer review

> **Relationship to existing issues:**
> - #17765 requests selective distribution of subnet routes to
>   clients based on tags, posture, and user groups. This design
>   generalises that idea to cover not just which routes are
>   distributed but also *which path* (direct, peer relay chain,
>   DERP) is used to reach a destination.
> - #18206 requests a narrow knob — "prefer IPv6 for direct,
>   IPv4 for DERP relay." The `AF` field on `PathEntry` (§2)
>   satisfies that as a degenerate case of this broader design.

---

## 1. Problem Statement

Today Tailscale picks the best path between two peers
automatically using latency scoring in `betterAddr()`
([wgengine/magicsock/endpoint.go](../wgengine/magicsock/endpoint.go)):

```
direct (IPv4/IPv6) > single-hop peer relay > DERP home region > public DERP
```

This is optimal for general use but gives operators no control
over:

- **Topology preferences** — e.g., "machines in region A should
  relay through region-A relays, not region-B."
- **Cost/bandwidth policy** — prefer a private DERP over the
  public fleet.
- **Regulatory compliance** — traffic between two regions must
  stay in a jurisdiction.
- **Multi-hop relay chains** — progressively longer relay chains
  as fallback.
- **Selective route distribution** (#17765) — a tag-matched
  subset of clients should use an exit node for IPv6 only while
  routing IPv4 normally.
- **Address-family pinning per path** (#18206) — use IPv6 for
  direct, IPv4 for DERP/relay.

### Key constraint: no intermediate decryption

Each packet in a relay chain has two distinct layers:

- **Outer layer — Geneve header.** The relay reads the inbound
  VNI, looks up the forwarding entry, rewrites the VNI to the
  outbound value, and forwards the packet to the next hop. This
  is the *only* part of the packet the relay touches.
- **Inner layer — WireGuard payload.** This is end-to-end
  encrypted between `src` and the final `dst` only. Relay nodes
  hold no WireGuard keys for this session and cannot read or
  modify the encrypted payload.

Intermediate nodes therefore see and forward only opaque,
encrypted datagrams — identical to how DERP servers operate
today, and how the existing single-hop peer relay works with
Geneve/VNI encapsulation.

---

## 2. Proposed Config Schema

Operators define path policy in the tailnet's control config
(e.g., an `acl.hujson` extension or a dedicated control API).
A new top-level `"PathPolicy"` block contains an array of rules:

```jsonc
{
  "PathPolicy": {
    "Rules": [
      {
        // Match: packets FROM any node tagged "tag:us-servers"
        //   or "tag:us-relays" TO any node with the same tags.
        "Src": ["tag:us-servers", "tag:us-relays"],
        "Dst": ["tag:us-servers", "tag:us-relays"],

        // Ordered fallback chain. Earlier entries are preferred.
        // Client advances to the next entry only on failure.
        "Path": [
          // 1. Direct UDP, IPv6 only (#18206: prefer IPv6)
          { "type": "direct", "af": "ipv6" },
          // 2. Direct UDP, IPv4 fallback
          { "type": "direct", "af": "ipv4" },
          // 3. Single-hop peer relay via any us-relay node
          { "type": "relay", "hops": ["tag:us-relays"], "af": "ipv4" },
          // 4. Two-hop chain
          { "type": "relay", "hops": ["tag:us-relays", "tag:us-relays"] },
          // 5. Three-hop chain
          { "type": "relay", "hops": ["tag:us-relays", "tag:us-relays", "tag:hk-relays"] },
          // 6. Private DERP region 900, IPv4
          { "type": "derp", "region": 900, "af": "ipv4" },
          // 7. Default public DERP fallback (always last)
          { "type": "derp" }
        ]
      }
    ]
  },

  "DERPMap": {
    "OmitDefaultRegions": false,
    "Regions": {
      "900": {
        "RegionID":   900,
        "RegionCode": "us",
        "Nodes": [
          {
            "Name":     "us1",
            "RegionID": 900,
            "Hostname": "us.example.com",
            "DERPPort": 1443,
            "STUNPort": 3478
          }
        ]
      }
    }
  }
}
```

### Path entry types

| `type` | `hops` | `af` | `region` | Meaning |
|---|---|---|---|---|
| `"direct"` | — | `"ipv4"`, `"ipv6"`, or omit | — | Direct UDP. `af` restricts address family. |
| `"relay"` | `["tag:X"]` | optional | — | Single-hop peer relay through any node tagged X |
| `"relay"` | `["tag:X","tag:Y"]` | optional | — | Two-hop chain: src → X-node → Y-node → dst |
| `"relay"` | `["tag:X","tag:Y","tag:Z"]` | optional | — | Three-hop chain |
| `"derp"` | — | `"ipv4"`, `"ipv6"`, or omit | region ID, or omit for default | Route via DERP. Omitting `region` = public/default fleet |

The `af` field directly satisfies #18206: `{"type":"direct","af":"ipv6"}`
followed by `{"type":"derp","af":"ipv4"}` expresses exactly the
IPv6-for-direct, IPv4-for-DERP behaviour requested there.

---

## 3. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                 Control Plane (headscale / Tailscale SaaS)       │
│                                                                  │
│  PathPolicy config  ──►  PathPolicy in MapResponse               │
└──────────────────────────────────┬───────────────────────────────┘
                                   │  tailcfg.MapResponse
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  Client node (src)                                               │
│                                                                  │
│  PathPolicyEngine  (NEW)                                         │
│   • Resolves tag → node set from netmap                          │
│   • For each dst peer, computes ordered candidate path list      │
│   • Feeds candidates to relayManager and betterAddr()            │
│                                                                  │
│  relayManager  (EXTENDED)                                        │
│   • Existing: single-hop relay session management                │
│   • New: multi-hop chain session management                      │
│   • Coordinates VNI allocation across relay chain                │
└───────┬──────────────────┬───────────────────────────────────────┘
        │ direct UDP        │ Geneve/VNI encapsulated relay
        ▼                   ▼
   ┌──────────┐     ┌──────────────────────────────────────┐
   │   dst    │     │ relay-1  →  relay-2  →  ...  →  dst  │
   │ (decrypts│     │ (forward only, no WG decryption)     │
   │  WireGuard)    └──────────────────────────────────────┘
   └──────────┘
```

All intermediate relay nodes forward opaque
Geneve-encapsulated WireGuard packets. They maintain a simple
VNI forwarding table. WireGuard decryption only happens at the
final destination.

---

## 4. Data Structure Changes (`tailcfg/tailcfg.go`)

### 4.1 New types

```go
// PathEntryType identifies what kind of path entry this is.
type PathEntryType string

const (
    PathEntryDirect PathEntryType = "direct"
    PathEntryRelay  PathEntryType = "relay" // single or multi-hop via peer nodes
    PathEntryDERP   PathEntryType = "derp"
)

// PathEntryAF constrains which address family is used for a path entry.
// Empty string means no constraint (try both IPv4 and IPv6).
type PathEntryAF string

const (
    PathEntryAFAny  PathEntryAF = ""
    PathEntryAFIPv4 PathEntryAF = "ipv4"
    PathEntryAFIPv6 PathEntryAF = "ipv6"
)

// PathEntry is one step in a PathRule.Path ordered fallback list.
type PathEntry struct {
    // Type indicates the kind of path.
    Type PathEntryType

    // Hops is the ordered list of tag groups for a relay chain.
    // len==1 → single-hop, len==2 → two-hop, etc.
    // Only valid when Type == PathEntryRelay.
    Hops []string `json:",omitempty"`

    // AF optionally restricts which address family is used.
    // Satisfies #18206: AF=ipv6 for direct, AF=ipv4 for DERP.
    // Empty means no restriction.
    AF PathEntryAF `json:",omitempty"`

    // DERPRegion is the DERP region ID.
    // Only valid when Type == PathEntryDERP. 0 = public/default fleet.
    DERPRegion int `json:",omitempty"`
}

// PathRule matches src→dst node pairs and specifies an ordered path preference.
type PathRule struct {
    // Src is a list of tag names. A node matches if it has ANY of these tags.
    Src []string `json:",omitempty"`

    // Dst is a list of tag names. A node matches if it has ANY of these tags.
    Dst []string `json:",omitempty"`

    // Path is the ordered fallback list. Earlier entries are preferred.
    // The client tries each in order, moving to the next on failure.
    Path []PathEntry `json:",omitempty"`
}

// PathPolicy is the top-level routing policy pushed from the control plane.
type PathPolicy struct {
    // Rules is evaluated in order; first matching rule wins.
    Rules []PathRule `json:",omitempty"`
}
```

### 4.2 Add to `MapResponse`

```go
// PathPolicy, if non-nil, overrides default path selection for matching
// src→dst pairs. Requires CapabilityVersion >= 134.
PathPolicy *PathPolicy `json:",omitempty"`
```

### 4.3 New capability version and node attribute

```go
// CapabilityVersion 134: PathPolicy in MapResponse.

NodeAttrPathPolicyRouting NodeAttr = "path-policy-routing"
```

The control plane gates `PathPolicy` delivery behind a
capability version check, so old clients that don't understand
the field simply ignore it.

---

## 5. Control Plane Changes

The control plane (separate repo, specified here for
completeness) must:

1. **Parse** the `PathPolicy` block from ACL/config.
2. **Validate**: tag names exist; relay chain lengths ≤ 4;
   no cycles; `af` values are `"ipv4"` or `"ipv6"`.
3. **Distribute** `PathPolicy` in `MapResponse`, filtering to
   rules relevant to that node as either src or dst.
4. **Capability gate**: only deliver `PathPolicy` to nodes with
   `CapabilityVersion >= 134`.

Tag-to-node resolution and relay capability enforcement are
**not** done at the control plane. The control plane sends raw
tag-based rules; clients resolve tags against their live netmap
so membership stays current as nodes join/leave without
requiring a new map push. Relay capability enforcement
(`PeerCapabilityRelayTarget`) is performed client-side in
`magicsock.updateRelay()` via `nodeHasCap()` when filtering
relay candidates.

---

## 6. Client: Path Policy Engine (new package `wgengine/pathpolicy`)

### 6.1 Responsibilities

- Receives `PathPolicy` from netmap on each `Update(nm)`.
  The engine holds an immutable reference to the
  `NetworkMap` passed to `Update()`; the snapshot is replaced
  wholesale on each netmap push. Between updates,
  `PathEntriesFor()` resolves tags against the stored
  snapshot.
- For a given `(srcNode, dstPeer)` pair, returns the
  `[]PathEntry` ordered list and the zero-based index of the
  matched rule.
- Tags are resolved against the current netmap peer list.
- Exposes `CandidateRelayChains(selfNode, dstPeer)` for
  multi-hop relay candidate resolution and
  `SingleHopRelayNodesFor(entries)` for the relay manager's
  single-hop candidate filtering. `CandidateRelayChains` is
  implemented and tested but not yet called by the relay
  manager — the client-side multi-hop chain session
  management that would drive it is deferred (see §8.2).

**No sequential fallback.** All candidate paths are
discovered in parallel and compared by policy index via
`betterAddrWithPolicy`. If the highest-priority path type is
unavailable (e.g., all policy relay nodes fail allocation),
the client uses whatever is available among the remaining
entries. Explicit sequential fallback with per-entry timeouts
is not implemented and could be added as future work.

Implemented public API:

```go
func (e *Engine) Update(nm *netmap.NetworkMap)
func (e *Engine) PathEntriesFor(selfNode, dstPeer tailcfg.NodeView) []tailcfg.PathEntry
func (e *Engine) PathEntriesAndRuleIdxFor(selfNode, dstPeer tailcfg.NodeView) ([]tailcfg.PathEntry, int)
func (e *Engine) CandidateRelayChains(selfNode, dstPeer tailcfg.NodeView) [][][]tailcfg.NodeView
func (e *Engine) SingleHopRelayNodesFor(entries []tailcfg.PathEntry) []tailcfg.NodeView
func AFAllowed(af tailcfg.PathEntryAF, addr netip.Addr) bool
```

### 6.2 Tag resolution

```go
// nodeMatchesTags returns true if the node carries any of the given tags.
func nodeMatchesTags(node tailcfg.NodeView, tags []string) bool

// nodesForTag returns all peers in the netmap that have the given tag.
func nodesForTag(nm *netmap.NetworkMap, tag string) []tailcfg.NodeView
```

For a relay chain `["tag:us-relays", "tag:hk-relays"]`:

- Hop 1 nodes = `nodesForTag(nm, "tag:us-relays")`
- Hop 2 nodes = `nodesForTag(nm, "tag:hk-relays")`

For single-hop relay, `SingleHopRelayNodesFor` collects
matching nodes and passes their keys to the relay manager,
which tries to allocate on each. Multi-hop chain allocation
from the relay manager is not yet implemented (see §8.2).

### 6.3 Integration with `betterAddr()`

`betterAddr()` in
[wgengine/magicsock/endpoint.go](../wgengine/magicsock/endpoint.go)
ranks paths purely by latency (`direct > peer-relay > DERP`).
Path policy overrides this with **array-index priority**: index
0 in the matched rule's `Path` list is the highest priority,
index 1 is next, and so on — regardless of latency. A relay at
index 0 beats a direct path at index 1 even if the direct path
has 1 ms RTT.

Three new functions on `endpoint` implement this, all called
with `de.mu` held:

#### `policyIdxForAddrLocked`

Maps a candidate `addrQuality` to its position in
`de.pathEntries` (the `Path` slice for the matched rule). A
path type absent from the policy is assigned `len(pathEntries)`
— the lowest possible priority.

```go
func (de *endpoint) policyIdxForAddrLocked(aq addrQuality) int {
    isDirect := !aq.vni.IsSet()
    for i, e := range de.pathEntries {
        if isDirect && e.Type == tailcfg.PathEntryDirect { return i }
        if !isDirect && e.Type == tailcfg.PathEntryRelay  { return i }
    }
    return len(de.pathEntries) // not present in policy → worst priority
}
```

#### `betterAddrWithPolicy`

Wraps the package-level `betterAddr()` with a policy-index
pre-check. If both candidates are in the same policy tier,
latency scoring breaks the tie as usual.

```go
func (de *endpoint) betterAddrWithPolicy(a, b addrQuality) bool {
    if len(de.pathEntries) > 0 {
        aIdx := de.policyIdxForAddrLocked(a)
        bIdx := de.policyIdxForAddrLocked(b)
        if aIdx != bIdx {
            return aIdx < bIdx  // lower index = higher priority
        }
    }
    return betterAddr(a, b)  // same tier or no policy → latency wins
}
```

This replaces both `betterAddr()` call sites in `endpoint.go`:

- `udpRelayEndpointReady` — comparing an incoming relay path
  against `de.bestAddr`
- `handlePongConnLocked` — comparing a direct pong against
  `de.bestAddr`

#### Changes to `endpoint.go` for policy enforcement

Replacing `betterAddr` with `betterAddrWithPolicy` alone is
not sufficient. Three additional changes in `endpoint.go` are
required for policy to take effect:

**1. `directAllowedLocked` distinguishes "no policy" from
"policy without direct entry."** Without a policy, direct is
always allowed. With a policy that omits `direct`, direct is
prohibited:

```go
func (de *endpoint) directAllowedLocked(addr netip.Addr) bool {
    if len(de.pathEntries) == 0 {
        return true // no policy applies; direct is always allowed
    }
    for _, e := range de.pathEntries {
        if e.Type == tailcfg.PathEntryDirect {
            return pathpolicy.AFAllowed(e.AF, addr)
        }
    }
    return false // policy applies and has no direct entry → direct prohibited
}
```

**2. `wantUDPRelayPathDiscoveryLocked` consults
`directAllowedLocked` before suppressing relay discovery.**
The original code unconditionally skipped relay discovery when
`bestAddr` was a trusted direct path. Under a relay-only
policy, relay discovery must still run:

```go
if de.bestAddr.isDirect() && now.Before(de.trustBestAddrUntil) {
    if de.directAllowedLocked(de.bestAddr.ap.Addr()) {
        return false  // trusted direct AND policy-permitted: no relay needed
    }
    // policy prohibits direct; continue to discover relay paths
}
```

**3. `betterAddrWithPolicy` replaces `betterAddr()` at both
call sites** (`udpRelayEndpointReady` and
`handlePongConnLocked`). The original `betterAddr()` hardcodes
`direct > relay`. Under a relay-first policy, the relay's
policy index (e.g., 0) must beat the direct path's index.

---

## 7. Multi-hop Relay Chain Protocol

Single-hop peer relay already exists. Multi-hop requires
extending both the relay server and the relay manager.

### 7.1 Terminology

- **Hop-N relay** — a Tailscale node acting as relay server at
  position N in the chain.
- **VNI** — Geneve Virtual Network Identifier, used today to
  identify single-hop relay sessions.
- **Chain session** — a coordinated set of VNI sessions that
  form a forwarding path.

### 7.2 Forwarding without decryption

For a chain `src → R1 → R2 → dst`:

```
src                R1                  R2                dst
 |                  |                   |                  |
 |-- [Geneve VNI_A]→|                   |                  |
 |   [WG packet]   rewrite+forward      |                  |
 |                  |-- [Geneve VNI_B]→ |                  |
 |                  |   [WG packet]    rewrite+forward     |
 |                  |                   |-- [Geneve VNI_C]→|
 |                  |                   |   [WG packet]   decrypt(WG)
```

- At each relay the **WireGuard payload is untouched**.
- The relay rewrites only the **outer Geneve header VNI** when
  forwarding.
- Relays maintain a forwarding table:
  `VNI_in → (next_hop_addr, VNI_out)`.

### 7.3 Chain session establishment

Establishment is driven by `src`, coordinated via DERP messages
to each relay in turn (same out-of-band channel used by existing
single-hop allocation — see
[disco/disco.go](../disco/disco.go)):

**Step 1 — Allocate at the final relay (R2), working inward:**

1. `src` sends `AllocateUDPRelayEndpointRequest` over DERP to
   R2. New field: `ChainNextHop = dst_endpoint`.
2. R2 allocates `VNI_C`, stores `(VNI_C → dst_endpoint)`,
   responds with `R2_endpoint + VNI_C`.
3. `src` performs the 3-way `BindUDPRelayEndpoint` handshake
   with R2.

**Step 2 — Allocate at each intermediate relay (R1):**

1. `src` sends `AllocateUDPRelayEndpointRequest` to R1.
   New fields: `ChainNextHop = R2_endpoint`,
   `ChainNextHopVNI = VNI_B`.
2. R1 allocates `VNI_A`, stores
   `(VNI_A → (R2_endpoint, VNI_B))`, responds with
   `R1_endpoint + VNI_A`.
3. `src` performs 3-way bind handshake with R1.

**Step 3 — End-to-end liveness probe:**

- `src` sends a disco ping through the chain:
  `src → R1(VNI_A) → R2(VNI_B) → dst`.
- `dst` receives the ping, replies with a pong back through the
  same chain.
- `src` receiving the pong confirms the full path is live.
- Path is installed as `bestAddr` if it wins
  `betterAddrWithPolicy()`.

### 7.4 Relay server changes (`net/udprelay`)

The relay server gains a new forwarding mode alongside the
existing peer-pair mode:

```go
// ChainForwardEntry maps an inbound VNI to an outbound (addr, VNI) pair.
// When a packet arrives on VNI_in, the relay forwards it (WG payload
// unchanged, Geneve VNI rewritten to VNI_out) to NextHop.
type ChainForwardEntry struct {
    VNI_in  uint32
    NextHop netip.AddrPort
    VNI_out uint32
}
```

The packet receive loop gains one branch:

```
recv packet with VNI_in:
  if paired session exists → forward to partner           (existing)
  if chain entry exists    → rewrite VNI, forward to NextHop  (NEW)
  else                     → drop
```

No WireGuard decryption occurs in either branch.

### 7.5 Disco protocol extensions

New fields on existing message types (backward-compatible; old
nodes ignore unknown fields):

```go
// In AllocateUDPRelayEndpointRequest (disco/disco.go):
ChainNextHop    netip.AddrPort  // if set, relay creates a chain entry
ChainNextHopVNI uint32          // VNI to use when forwarding to ChainNextHop
```

Capability gating: a `PeerCapabilityRelayChainTarget`
constant is defined for relay nodes that support chain
forwarding. The client-side enforcement check is not yet
wired — this must be added before merging so that old relay
nodes are never sent chain allocation requests they don't
understand.

---

## 8. Relay Manager Changes (`wgengine/magicsock/relaymanager.go`)

### 8.1 Implemented: single-hop relay candidate filtering

This prototype implements single-hop policy-directed relay
filtering. Multi-hop client-side chain session management is
deferred (see §8.2); the server-side chain plumbing is in
place for future use.

What was actually built:

- `policyRelayNodeKeys []key.NodePublic` is added to
  `endpointWithLastBest`. When `SetPathPolicy` fires,
  `pathpolicy.Engine.SingleHopRelayNodesFor(entries)` resolves
  the single-hop relay policy entries for each peer and stores
  the resulting node keys.
- `startUDPRelayPathDiscoveryFor` accepts the keys as a 4th
  parameter.
- Inside `allocateAllServersRunLoop`, if `policyRelayNodeKeys`
  is non-empty, a filter set is built and any candidate server
  whose node key is not in the set is skipped. When the list is
  empty (no policy applies) the existing behaviour — try all
  known peer relays — is unchanged.
- `matchedPolicyRuleIdx int` is stored on `endpoint` so the
  matched rule index is available for debug output.

### 8.2 Multi-hop chain session management (future work)

The server-side chain forwarding plumbing is implemented and
tested:

- `AllocateChainEndpoint` on the relay server accepts
  `ChainNextHop` / `ChainNextHopVNI` and creates a VNI
  forwarding entry.
- `handlePacket` has a chain branch that rewrites the Geneve
  VNI and forwards to the next hop.
- `disco.AllocateUDPRelayEndpointRequest` carries the chain
  fields on the wire.
- `pathpolicy.Engine.CandidateRelayChains` resolves policy
  tags to candidate node lists for each hop.

What is **not** yet implemented is the client-side relay
manager code that would tie these pieces together:

1. Call `CandidateRelayChains(src, dst)` to get candidate
   nodes per hop.
2. Allocate VNIs back-to-front: allocate at the last relay
   first (closest to `dst`), then work backward, passing
   each relay's address and VNI as `ChainNextHop` /
   `ChainNextHopVNI` to the next relay in the chain.
3. Manage chain session lifecycle (retry, teardown, health
   checks).
4. Teach `betterAddrWithPolicy` to score chain paths.

### 8.3 Path priority enforcement

On `startDiscovery(ep)`, the manager now passes
`de.policyRelayNodeKeys` to `startUDPRelayPathDiscoveryFor`.
Only relay servers in the policy set are contacted. If no policy
applies, all known servers are tried (original behaviour).

---

## 9. Fallback and Monitoring

### 9.1 Path selection behavior

All candidate paths (direct, relay, DERP) are discovered in
parallel. `betterAddrWithPolicy` selects the available
candidate with the lowest policy index. There is no sequential
per-entry timeout; if a higher-priority path type has no
available candidate, the next-best available path is used.

If a higher-priority path later becomes available (e.g., NAT
traversal succeeds after relay was already installed),
`betterAddrWithPolicy` switches to it. A path stays in use
until `trustBestAddrUntil` expires and the probe fails, or a
better path is found.

### 9.2 New path type labels

Extend constants in
[wgengine/magicsock/magicsock.go](../wgengine/magicsock/magicsock.go):

```go
PathPeerRelayChainIPv4 Path = "peer_relay_chain_ipv4"
PathPeerRelayChainIPv6 Path = "peer_relay_chain_ipv6"
```

### 9.3 Metrics

Add chain path counters to the `metrics` struct
([magicsock.go](../wgengine/magicsock/magicsock.go)):

```go
inboundPacketsPeerRelayChainIPv4Total  expvar.Int
outboundPacketsPeerRelayChainIPv4Total expvar.Int
// ... bytes variants, IPv6 variants ...
```

### 9.4 Debug CLI

Implemented in this prototype:

- `tailscale debug peer-relay-sessions` — extended to show
  active chain forwarding entries (`ChainSessions`) alongside
  regular peer sessions (VNI, NextHop addr:port, outbound VNI).
- `tailscale debug set-path-policy --file <policy.json>` —
  injects a `PathPolicy` override into the local `tailscaled`
  without going through the control plane. Useful for
  real-world testing before the online policy editor supports
  the `PathPolicy` field. Pass `--clear` to remove the
  override.

Not yet implemented:

- Per-hop RTT display (requires relay nodes to reflect
  timestamps; deferred).

---

## 10. Implementation Phases

Each phase maps to a separate commit against `main`.

### Phase 1 — Data structures (no behavior change)

**Commit subject:**
`tailcfg,types/netmap: add PathPolicy types for policy-based routing`

Files:
- [tailcfg/tailcfg.go](../tailcfg/tailcfg.go) —
  `PathPolicy`, `PathRule`, `PathEntry`, `PathEntryAF`;
  `MapResponse.PathPolicy`; capability version 134;
  `NodeAttrPathPolicyRouting`.
- [types/netmap/netmap.go](../types/netmap/netmap.go) —
  expose `PathPolicy` from `NetworkMap`.
- [control/controlclient/map.go](../control/controlclient/map.go) —
  parse `PathPolicy` from `MapResponse`.

Tests: JSON round-trip of new types; unknown fields ignored by
old capability version.

### Phase 2 — Path policy engine

**Commit subject:**
`wgengine/pathpolicy: add path policy engine for tag-based route selection`

Files (new package):
- `wgengine/pathpolicy/pathpolicy.go` — `Engine`: tag→node
  resolution, rule matching, candidate chain generation.
- `wgengine/pathpolicy/pathpolicy_test.go`

Files changed:
- [wgengine/magicsock/magicsock.go](../wgengine/magicsock/magicsock.go) —
  instantiate/update `Engine` in `SetNetworkMap()`.
- [wgengine/magicsock/endpoint.go](../wgengine/magicsock/endpoint.go) —
  `betterAddrWithPolicy` replaces `betterAddr()` at both call
  sites; `directAllowedLocked`, `policyIdxForAddrLocked` added;
  AF constraint applied to candidate addresses.

Tests: rule matching with synthetic netmaps; `betterAddr()`
policy filtering; AF restriction.

### Phase 3 — Relay server chain forwarding

**Commit subject:**
`net/udprelay,disco: add chain forwarding support for multi-hop relay`

Files:
- [net/udprelay/server.go](../net/udprelay/server.go) —
  `ChainForwardEntry` table; handler for `ChainNextHop` in
  allocation request; chain branch in packet receive loop.
- [disco/disco.go](../disco/disco.go) —
  `ChainNextHop`/`ChainNextHopVNI` on
  `AllocateUDPRelayEndpointRequest`.
- [tailcfg/tailcfg.go](../tailcfg/tailcfg.go) —
  `PeerCapabilityRelayChainTarget` constant.

Tests: two-hop and three-hop chain forwarding with synthetic
UDP; old relay server ignores unknown fields.

### Phase 4 — Policy-directed relay candidate filtering

**Commit subject:**
`wgengine/magicsock: filter relay candidates by path policy`

> **Note:** The full multi-hop chain session management is
> deferred. Phase 4 as implemented is narrower: single-hop
> relay discovery is filtered to only the nodes named by the
> policy. The server-side chain plumbing from Phase 3 is in
> place for future multi-hop work.

Files changed:
- [wgengine/magicsock/relaymanager.go](../wgengine/magicsock/relaymanager.go) —
  `policyRelayNodeKeys` in `endpointWithLastBest`; filter logic
  in `allocateAllServersRunLoop`.
- [wgengine/magicsock/endpoint.go](../wgengine/magicsock/endpoint.go) —
  `policyRelayNodeKeys` and `matchedPolicyRuleIdx` on
  `endpoint`; `setPathEntriesLocked` updated.
- [wgengine/magicsock/magicsock.go](../wgengine/magicsock/magicsock.go) —
  `SetPathPolicy` calls `PathEntriesAndRuleIdxFor` +
  `SingleHopRelayNodesFor` and propagates keys to each endpoint.
- [wgengine/pathpolicy/pathpolicy.go](../wgengine/pathpolicy/pathpolicy.go) —
  `SingleHopRelayNodesFor`, `PathEntriesAndRuleIdxFor`.

Tests: `TestRelayManager*` updated; relay server policy
filtering verified.

### Phase 5 — Observability & CLI

**Commit subject:**
`cmd/tailscale,ipn,net/udprelay/status: add chain relay observability and debug policy override`

Files:
- [net/udprelay/status/status.go](../net/udprelay/status/status.go) —
  `ChainSession` type; `ChainSessions []ChainSession` on
  `ServerStatus`.
- [net/udprelay/server.go](../net/udprelay/server.go) —
  `GetChainSessions()` method.
- [feature/relayserver/relayserver.go](../feature/relayserver/relayserver.go) —
  `GetChainSessions()` added to `relayServer` interface;
  `serverStatus()` populates `ChainSessions`.
- [cmd/tailscale/cli/debug-peer-relay.go](../cmd/tailscale/cli/debug-peer-relay.go) —
  chain session display in `peer-relay-sessions` output.
- [wgengine/magicsock/magicsock.go](../wgengine/magicsock/magicsock.go) —
  `PathPeerRelayChainIPv4`/`PathPeerRelayChainIPv6` constants.
- [ipn/ipnlocal/local.go](../ipn/ipnlocal/local.go) —
  `debugPathPolicy` override field; `DebugSetPathPolicy()`
  method; override applied in `setNetMapLocked`.
- [ipn/localapi/debug.go](../ipn/localapi/debug.go) —
  `POST /localapi/v0/debug-path-policy` handler.
- [client/local/local.go](../client/local/local.go) —
  `DebugSetPathPolicy()` on `Client`.
- [cmd/tailscale/cli/debug.go](../cmd/tailscale/cli/debug.go) —
  `tailscale debug set-path-policy` subcommand
  (`--file`, `--clear`).

---

## 11. Security Considerations

1. **Same trust model as existing peer relay.** Chain
   forwarding reuses the same UDP sockets, Geneve protocol,
   packet receive loop, and DERP-authenticated allocation
   path as single-hop peer relay. No new listeners, protocols,
   or authentication mechanisms are introduced. The per-packet
   operation is a VNI lookup and 4-byte header rewrite —
   strictly simpler than single-hop relay which additionally
   does peer binding validation. WireGuard traffic is
   end-to-end encrypted between `src` and `dst`; intermediate
   relays forward opaque datagrams.
2. **VNI integrity.** Each relay verifies VNI against its
   forwarding table before forwarding; entries are immutable
   after creation. The VNI is also carried inside the
   disco-sealed `BindUDPRelayEndpointCommon` message, so
   tampering with the Geneve cleartext header is detectable.
3. **Capability gating (not yet enforced).**
   `PeerCapabilityRelayChainTarget` is defined but the
   client-side check is not yet wired. Before merging, the
   client must verify this capability before sending chain
   allocation requests. For single-hop relay,
   `PeerCapabilityRelayTarget` is already enforced client-side
   in `magicsock.updateRelay()` via `nodeHasCap()`.
4. **Amplification.** A relay forwards only to the `NextHop`
   registered at session allocation time. That address is set
   by an authenticated, capability-bearing node via DERP and
   is immutable for the session lifetime.
5. **Loop prevention.** The client engine refuses any chain
   that includes itself or the destination node. The control
   plane should additionally reject cycles at policy parse
   time.
