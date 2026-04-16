# Proposal: Conn25 Config Rearrangement

## Context

The self-routed domains work introduced a split config model so that
`Conn25` could track two independent sources of truth:

1. **Node view config** (`nodeViewConfig`) -- derived from the self
   node's CapMap, which carries the policy (apps, domains, connector
   tags, IP pools). Updated via the `OnSelfChange` hook.
2. **Prefs config** (`prefsConfig`) -- derived from the user's prefs,
   specifically `AppConnector.Advertise`. Updated via the
   `ProfileStateChange` hook.

Both are needed to decide whether a domain is "self-routed" (i.e. this
node is itself a connector for that domain and should *not* rewrite DNS
or allocate magic/transit IPs for it). The check is:

```go
func (c config) isSelfRoutedDomain(d dnsname.FQDN) bool {
    return c.prefs.isEligibleConnector && c.nv.selfDomains.Contains(d)
}
```

The current implementation stores a composite `config` struct (wrapping
`nodeViewConfig` + `prefsConfig`) inside both `client` and `connector`,
and uses a read-modify-write pattern to update it. This proposal
explains why we should restructure it.

## Problems with the current layout

### 1. Read-modify-write on a shared config

`onSelfChange` and `profileStateChange` both follow this pattern:

```go
cfg := e.conn25.client.getConfig()   // read current config
cfg.nv = nvCfg                        // modify one half
e.conn25.reconfig(cfg)                // write it back
```

This works *only* because we assume the two hooks never fire
concurrently. But the pattern is fragile -- if that assumption ever
breaks, one hook's update silently overwrites the other's. And even
when correct, it's hard to reason about: a reader has to verify the
concurrency contract to trust the code.

### 2. Config duplicated across client and connector

`Conn25.reconfig` forwards the same `config` to both `client.reconfig`
and `connector.reconfig`, each of which stores its own copy under its
own mutex. This means:

- Two copies of the same data, both guarded by different mutexes.
- The connector's copy is only used for a single lookup
  (`appsByName` in `handleTransitIPRequest`), making the duplication
  wasteful.
- `TestReconfig` asserts
  `reflect.DeepEqual(c.client.config, c.connector.config)` -- an
  invariant that only exists because the design requires it.

### 3. Boundary checks buried in leaf methods

IP-set membership checks (e.g. "is this magic IP actually in our
configured pool?") live inside `client.transitIPForMagicIP` and
`connector.realIPForTransitIPConnection`. These are internal methods
that shouldn't need to know about the global config -- they just do
lookups in their local maps. Mixing boundary validation with map
lookups makes both harder to test and reason about.

### 4. Methods on the wrong receiver

`mapDNSResponse`, `rewriteDNSResponse`, and `isConnectorDomain` live
on `client`, but they need both config data (to check self-routed
domains, look up app names) and client state (to reserve addresses).
This forces `client` to own the config, which cascades into the
problems above.

## Hooks naturally belong on Conn25, not client or connector

A node running conn25 is simultaneously a client *and* a connector (or
at least might be -- it depends on config and prefs). Most of the hooks
installed in `installHooks` don't know at registration time which role
they're serving, and many can't know at call time either without
consulting config first. Consider the concrete examples:

**DNS response mapping** (`SetQueryResponseMapper`). When a DNS
response arrives, the hook needs to decide: is this domain one we
should rewrite with magic IPs (client behavior), or is it a domain we
ourselves serve as a connector (self-routed, so leave it alone)? That
decision requires both the config (`appNamesByDomain`, `selfDomains`)
and the prefs (`advertiseConnectorPref`). Only after that triage does
the actual client work (reserving addresses, rewriting the packet)
begin. This is fundamentally a `Conn25`-level concern.

**IPMapper methods** (`ClientTransitIPForMagicIP`,
`ConnectorRealIPForTransitIPConnection`). The datapath handler calls
these on `Conn25` -- it doesn't know (or care) whether the packet is a
client flow or a connector flow. `Conn25` checks the IP sets from
config to decide which sub-component to dispatch to. The current code
pushes those checks down into `client` and `connector`, but the
datapath already calls `Conn25` -- so the boundary check is in the
wrong place.

**Transit IP request handling** (`handleConnectorTransitIPRequest`).
When a peer sends a `/v0/connector/transit-ip` PeerAPI request, the
handler needs to validate the app name against config *before* handing
individual requests to the connector. The app name lookup is a
config concern; only the actual transit-IP-to-destination mapping is a
connector concern.

**Packet filter hooks** (`LinkLocalAllowHooks`, `IngressAllowHooks`).
These are the exception -- they *do* delegate directly to `client` or
`connector` because they're checking IP-specific state that already
lives on the right sub-component. But even these are registered at the
extension level and gated on `conn25.isConfigured()`.

The current layout already registers all hooks on `extension` /
`Conn25` and has them call into `client` or `connector`. But methods
like `mapDNSResponse` and `isConnectorDomain` live on `client`, so
the "pass through" is just `Conn25` immediately delegating to
`client` -- as if we already know the answer is "this is client
work." That assumption was never accurate: the self-routed domain
check made it explicit that we have to inspect config at the `Conn25`
level before we know which sub-component (if any) should act.

## Proposed changes

### Move config to Conn25, not client/connector

```go
type Conn25 struct {
    mu                     sync.Mutex
    config                 config          // single source of truth
    advertiseConnectorPref bool            // from prefs, set independently
    client                 *client
    connector              *connector
}
```

`config` would be the current `nodeViewConfig` (renamed back to
`config`). The prefs-derived state becomes a single `bool` field on
`Conn25`. No wrapper struct, no `prefsConfig` type, no nested
`nv`/`prefs` fields.

### Eliminate read-modify-write

The two hooks would update orthogonal fields with no overlap:

```go
func (e *extension) onSelfChange(selfNode tailcfg.NodeView) {
    cfg, err := configFromNodeView(selfNode)
    // ...
    e.conn25.reconfig(cfg)       // replaces config wholesale
}

func (e *extension) profileStateChange(...) {
    e.conn25.advertiseConnectorPref = prefs.AppConnector().Advertise
}
```

`onSelfChange` replaces the entire config. `profileStateChange` sets a
bool. Neither reads-then-modifies the other's data, so there is no
TOCTOU window even in theory.

### Remove config from connector

The only thing the connector needs from config is the `appsByName`
map to validate incoming transit IP requests. That check should be done
in `Conn25.handleConnectorTransitIPRequest` *before* calling into the
connector, using `c.config.appsByName` directly. The connector struct
would have no `config` field at all, and `connector.reconfig` would be
deleted.

### Move boundary checks to the boundary

IP set membership checks would move from `client.transitIPForMagicIP` /
`connector.realIPForTransitIPConnection` up to `Conn25`'s public
`ClientTransitIPForMagicIP` / `ConnectorRealIPForTransitIPConnection`
methods:

```go
func (c *Conn25) ClientTransitIPForMagicIP(m netip.Addr) (netip.Addr, error) {
    if !c.config.v4MagicIPSet.Contains(m) && !c.config.v6MagicIPSet.Contains(m) {
        return netip.Addr{}, nil
    }
    return c.client.transitIPForMagicIP(m)
}
```

The internal `client` and `connector` methods would only deal with
their own maps -- they wouldn't need to reference the global config at
all.

### Move methods to the right receiver

`mapDNSResponse`, `rewriteDNSResponse`, `isConnectorDomain`, and
`isSelfRoutedDomain` would move from `client` to `Conn25`. These
methods need access to both config and client internals, so `Conn25`
(which owns both) is the natural home.

Similarly, `reserveAddresses` would take an `app` parameter instead of
looking up `appNamesByDomain` internally. The app-name lookup would
happen in `rewriteDNSResponse` (on `Conn25`, which has the config),
and the resolved app name would be passed down. This keeps
`client.reserveAddresses` focused on IP allocation. The
pass-through-to-client pattern goes away because the hooks that used it
were never pure client work to begin with.

## Summary of proposed changes

| Aspect | Current | Proposed |
|---|---|---|
| Config location | Duplicated in `client` and `connector` | Single copy on `Conn25` |
| Prefs state | `prefsConfig` struct inside composite `config` | `bool` field on `Conn25` |
| Config update | Read-modify-write from hooks | `onSelfChange` replaces config; `profileStateChange` sets a bool |
| `connector.config` | Full config copy + own mutex | Removed entirely |
| IP set boundary checks | Inside `client`/`connector` leaf methods | At `Conn25` public API boundary |
| `mapDNSResponse` | Method on `client` | Method on `Conn25` |
| `isConnectorDomain` | Method on `client` | Method on `Conn25` |
| `reserveAddresses` | Looks up app name from config internally | Receives app name as parameter |
| `getConfig()` | Exported from `client` for hooks to read | Removed; not needed |

## Why this is better

1. **Single source of truth.** Config exists in one place. No
   invariant to maintain across two copies.

2. **No TOCTOU risk.** The two config sources (node view, prefs)
   update independent fields. Neither hook reads the other's data
   before writing.

3. **Simpler connector.** The connector becomes purely a map of
   transit-IP-to-real-IP assignments. It doesn't hold or manage config,
   which matches its actual responsibility.

4. **Cleaner layering.** Boundary validation (IP set checks, app name
   lookups) happens at the `Conn25` level. Internal components
   (`client`, `connector`) receive pre-validated inputs and focus on
   their core job.

5. **Less code.** The rearrangement is a net deletion of ~50 lines,
   removing `prefsConfig`, `nodeViewConfig`, `config` wrapper,
   `connector.reconfig`, `client.getConfig`, and the duplicated IP
   set checks.
