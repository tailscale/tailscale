# Proposal: direct domain exclusions for exit nodes

Status: proposed; no change to client behavior.

Tracking issue: [#15521](https://github.com/tailscale/tailscale/issues/15521).

## Problem

Some services reject traffic from VPN exit nodes. Users must currently turn off
their exit node or send the affected traffic through an app connector. Turning
off the exit node also sends unrelated traffic outside the VPN. An app connector
changes the source address to another machine's address, rather than using the
client's own internet connection.

Allow a client to keep its exit node selected while connecting directly to a
small, explicit set of domains. Banking and shopping services, and specific R2
or S3 download endpoints, are examples. This should work with both ordinary and
Mullvad exit nodes.

## Configuration

Start with a local preference, exposed through `tailscale set`, rather than a
new ACL construct. ACL grants allow connections; they do not select the client's
internet egress path. The flag name below is a proposal, not an available option:

```
tailscale set --exit-node-exclude-domains=example.com,*.example.com
```

An exact name matches only that name. `*.example.com` matches its subdomains,
but not the apex or `notexample.com`. Normalize case and trailing dots, and
reject URLs, ports, empty labels, and wildcards anywhere except the leftmost
label. An empty value clears the list. Do not ship service-specific presets:
storage downloads may use custom domains, and a service's dependencies can
change independently of the client.

Exclusions take effect only while using an exit node. Disabling the exit node,
removing an exclusion, switching profiles, or shutting down clears its derived
state. A reconnect or exit-node change must rebuild the state before releasing
DNS answers that depend on it.

Managed clients need a policy controlling whether local exclusions are allowed.
A forced exit node must not become bypassable through this preference by
default. Control-plane configuration and GUI controls can follow once the local
semantics and policy interaction are agreed.

## DNS and routing

Observe successful responses to matching queries through Tailscale's resolver.
Follow answer-section CNAME chains from the queried name to terminal A and AAAA
records. Do not learn unrelated addresses from additional records or promote a
CNAME target into a permanent domain exclusion. Validate the complete response
before changing routing state; truncated or malformed responses add no routes.

Keep the discovered addresses in memory with their originating query and
expiry. The usable lifetime is bounded by the address TTL and every CNAME TTL
on its path. Retain an address while any configured domain has an unexpired
reference to it. Expire references without requiring another DNS query, and
bound the number of retained entries. Do not persist learned routes across
daemon restarts.

Install the derived IPv4 /32 and IPv6 /128 exceptions before returning the DNS
answer. If installation fails or capacity is exhausted, return a DNS failure
rather than silently promise direct access. Route updates need an acknowledgement
from the platform adapter; enqueueing an asynchronous update is not sufficient.
TTL-zero answers and connections surviving DNS expiry need an explicit lifetime
decision before implementation.

Preserve tailnet destinations, accepted subnet routes, and app connector routes.
An exclusion must not redirect those destinations to the public network. Keep
the exit-node default routes and existing LAN-access behavior for everything
else. Restrict initial support to platforms where both route precedence and
kill-switch exceptions can be verified.

The existing `router.Config.LocalRoutes` is a possible platform handoff, but it
means "outside Tailscale", not "outside the exit node". It must not be populated
blindly from DNS. Linux has throw-route support; Windows also has firewall
exceptions to coordinate. The standalone BSD router does not currently consume
`LocalRoutes`. macOS and iOS network-extension integration needs review in the
platform wrappers, which are outside this repository.

`net/dns.Manager.Query` is a candidate response observation point. Its current
response mapper runs under the DNS manager lock and is also used by app
connectors. Avoid replacing that mapper or applying backend/router updates
while holding the DNS lock. Define the ordering with app connector address
rewriting and a cancellable route-installation barrier first.

## Limits

This is DNS-derived IP routing, not URL or application routing. If an excluded
domain and another service share an IP, traffic to that IP may also go direct
while the exception exists. The client must explain this when enabling the
feature. It cannot distinguish downloads from uploads to the same endpoint.

Applications using private DoH/DoT resolvers, previously cached answers, or
literal IP addresses may bypass DNS observation. Such traffic keeps using the
exit node unless its destination already has a learned exception. DNS itself
should keep the existing exit-node behavior; excluding a domain should not
silently change the DNS privacy setting.

HTTPS/SVCB address hints and alternative endpoints need a defined treatment.
The initial implementation should learn only validated A/AAAA answers and
document the resulting coverage, rather than infer that an entire service is
excluded from one hostname.

## Validation before enabling

Unit tests should cover matching boundaries, normalization, CNAME chains and
loops, both address families, malformed and truncated responses, unrelated
records, shared addresses, TTL expiry, bounded state, and configuration removal.
Backend tests should cover route-installation failure, update ordering, profile
changes, shutdown, and managed-policy precedence.

Platform tests need to exercise the actual routing and firewall behavior: an
excluded endpoint sees the client's ISP address, an unrelated endpoint sees
the exit-node address, and tailnet/subnet destinations remain reachable through
Tailscale. Repeat with the exit node unavailable, network changes, IPv6-only
connectivity, and active connections at expiry. Unsupported platforms must
reject the setting rather than accept it without providing direct routing.

## Decisions requested

* Is a local preference the right first configuration surface?
* Is the shared-IP limitation acceptable, or should this require an explicit
  IP-based opt-in instead?
* How should TTL-zero answers and existing connections at expiry behave?
* Which platforms can acknowledge completed route and firewall updates, and
  how should managed clients authorize these exceptions?
