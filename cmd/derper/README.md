# DERP

This is the code for the [Tailscale DERP server](https://tailscale.com/kb/1232/derp-servers).

In general, you should not need to nor want to run this code. The overwhelming majority of Tailscale users (both individuals and companies) do not.

In the happy path, Tailscale establishes direct connections between peers and
data plane traffic flows directly between them, without using DERP for more than
acting as a low bandwidth side channel to bootstrap the NAT traversal. If you
find yourself wanting DERP for more bandwidth, the real problem is usually the
network configuration of your Tailscale node(s), making sure that Tailscale can
get direction connections via some mechanism.

But if you've decided or been advised to run your own `derper`, then read on.

## Caveats

* Node sharing and other cross-Tailnet features don't work when using custom
  DERP servers.

* DERP servers only see encrypted WireGuard packets and thus are not useful for
  network-level debugging.

* The Tailscale control plane does certain geo-level steering features and
  optimizations that are not available when using custom DERP servers.

## Guide to running `cmd/derper`

* You must build and update the `cmd/derper` binary yourself. There are no
  packages. Use `go install tailscale.com/cmd/derper@latest` with the latest
  version of Go.

* The DERP protocol does a protocol switch inside TLS from HTTP to a custom
  bidirectional binary protocol. It is thus incompatible with many HTTP proxies.
  Do not put `derper` behind another HTTP proxy.

* The `tailscaled` client does its own selection of the fastest/nearest DERP
  server based on latency measurements. Do not put `derper` behind a global load
  balancer.

* DERP servers should ideally have both a static IPv4 and static IPv6 address.
Both of those should be listed in the DERP map so the client doesn't need to
rely on its DNS which might be broken and dependent on DERP to get back up.

* A DERP server should not share an IP address with any other DERP server.

* Avoid having multiple DERP nodes in a region. If you must, they all need to be
  meshed with each other and monitored. Having two one-node "regions" in the
  same datacenter is usually easier and more reliable than meshing, at the cost
  of more required connections from clients in some cases. If your clients
  aren't mobile (battery constrained), one node regions are definitely
  preferred. If you really need multiple nodes in a region for HA reasons, two
  is sufficient.

* Monitor your DERP servers with [`cmd/derpprobe`](../derpprobe/).

* If using `--verify-clients`, a `tailscaled` must be running alongside the
  `derper`.

* If using `--verify-clients`, a `tailscaled` must also be running alongside
  your `derpprobe`, and `derpprobe` needs to use `--derp-map=local`.

* The firewall on the `derper` should permit TCP ports 80 and 443 and UDP port
  3478.

* Only LetsEncrypt certs are rotated automatically. Other cert updates require a
  restart.

* Don't use a firewall in front of `derper` that suppresses `RST`s upon
  receiving traffic to a dead or unknown connection.

* Don't rate-limit UDP STUN packets.

* Don't rate-limit outbound TCP traffic (only inbound).
