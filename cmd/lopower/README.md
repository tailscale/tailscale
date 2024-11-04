# Tailscale LOPOWER

"Little Opionated Proxy Over Wireguard-encrypted Routes"

**STATUS**: in-development alpha (as of 2024-11-03)
 
## Background

Some small devices such as ESP32 microcontrollers [support WireGuard](https://github.com/ciniml/WireGuard-ESP32-Arduino) but are too small to run Tailscale.

Tailscale LOPOWER is a proxy that you run nearby that bridges a low-power WireGuard-speaking device on one side to Tailscale on the other side. That way network traffic from the low-powered device never hits the network unencrypted but is still able to communicate to/from other Tailscale devices on your Tailnet.

## Features

* Runs separate Wireguard server with separate keys (unknown to the Tailscale control plane) that proxy on to Tailscale
* Outputs WireGuard-standard configuration to enrolls devices, including in QR code form.
* embeds `tsnet`, with an identity on which the device(s) behind the proxy appear on your Tailnet
* optional IPv4 support. IPv6 is always enabled, as it never conflicts with anything. But IPv4 (or CGNAT) might already be in use on your client's network.
* includes a DNS server (at `fd7a:115c:a1e0:9909::1` by default and optionally also at `10.90.0.1`) to serve both MagicDNS names as well as forwarding non-Tailscale DNS names onwards
    * if IPv4 is disabled, MagicDNS `A` records are filtered out, and only `AAAA` records are served.

## Limitations

* this runs in userspace using gVisor's netstack. That means it's portable (and doesn't require kernel/system configuration), but that does mean it doesn't operate at a packet level but rather it stitches together two separate TCP (or UDP) flows and doesn't support IP protocols such as SCTP or other things that aren't TCP or UDP.
* the standard WireGuard configuration doesn't support specifying DNS search domains, so resolving bare names like the `go` in `http://go/foo` won't work and you need
