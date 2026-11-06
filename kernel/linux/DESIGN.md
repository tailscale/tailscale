# tswg: Tailscale-flavored kernel WireGuard

This is a living design document. It records requirements, decisions (with
their reasons), and the TODO list. Update it whenever something is decided
or changes.

Tracking issue: https://github.com/tailscale/tailscale/issues/426

## Goal

Move the Tailscale data plane on Linux into the kernel. Packets between
Tailscale peers should be encrypted, decrypted and forwarded by a kernel
module without crossing into userspace on the direct (UDP) path. tailscaled
keeps doing everything else: control plane, disco, NAT traversal (STUN,
hole punching), port mapping (UPnP, NAT-PMP, PCP), DERP, and programming
the kernel module.

What we expect to win, and should measure, compared to wireguard-go with
TUN GSO/GRO:

* CPU cost per byte and per packet.
* Latency and small-packet rate.
* Forwarding performance for subnet routers and exit nodes.

Raw single-flow throughput is not the main argument; wireguard-go is
already fast there.

## Non-goals

* Upstreaming. tswg is an out-of-tree module, installed via DKMS or
  similar. We do not depend on upstream WireGuard accepting changes.
* Rust. Decided 2026-11-06: the in-tree Rust networking abstractions are
  too thin (no sk_buff, net_device, UDP tunnel, or lib/crypto bindings) and
  out-of-tree Rust modules need a kernel built with CONFIG_RUST and a
  matching rustc, which most distro kernels can't provide. Revisit later.
* Changing the WireGuard wire protocol. tswg must interoperate with every
  existing Tailscale peer running wireguard-go.
* Multipath or "spray" sending in the kernel. When disco hasn't yet
  trusted a direct path, tailscaled sprays from userspace (see "DERP and
  spray").

## Architecture

```
            tailscaled (userspace)
   control, disco, STUN, portmapper, DERP client
     |  genetlink "tswg"          |  owns the UDP socket(s)
     v                            v
  +---------------------------------------------+
  | tswg.ko  (fork of drivers/net/wireguard)    |
  |  tailscale0 netdev, noise, allowedips, ...  |
  |  encap_rcv on tailscaled's UDP socket:      |
  |    WG messages -> kernel                    |
  |    everything else -> socket receive queue  |
  +---------------------------------------------+
```

### Fork, not patches

tswg is a fork of the in-tree WireGuard driver, kept as close to upstream as
possible so upstream security fixes merge cleanly.

* `upstream/` holds a pristine copy of the upstream files. It is only ever
  replaced wholesale by an import of a newer upstream; see
  `upstream/UPSTREAM_COMMIT`.
* `src/` holds the fork. `diff -r upstream/drivers/net/wireguard src` is
  the fork's delta (plus build files and compat headers).
* Internal symbols keep their `wg_` names. Unexported symbols in two
  modules don't conflict, so tswg.ko and the in-tree wireguard.ko (built-in
  or modular) can be loaded at the same time. Renaming them would make every
  upstream merge painful.
* User-visible identifiers are renamed: module `tswg`, rtnl link kind
  `tswg` (from `KBUILD_MODNAME`), genetlink family `tswg`.
* The uapi stays attribute-compatible with upstream WireGuard. New
  attributes are only ever appended. That way wgctrl-go and a lightly
  patched `wg(8)` keep working by changing only the family name.

### Kernel compatibility

The fork's base is the newest upstream (currently 7.4-rc1). Older kernels
are supported through compat shims in `src/compat/`.

* Prefer feature probes (configure-style compile tests, as in OpenZFS or
  NVIDIA's conftest) over `LINUX_VERSION_CODE` checks. RHEL kernels carry
  years of backports, so version numbers lie.
* Use the kernel's lib/crypto (chacha20poly1305, blake2s, curve25519). Every
  distro kernel that ships WireGuard builds those libraries. Do not vendor
  crypto.
* Minimum kernel: TBD. The first target is Ubuntu 24.04 (6.8).

### Shared UDP socket

Tailscale needs disco, STUN and WireGuard to share one UDP 4-tuple so NAT
mappings discovered by disco are the ones WireGuard uses. Plan, modeled on
ESP-in-UDP (`UDP_ENCAP_ESPINUDP`) and L2TP:

1. tailscaled creates and binds the UDP socket(s) and sets its socket
   options (SO_MARK, buffer sizes, and so on).
2. tailscaled passes the fd to tswg over genetlink (new attributes
   `WGDEVICE_A_TSWG_SOCK_FD4` and `..._FD6`, names TBD).
3. tswg calls `setup_udp_tunnel_sock()` on it with its `encap_rcv`.
4. `encap_rcv` consumes WireGuard messages (types 1-4 with three zero
   reserved bytes) and returns >0 for everything else (disco, STUN), which
   then lands in the socket's normal receive queue for tailscaled's
   `recvmsg`.
5. tailscaled sends disco and STUN with plain `sendmsg` on the same socket.

Socket lifetime: tswg holds a reference to the socket, so the data plane
survives a tailscaled restart. The new tailscaled can't bind the same port
while the kernel holds it, so either put the fd in systemd's fd store
(`FileDescriptorStoreMax=`) or add an explicit "detach socket" op. TBD.

### Endpoints and roaming

Upstream WireGuard roams a peer's endpoint to the source of the latest
authenticated packet. That fights disco's path selection: a packet that
arrives via DERP would steal the endpoint from a good direct path. tswg
adds a per-peer flag (or device-wide default) that disables auto-roaming;
tailscaled sets endpoints explicitly.

Changing a peer's endpoint does not re-key or reset the noise session in
upstream WireGuard either; that is already fine.

### DERP and spray

DERP stays in tailscaled. A peer whose current path is DERP gets a
loopback endpoint (as planned back in 2020):

* Each DERP-pathed peer gets its own address in 127.0.0.0/8 with a common
  port P, so tailscaled can bind one socket on `*:P`, read the destination
  with `IP_PKTINFO` and map it back to the peer. That mapping is needed
  because WireGuard transport messages only carry a receiver index.
* For inbound DERP traffic, tailscaled sends to tswg's socket from
  127.x.y.z:P (setting the source with `ipi_spec_dst`).
* Spray mode (untrusted direct path): tailscaled points the peer at its
  loopback endpoint, forwards each ciphertext packet to DERP, and also
  sends a copy to the candidate direct address via the shared socket (same
  source port). Once disco trusts the direct path, tailscaled switches the
  kernel endpoint to it.

### What doesn't need kernel work

* ACLs: nftables (tailscaled already has nftables and iptables code;
  conntrack handles return traffic).
* MagicDNS, peerapi, Tailscale SSH, Taildrop: kernel sockets on the
  tailscale0 address.
* TSMP: raw socket on IP protocol 99.
* Subnet routers and exit nodes: kernel forwarding.

### Lazy peer configuration

tailscaled only programs recently active peers into wireguard-go, mostly
because of per-peer cost in wireguard-go. Kernel peers are cheap and
hashed, so first try programming every peer. If that doesn't scale, add an
unknown-peer upcall from `wg_noise_handshake_consume_initiation` with a
short stash of the initiation for replay (to avoid a 5s `REKEY_TIMEOUT`
stall).

### DKMS and fallback

Out-of-tree modules on Secure Boot systems need signing and MOK
enrollment. tailscaled must always fall back to wireguard-go when tswg is
missing, fails to load, or reports an incompatible version (the genetlink
family version or a feature attribute).

## Testbed

Integration tests run as natlab vmtests in tailscale.com
(`tstest/natlab/vmtest`), which boot QEMU VMs connected by vnet, a
simulated network with NATs, DERP and a test control server.

* Guest: the natlab Ubuntu 24.04 cloud image, stock kernel
  `6.8.0-106-generic`. The host is also Ubuntu 24.04 with the same gcc
  (13.3), so the host builds tswg.ko against that kernel's headers,
  fetched with `apt-get download` and unpacked into a cache directory
  (never installed).
* The test copies tswg.ko into the guest (over the debug SSH NIC or the
  vnet file server) and loads it.
* Later: also boot a custom debug kernel (KASAN, lockdep) built from a
  Linux tree, and more distro images (Debian, Fedora) for compat coverage.

## Repo layout

* `DESIGN.md`: this file.
* `upstream/`: pristine upstream sources (see "Fork, not patches").
* `src/`: the tswg module sources, Kbuild and compat headers.
* `scripts/`: helpers (building against a distro kernel's headers,
  importing upstream).

## TODO

- [x] Create repo; import pristine upstream WireGuard (Linux 7.4-rc1).
- [x] Write DESIGN.md.
- [ ] Fork into `src/`: rename module, link kind and genetlink family to
      `tswg`; out-of-tree Kbuild/Makefile.
- [ ] Build against the host's 7.0 headers.
- [ ] Script: fetch and unpack Ubuntu kernel headers for a given version;
      build tswg.ko against them.
- [ ] Compat shims so it builds and loads on Ubuntu 24.04 (6.8).
- [ ] vmtest: two Ubuntu VMs, load tswg.ko, configure a tswg tunnel by
      hand, ping through it.
- [ ] Userspace config tool or Go package (fork of wgctrl's netlink code
      with family `tswg`).
- [ ] Socket fd passing plus `encap_rcv` classifier (WG vs. disco/STUN).
- [ ] vmtest: disco/STUN still reach userspace on the shared socket.
- [ ] Per-peer no-auto-roam flag.
- [ ] Loopback DERP endpoints; vmtest with DERP-only path.
- [ ] tailscaled integration (wgengine backend that programs tswg) on a
      tailscale.com branch.
- [ ] Fallback to wireguard-go when tswg is unavailable.
- [ ] Decide socket lifetime across tailscaled restarts.
- [ ] Decide minimum supported kernel; feature-probe compat framework.
- [ ] dkms.conf and packaging.
- [ ] Benchmarks versus wireguard-go (CPU/byte, pps, latency, forwarding).
- [ ] Custom debug kernel (KASAN, lockdep) in the testbed.
- [ ] UDP GSO/GRO on the encap socket (later perf work).
- [ ] Measure scaling with many peers; unknown-peer upcall only if needed.
