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

Performance is the primary motivation for this work (stated
2026-11-06). Everything else is in service of getting the data plane out
of userspace, so every change should be judged by its effect on
performance, and performance must be measured, not assumed.

What we expect to win, compared to wireguard-go with TUN GSO/GRO and UDP
GSO/GRO:

* CPU cost per byte and per packet.
* Latency and small-packet rate.
* Forwarding performance for subnet routers and exit nodes.
* Throughput, especially on small or many-core machines, once outer UDP
  GSO/GRO is in place (see "Performance" below).

## Performance

### What we inherit from upstream WireGuard

* Inner GSO on send: the device advertises GSO (`WG_NETDEV_FEATURES` in
  `device.c`), so the stack hands it large TCP super-packets, which
  `wg_xmit` segments (`skb_gso_segment`) before encrypting each segment.
* Inner GRO on receive: decrypted packets go up through each peer's NAPI
  context with `napi_gro_receive` (`receive.c`), so the stack sees
  coalesced inner packets.
* Parallel encryption and decryption across CPUs (per-device crypt
  workqueue), with per-peer ordering.

### What's missing: outer UDP GSO/GRO

* Send: each encrypted packet is sent as its own UDP datagram through
  `udp_tunnel_xmit_skb`, so every MTU-sized packet pays the full IP/UDP
  output and qdisc/driver cost. Building UDP GSO super-datagrams
  (`SKB_GSO_UDP_L4`) out of a peer's consecutive encrypted packets would
  amortize that, and let NICs with UDP segmentation offload do the
  splitting.
* Receive: the encap socket has no `gro_receive`, so encrypted datagrams
  aren't coalesced; each one goes through the IP/UDP input path
  separately. A `gro_receive`/`gro_complete` pair (as VXLAN, Geneve and
  FOU have) could batch them per flow before decryption.
* These are the kernel analogues of what makes wireguard-go fast. In the
  kernel there are no syscalls to amortize, so the expected win is
  smaller, but it is likely the biggest remaining throughput lever.
  Measure before and after.

### Shared socket and GRO

The UDP stack segments GRO'd UDP packets before handing them to a socket
with `encap_rcv` set (`udp_unexpected_gso`, checked in both 6.8 and 7.4),
so `UDP_GRO` on the shared socket is safe but wasteful: datagrams get
coalesced and then immediately split again. In kernel mode, tailscaled
should not enable `UDP_GRO` (or rely on `UDP_SEGMENT`) on the shared
socket; only low-volume disco and STUN traffic reaches userspace there,
and the module's sends don't go through the socket send path at all.

### Measuring

* A benchmark harness in the natlab testbed (iperf3-style TCP and UDP
  throughput, pps with small packets, latency under load, CPU use via
  `/proc/stat` or perf), comparing tswg against wireguard-go
  (tailscaled in its usual TUN mode) on the same VMs.
* natlab's vnet is a userspace network simulator, so it caps absolute
  numbers. Use it for relative comparisons and regressions; for real
  numbers, also benchmark on bare metal or between cloud VMs with real
  NICs.

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
* The uapi header is `src/include/uapi/linux/tswg.h`. Upstream generates
  it, and `src/generated/netlink.[ch]`, from
  `Documentation/netlink/specs/wireguard.yaml` with YNL. For now we
  hand-edit the generated files; once we add attributes, keep a forked
  spec and regenerate with a kernel tree's `tools/net/ynl/ynl-regen.sh`
  (TODO).

### Kernel compatibility

The fork's base is the newest upstream (currently 7.4-rc1). Older kernels
are supported through compat shims in `src/compat/`.

* Feature probes, not `LINUX_VERSION_CODE` checks (decided 2026-11-06;
  RHEL kernels carry years of backports, so version numbers lie).
  `scripts/probe.sh` compiles each `src/compat/probes/HAVE_*.c` against
  the target kernel's build directory, in parallel (about one second in
  total), and writes `src/compat/generated/autoconf.h`. The top-level
  Makefile runs it before every build.
* `src/compat/compat.h` is force-included into every file and shims
  whatever is missing, mostly as macros or static inlines named like the
  new API, so upstream code stays untouched. The few spots that can't be
  shimmed from a header get small `#ifdef HAVE_...` blocks marked
  `TSWG_COMPAT` in the `.c` files (currently only `device.c`).
* To add a shim: add a probe file, use its `HAVE_` macro in compat.h, and
  build against both an old and a new kernel.
* Use the kernel's lib/crypto (chacha20poly1305, blake2s, curve25519). Every
  distro kernel that ships WireGuard builds those libraries. Do not vendor
  crypto.
* Builds today: Ubuntu 6.8.0-106-generic (the natlab guest) and
  7.0.0-1009-aws (the dev host). The 7.4 path itself (all probes
  succeeding) isn't verified yet, since that needs a configured and built
  7.4 tree.
* Minimum kernel: TBD.

### Userspace (Go) side

Decided 2026-11-06: the Go code lives in tailscale.com, because tailscaled
is what will program the module.

* `tailscale.com/wgengine/tswg`: netlink client for the `tswg` genetlink
  family (configure and dump devices).
* `tailscale.com/cmd/tswgctl`: a wg(8)-like debugging tool built on it.
* This work lives on the `bradfitz/tswg` branch, in a worktree at
  `~/src/tailscale.com-tswg`.

### Shared UDP socket

Tailscale needs disco, STUN and WireGuard to share one UDP 4-tuple so NAT
mappings discovered by disco are the ones WireGuard uses. Implemented
2026-11-06 (`src/socket.c`, "TSWG: user-supplied sockets"), modeled on
L2TP's user-supplied tunnel sockets and ESP-in-UDP:

1. tailscaled creates and binds the UDP socket(s) and sets its socket
   options (SO_MARK, buffer sizes, and so on).
2. tailscaled passes the fds to tswg in `WG_CMD_SET_DEVICE`, as
   `TSWGDEVICE_A_SOCK_FD4` / `TSWGDEVICE_A_SOCK_FD6` (NLA_S32) nested in
   `WGDEVICE_A_TSWG`. The netlink request is processed in the caller's
   context, so `sockfd_lookup` sees the caller's fd table.
3. tswg validates the socket (UDP, the right family, bound, IPv6 sockets
   must be `IPV6_V6ONLY`, not already used by a tunnel), calls
   `setup_udp_tunnel_sock()` with its `encap_rcv` and `encap_destroy`, and
   keeps a reference to the `struct sock` (not the file).
4. `encap_rcv` consumes WireGuard messages (a first byte of 1-4 followed by
   three zero bytes) and returns 1 for everything else, which lands in the
   socket's normal receive queue for tailscaled. Nothing else Tailscale
   sends matches: disco starts with "TS", STUN with 0x00, or 0x01 followed
   by a nonzero byte, and Geneve (peer relay) with 0x00.
5. tailscaled sends disco and STUN with plain `sendmsg` on the same socket.

Details and decisions:

* uapi numbering: all tswg device attributes live in one nested attribute,
  `WGDEVICE_A_TSWG` = 64, far above upstream's (8 today), so upstream can
  keep appending its own without colliding. Peer attributes will get the
  same treatment (`WGPEER_A_TSWG` = 64). Dumps report
  `TSWGDEVICE_A_FLAGS` (`TSWGDEVICE_F_USER_SOCK4/6`).
* Socket lifetime is the lifetime of tailscaled's fd (decided
  2026-11-06). When the process closes the socket (or exits), UDP calls
  our `encap_destroy` and the device drops it, leaving the device with no
  socket for that family until tailscaled passes a new one. No explicit
  detach op is needed for restarts. A restart that keeps the data plane up
  needs the fd to survive it, via systemd's fd store
  (`FileDescriptorStoreMax=`); that's a tailscaled-side TODO.
* Passing -1 detaches the socket, and the device goes back to creating its
  own on its listen port (which fails with EADDRINUSE if tailscaled still
  holds that port).
* The user sockets are kept per device (`tswg_user_sock4/6`) across
  ifdown/ifup; while the device is up they're also its active
  `sock4/sock6`. WireGuard messages arriving while the device is down are
  dropped; everything else still reaches userspace.
* Setting `WGDEVICE_A_LISTEN_PORT` to a different port while a user
  socket is attached fails with EBUSY.
* Detaching restores the socket to plain UDP (`encap_rcv`, `encap_type`,
  `sk_user_data`, checksum conversion). It leaves multicast loopback
  disabled, since we don't know its previous value, and leaves the encap
  static key reference for UDP to drop when the socket is destroyed.
* A global mutex, `tswg_user_sock_lock`, serializes attach and detach,
  including detach from `encap_destroy`, which runs from the user's
  `close()` without any of our locks held. Lock order:
  `device_update_lock`, then `tswg_user_sock_lock`, then
  `socket_update_lock`.
* `UDP_GRO` on the shared socket is safe: the UDP stack segments GRO'd
  packets before handing them to a socket with `encap_rcv` set (checked
  in both 6.8 and 7.4). Making WireGuard itself use GRO is separate perf
  work.
* We set `sk_allocation = GFP_ATOMIC` on the user socket, as WireGuard and
  L2TP do for their sockets, since we send from atomic context.

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
simulated network with NATs, DERP and a test control server. The tests
live in the tailscale.com worktree, in `tstest/natlab/vmtest/tswg_test.go`.
Run them with `scripts/vmtest.sh [TEST_REGEXP]`; it sets `TSWG_DIR` to this
tree, and the tests skip if the tree is missing.

### Primary guest: gokrazy

Decided 2026-11-06: the natlab gokrazy image is the primary test guest.

* It boots a recent upstream kernel (7.2.8 today), from the
  `github.com/gokrazy/kernel.amd64` package pinned in tailscale.com's
  go.mod. A gokrazy bot bumps that package to new kernel releases, and a
  tailscale.com cron bot bumps the go.mod dependency, so the test guest
  follows upstream kernels without anyone doing anything. That keeps the
  fork honest against new kernel APIs, which is where the fork's base is
  anyway.
* Consequence: a gokrazy vmtest failure after a dependency bump most
  likely means kernel API churn that needs a new compat probe and shim
  (or an upstream WireGuard change worth importing), not a test flake.
* gokrazy has no userspace tools (no modprobe, iproute2 or shell), just
  like the end state, where tailscaled drives the kernel entirely. So
  everything is done from Go: `tswg.LoadModule` calls init_module(2) on
  the tswg.ko image, and links and addresses are set up over rtnetlink.
* gokrazy kernels are kernel.org releases plus the patches in
  `_build/series`, with an embedded config (`CONFIG_IKCONFIG`) and without
  MODVERSIONS or module signing. `scripts/gokrazy-kdir.sh` recreates a
  matching module build tree (download, patch, embedded config,
  `modules_prepare`; about 20 seconds, cached). We build with the host's
  gcc 13 while gokrazy uses Debian 12's gcc 12; the only resulting config
  differences are toolchain capability bits. If that ever matters, build
  in a Debian 12 container instead.
* Such a tree has no `Module.symvers`, so modpost can't check the kernel's
  exports (we set `KBUILD_MODPOST_WARN=1`); a missing symbol shows up as a
  load failure instead.
* The test agent (`cmd/tta`) has `/tswg/load` (POST tswg.ko),
  `/tswg/up` (create, configure and bring up a one-peer device),
  `/tswg/show` (device JSON) and `/tswg/dmesg` (kernel log lines
  mentioning tswg, read from /dev/kmsg).
* `TestTSWGGokrazyManualTunnel`: two gokrazy VMs on one LAN, tunnel set up
  through tta, ping across it, and check handshake and byte counters.

### Secondary guest: Ubuntu 24.04

Kept for distro and DKMS-style coverage, since that's how real users will
install the module.

* The natlab Ubuntu 24.04 cloud image, stock kernel `6.8.0-106-generic`.
  The host is also Ubuntu 24.04 with the same gcc (13.3), so
  `scripts/build-for-ubuntu.sh` builds tswg.ko against that kernel's
  headers, fetched with `apt-get download` and unpacked into a cache
  directory (never installed).
* The test asks the guest for `uname -r`, builds tswg.ko and `tswgctl`,
  registers both with the vnet file server, and has the guest curl them
  from `http://52.52.0.6/tswg/<kver>/`, then `depmod` and `modprobe tswg`.
  Commands run as root over the debug SSH NIC.
* `TestTSWGManualTunnel`: the same tunnel check, configured with
  `ip link` and `tswgctl`.

### Later

* A custom debug kernel (KASAN, lockdep) built from a Linux tree, which
  would also cover the 7.4 compat path.
* More distro images (Debian, Fedora) for compat coverage.

## Repo layout

* `DESIGN.md`: this file.
* `upstream/`: pristine upstream sources (see "Fork, not patches").
* `src/`: the tswg module sources, Kbuild and compat headers.
* `scripts/`: `probe.sh` (compat probes), `build.sh` (build tswg.ko
  against a KDIR in a private copy of `src/`), `ubuntu-headers.sh` and
  `build-for-ubuntu.sh` (Ubuntu kernels), `gokrazy-kdir.sh` and
  `build-for-gokrazy.sh` (gokrazy kernels), `extract-ikconfig` (vendored
  from Linux), `vmtest.sh` (run the natlab vmtests).

## TODO

Performance (the primary motivation; see "Performance"):

- [ ] Benchmark harness: tswg vs. wireguard-go (tailscaled TUN mode) on the
      same VMs: TCP/UDP throughput, small-packet pps, latency under load,
      CPU per byte and per packet, subnet router and exit node forwarding.
- [ ] Benchmarks on real NICs (bare metal or cloud VMs), not just natlab.
- [ ] Outer UDP GSO on send: coalesce a peer's consecutive encrypted
      packets into `SKB_GSO_UDP_L4` super-datagrams.
- [ ] Outer UDP GRO on receive: `gro_receive`/`gro_complete` on the encap
      socket to batch encrypted datagrams before decryption.
- [ ] vmtest: shared socket with `UDP_GRO` enabled still works (exercises
      the segment-before-encap_rcv path at runtime).
- [ ] tailscaled: don't enable `UDP_GRO`/`UDP_SEGMENT` on the shared
      socket in kernel mode.
- [ ] Profile the encrypt/decrypt path (workqueue fan-out, per-peer
      ordering) under many-flow and many-peer loads.
- [ ] Measure scaling with many peers; unknown-peer upcall only if needed.

Everything else:

- [x] Create repo; import pristine upstream WireGuard (Linux 7.4-rc1).
- [x] Write DESIGN.md.
- [x] Fork into `src/`: rename module, link kind and genetlink family to
      `tswg`; out-of-tree Kbuild/Makefile.
- [x] Feature-probe compat framework.
- [x] Build against the host's 7.0 headers.
- [x] Script: fetch and unpack Ubuntu kernel headers for a given version;
      build tswg.ko against them.
- [x] Compat shims so it builds on Ubuntu 24.04 (6.8).
- [x] Go netlink client (`tailscale.com/wgengine/tswg`) and `tswgctl`.
- [x] vmtest: two Ubuntu VMs, load tswg.ko, configure a tswg tunnel by
      hand, ping through it (`TestTSWGManualTunnel`, passes in about 80s).
- [x] Same on gokrazy, with no userspace tools
      (`TestTSWGGokrazyManualTunnel`, passes in about 23s).
- [ ] Generate a Module.symvers for gokrazy build trees (for example from
      the kernel's exported-symbol list) so missing exports fail at build
      time rather than load time.
- [ ] Verify the 7.4 path (all probes succeed) against a built 7.4 tree.
      (Partly covered: gokrazy's 7.2.8 has every probed API except
      udp_get_len_short.)
- [ ] Forked YNL spec plus regen script. (We now have hand-written
      additions in `src/generated/netlink.[ch]`, marked TSWG.)
- [ ] Look at the allowedips.c frame-size warning (1048 > 1024 bytes),
      present in upstream code too.
- [ ] Split large peer lists across several netlink messages in the Go
      client.
- [x] Socket fd passing plus `encap_rcv` classifier (WG vs. disco/STUN).
- [x] vmtest: disco/STUN still reach userspace on the shared socket, from
      the same 4-tuple; no WireGuard leaks to userspace; closing the fd
      detaches; a new fd reattaches (`TestTSWG{Gokrazy,Ubuntu}SharedSocket`).
- [ ] tailscaled: keep the shared sockets in systemd's fd store across
      restarts.
- [ ] Per-peer no-auto-roam flag.
- [ ] Loopback DERP endpoints; vmtest with DERP-only path.
- [ ] tailscaled integration (wgengine backend that programs tswg) on a
      tailscale.com branch.
- [ ] Fallback to wireguard-go when tswg is unavailable.
- [ ] Decide minimum supported kernel.
- [ ] dkms.conf and packaging.
- [ ] Custom debug kernel (KASAN, lockdep) in the testbed.
