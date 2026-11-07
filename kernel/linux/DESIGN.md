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

What upstream lacks: outer UDP GSO and GRO. Every encrypted packet took
its own trip through the UDP/IP stack and the NIC in both directions.
These are the kernel analogues of what makes wireguard-go fast, and were
the biggest levers; see the next section.

### What tswg changes (2026-11-07)

Profiled with the lean harness's sampling profiler (below), then fixed in
this order. Each step's throughput is bulk TCP, 1 stream, IPv4, 4 vCPUs.

1. Crypt worker kicks (3.6 -> 5.0 Gbps). Upstream queues the next CPU's
   crypt worker for every packet, round robin, which usually means an
   IPI (a VM exit in a VM); on receive, that was half of the softirq
   CPU. Now a packet needs no kick while some worker is draining the
   ring (`tswg_busy`, paired with the ring under full barriers), and we
   recruit another CPU's worker only when the backlog shows the busy
   ones falling behind (`tswg_crypt_kick`). Workers polling the ring for
   20us before going idle, to save more IPIs, didn't help and isn't
   used.
2. Outer UDP GSO on send (-> 5.8). First by chaining encrypted packets as
   a GSO `frag_list`, which needed the packets orphaned (segmenting a
   frag_list of TCP-owned packets underflowed `tcp_wfree`'s refcount),
   and whose segmentation copied each packet again. Replaced by:
3. Encryption into page frags (`tswg_encrypt_list`, same throughput,
   sender CPU 65% -> 43%). Rather than linearize each packet
   (`skb_cow_data`, a copy) and encrypt in place, the encrypt worker
   copies it into pages of its own (computing the inner checksum on the
   way, as `skb_checksum_help` would), encrypts it there, and gathers
   each run of equal-size messages into one `SKB_GSO_UDP_L4` packet whose
   payload is those pages. Segmenting that needs only page references,
   and a NIC with UDP segmentation offload (virtio with USO, here) takes
   it whole.
4. Peer queue length. The in-order per-peer queue (`prev_queue`)
   overflowed at upstream's 1024 packets whenever a decrypt worker was
   held up, silently, and TCP took the drops as congestion. Its limit
   now counts packets, not entries (a GRO entry is up to 64), at 2048,
   and drops are counted in `rx_dropped` and `rx_fifo_errors`.
5. Outer UDP GRO on receive (-> 9.6). Our sockets have `gro_receive`
   and `gro_complete`, as UDP tunnels do. They merge consecutive data
   messages of a flow that use the same key and are all the same size
   but perhaps the last; UDP then hands the merged packet
   (`SKB_GSO_UDP_TUNNEL`) to `encap_rcv` whole (without the tunnel type,
   UDP would segment it first, with software checksums). It goes through
   the decrypt ring and the peer's queue as one entry, and one worker
   decrypts each message into a new packet (`tswg_decrypt_gso`).
   `skb_gro_receive` isn't exported, so socket.c has a copy
   (`tswg_gro_merge`).
6. Freeing on the tx worker (-> 10.4). Freeing the original packets in
   the encrypt workers ran TCP's small queues handlers on all of them at
   once, contending for the socket lock.
7. Backpressure (TSQ). Upstream encrypts in place, so a packet stays
   charged to its socket until the NIC has sent it, and TCP is held to
   the NIC's pace. Our encrypted packets are new, so without care TCP
   could fill the NIC's qdisc as fast as we encrypt, which on a slow
   uplink with a FIFO qdisc would be massive bufferbloat. So the
   encrypted packet takes over the socket's ownership and charge
   (`tswg_move_owner`, only for destructors that just uncharge
   `truesize`: `sock_wfree` and TCP's), with the charge settled to its
   real size (`tswg_settle_charge`; segments' `truesize` is about twice
   their length). That cost throughput, since TCP's small queues allow
   only about 1ms of data in flight, so we set TCP sockets'
   `sk_pacing_shift` to 9 (about 2ms) as Wi-Fi drivers do (8) for their
   aggregation.
8. Where the tx worker runs. Upstream pins a peer's tx worker to one CPU
   by peer ID. When that's the CPU taking the NIC's interrupts, softirq
   work starved it, and encrypted packets waited up to 20ms to be sent.
   It's now queued on the CPU that finished encrypting.

The lean harness's VMs have guest USO off (decided 2026-11-07): with it,
the host hands VM-to-VM UDP GSO packets to the receiving guest still
coalesced, which no physical network does and which flatters UDP data
planes (wireguard-go got 10.5 Gbps with it, 10.0 without).
`TSWG_LAB_GUEST_USO=1` turns it back on.

### Measuring

Two harnesses:

* natlab (`TestTSWGBenchmark`, run with `scripts/bench.sh`): full
  tailscaled in TUN mode (wireguard-go) versus tailscaled in kernel mode,
  on the same pair of gokrazy VMs on one natlab LAN. tta's `/tswg/bench/`
  endpoints provide the tools (gokrazy has none): a TCP sink, TCP senders
  (1 and 4 streams), a 64-byte UDP flood, UDP ping-pong for RTT (idle and
  under a TCP load), and `/proc/stat` CPU snapshots (busy time excluding
  idle, iowait and steal). Results are printed as a table and written as
  JSON. natlab's vnet is a userspace switch in the test process, which
  costs a lot on the host (the test process ran at 120-150% CPU and each
  QEMU at 200-260% during TCP runs) and caps throughput, so this harness
  is for full-stack comparisons and the CPU cost inside the VMs, not
  absolute numbers.
* A lean harness without natlab (decided 2026-11-07; natlab "was never
  meant to be fast"), in tailscale.com's `tstest/tswgbench`, run with
  `scripts/leanbench.sh` (`-smoke` for the quick correctness test). See
  "Lean benchmark harness" below.

First natlab results, 2026-11-07 (2 vCPUs per VM, 10-second runs, three
runs; the numbers below are from run 2, and runs 1 and 3 agreed within a
few percent):

| metric | wireguard-go | tswg | tswg/wg |
|---|---|---|---|
| TCP 1 stream, Mbps | 2455 | 2392 | 0.97x |
| TCP 1 stream, sender / receiver CPU-s per GB | 4.06 / 4.83 | 3.93 / 4.67 | 0.97x / 0.97x |
| TCP 4 streams, Mbps | 2966 | 2856 | 0.96x |
| TCP 4 streams, sender / receiver CPU-s per GB | 3.54 / 4.59 | 3.58 / 4.40 | 1.01x / 0.96x |
| UDP 64B received, pps | 93k | 156k | 1.68x |
| UDP 64B receiver CPU per packet, us | 12.3 | 8.6 | 0.70x |
| RTT idle p50 / p99, ms | 1.29 / 2.61 | 1.30 / 2.20 | 1.01x / 0.84x |
| RTT under TCP load p50 / p99, ms | 2.92 / 7.86 | 1.53 / 4.68 | 0.53x / 0.60x |

Takeaways from natlab (but see the lean harness results below, which
overturn the first one):

* Bulk TCP: neither VM was CPU-saturated (50-80% of 2 vCPUs), so
  throughput is capped by natlab, and the CPU cost per byte is about the
  same.
* Small packets: the kernel delivers about 1.7x the packets per second
  at about 30% less CPU per packet.
* Latency under load: the kernel roughly halves RTT p50 and p99 while a
  TCP stream runs; idle RTT is about the same.

### Lean benchmark harness

`tstest/tswgbench` in tailscale.com (2026-11-07):

* Two QEMU VMs (q35, KVM, `-cpu host`, N vCPUs and N virtio-net queues)
  on a host bridge (`tswgb-br`, 10.77.0.0/24 and fd77::/64) with
  multiqueue taps and vhost-net. Creating the bridge and taps needs
  passwordless sudo; the taps are owned by the user so QEMU isn't root.
  Everything is removed afterwards.
* The VMs boot the natlab gokrazy kernel with a tiny gzipped cpio
  initramfs: `/init` is a static Go agent (`tstest/tswgbench/agent`),
  plus `/tswg.ko`. Booting takes about a second.
* The agent brings up eth0 from the kernel command line and serves an
  HTTP API: set up `wg0` with one of the data planes, tear it down, show
  the device, and the shared `netbench` endpoints (the same benchmark
  code tta serves for natlab, now in `tstest/tswgbench/netbench`).
* Data planes: `plain` (no tunnel, the ceiling), `kernelwg` (the
  kernel's own WireGuard, driven by the tswg Go client with family
  "wireguard"), `tswg`, and `wggo` (Tailscale's wireguard-go fork with a
  TUN device and its standard bind, so TUN offloads and UDP GSO/GRO, as
  tailscaled uses, but without magicsock). All tunnels use MTU 1280, as
  Tailscale does.
* `TestLeanSmoke` (about 25 seconds) checks every data plane over IPv4
  and IPv6 underlays, which natlab can't (it's IPv4-only here).
  `TestLeanBenchmark` runs the suite for each.

First results, 2026-11-07, IPv4 underlay, 4 vCPUs per VM, 10-second runs
(IPv6 is within a few percent; tswg and kernel WireGuard are the same
within noise everywhere, so the fork costs nothing):

| metric | wireguard-go | tswg | kernel WG | plaintext |
|---|---|---|---|---|
| TCP 1 stream, Mbps | 10498 | 3645 | 3647 | 16449 |
| TCP 1 stream, sender / receiver CPU (% of VM) | 58 / 62 | 29 / 55 | 29 / 56 | 21 / 15 |
| TCP 1 stream, sender / receiver CPU-s per GB | 1.96 / 2.06 | 3.00 / 5.20 | 2.95 / 5.22 | 0.45 / 0.31 |
| TCP 4 streams, Mbps | 12577 | 4376 | 4380 | 47158 |
| UDP 64B received, pps | 234k | 174k | 170k | 874k |
| UDP 64B receiver CPU per packet, us | 6.7 | 9.2 | 9.3 | 1.3 |
| RTT idle p50 / p99, ms | 0.57 / 1.33 | 0.63 / 2.13 | 0.70 / 1.78 | 0.24 / 0.92 |
| RTT under TCP load p50 / p99, ms | 1.43 / 2.85 | 1.20 / 5.29 | 0.99 / 5.33 | 0.20 / 0.74 |

Takeaways:

* Kernel WireGuard, as upstream designed it, is far behind Tailscale's
  wireguard-go for bulk traffic: about a third of the throughput, at 1.5x
  (sender) to 2.5x (receiver) the CPU per byte. It isn't CPU-bound
  either (29% and 55% of 4 vCPUs), so something serializes it. The
  natlab results only looked like parity because natlab capped both.
* Likely causes, to verify by profiling: every 1280-byte packet takes
  its own trip through the UDP/IP stack and the NIC in both directions
  (no outer UDP GSO on send, no UDP GRO on receive), while wireguard-go
  batches with UDP GSO/GRO and TUN offloads; the single WireGuard UDP
  flow lands on one NIC RX queue and so one CPU; and each peer's
  decrypted packets go through one NAPI context.
* So outer UDP GSO/GRO, and finding where the kernel serializes, are the
  critical performance work, ahead of everything else. tswg's reason to
  exist is to beat wireguard-go, and today it doesn't on bulk throughput.
* Small packets are closer: the kernel receives 0.75x the packets of
  wireguard-go, but at much lower loss (wireguard-go accepts far more
  from the sender than it can deliver), and at 1.4x the CPU per packet.
* Latency: the kernel is a little worse idle, better at p50 under load,
  and worse at p99 under load.

Results after the work in "What tswg changes", 2026-11-07 (same setup,
but guest USO off; one 10-second run of each, so expect a few percent of
noise; `scripts/leancompare.sh` gives medians of interleaved runs, which
put TCP 1 stream at 10.1 vs. 9.7 Gbps and 4 streams at 12.3 vs. 10.8):

| metric (IPv4; IPv6 in parentheses) | wireguard-go | tswg | tswg/wg |
|---|---|---|---|
| TCP 1 stream, Mbps | 10158 (9929) | 10220 (9474) | 1.01x (0.95x) |
| TCP 1 stream, sender / receiver CPU-s per GB | 1.93 / 2.37 | 1.81 / 2.12 | 0.94x / 0.90x |
| TCP 4 streams, Mbps | 11133 (11146) | 11707 (11621) | 1.05x (1.04x) |
| TCP 4 streams, sender / receiver CPU-s per GB | 1.84 / 2.31 | 1.87 / 2.14 | 1.01x / 0.93x |
| UDP 64B received, pps (loss) | 242k (79%) | 263k (0%) | 1.08x |
| UDP 64B receiver CPU per packet, us | 7.3 | 5.2 | 0.72x |
| RTT idle p50 / p99, ms | 0.61 / 1.27 | 0.92 / 1.95 | 1.50x / 1.53x |
| RTT under TCP load p50 / p99, ms | 1.57 / 3.16 | 1.49 / 11.68 | 0.95x / 3.69x |

Takeaways:

* Bulk TCP: tswg went from 0.35x to parity or a little better with one
  stream, and ahead with four, at 6-10% less CPU per byte, so it should
  pull further ahead where CPU is the limit. From 3.6 Gbps to 10.2,
  mostly from outer GSO and GRO.
* Small packets: tswg delivers everything it's sent, at 0.6-0.7x
  wireguard-go's CPU per packet. (It sends fewer because the sender's
  socket now waits for the NIC, as it should.)
* Idle latency is worse, and it's the VM: with the guests booted with
  `idle=poll` (`TSWG_LAB_CMDLINE=idle=poll`), so that waking a vCPU
  costs nothing, tswg's idle RTT p50 is 0.08ms, against 0.14 for
  wireguard-go and 0.06 without a tunnel, and under load 0.71 / 1.70ms
  (p50 / p99) against 1.07 / 2.36. Each of tswg's handoffs (to an
  encrypt worker, the tx worker, a decrypt worker, the peer's NAPI
  thread) can wake a halted vCPU, which costs a VM exit and the host
  scheduling the vCPU's thread, while wireguard-go's goroutines mostly
  find their Ps spinning. Cloud VMs pay this too, so it's worth fixing;
  see the TODO list.
* p99 under load is worse, and isn't explained yet: instrumenting the
  queues showed that at full load the receiving VM's crypt workers and
  tx worker sometimes didn't run for 10-40ms, with entries waiting in
  the decrypt ring and the tx queue. The host here is itself a VM, with
  16 CPUs for 8 vCPUs and 8 busy vhost threads; check on bare metal and
  with fewer queues before redesigning around it.

Tools in the lean harness, for this kind of work:

* `TestLeanProfile` (`TSWG_LEAN_PROFILE=tswg,wggo`): a sampling
  profiler in the agent (perf_event_open, since the VMs have no perf),
  per CPU, kernel and Go symbols; `TSWG_PROFILE_FOCUS=sym` reports the
  call stacks of one symbol.
* `TestLeanCompare` (`scripts/leancompare.sh`): interleaved repeated
  runs, reporting medians, for A/B checks; `TSWG_COMPARE_LOAD=rtt` for
  latency.
* `TestLeanDebug`: counters (`/proc/net/snmp`, `/proc/net/dev`), the
  kernel log and the device after a short run.
* `TSWG_DEBUG_KERNEL=1`: boots a KASAN, lockdep, DEBUG_VM and DEBUG_NET
  build of the same kernel (`scripts/gokrazy-debug-kernel.sh`). Every
  lean test fails if a VM's kernel reports a bug.

## Non-goals

* Upstreaming. tswg is an out-of-tree module, installed via DKMS or
  similar. We do not depend on upstream WireGuard accepting changes.
* Rust. Decided 2026-11-06: the in-tree Rust networking abstractions are
  too thin (no sk_buff, net_device, UDP tunnel, or lib/crypto bindings) and
  out-of-tree Rust modules need a kernel built with CONFIG_RUST and a
  matching rustc, which most distro kernels can't provide. Revisit later.
* Changing the WireGuard wire protocol. tswg must interoperate with every
  existing Tailscale peer running wireguard-go. (But see "Hybrid
  post-quantum handshakes": wireguard-go is about to grow a handshake
  tswg doesn't have.)
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
* Attaching also installs our `gro_receive`/`gro_complete` (see "Outer
  UDP GSO and GRO"), which take precedence over the socket's own
  `UDP_GRO` setting, so whether tailscaled enables `UDP_GRO` doesn't
  matter. Detaching removes them, first undoing the static call that
  `setup_udp_tunnel_sock` may have made of `gro_receive` (7.x), which
  must not outlive the module.
* We set `sk_allocation = GFP_ATOMIC` on the user socket, as WireGuard and
  L2TP do for their sockets, since we send from atomic context.

### Endpoints and roaming

Upstream WireGuard roams a peer's endpoint to the source of the latest
authenticated packet. That fights disco's path selection: a packet that
arrives via DERP would steal the endpoint from a good direct path.
Implemented 2026-11-06:

* A per-peer flag, `TSWGPEER_F_NO_ROAM`, in `TSWGPEER_A_FLAGS` nested in
  `WGPEER_A_TSWG` (= 64, like the device attribute). Setting
  `TSWGPEER_A_FLAGS` replaces all of the peer's tswg flags. Dumps report
  it. Go: `tswg.PeerConfig.NoRoam` and `tswg.Peer.NoRoam`.
* Upstream learns endpoints in three places: on a valid handshake
  initiation and a valid handshake response (via
  `wg_socket_set_peer_endpoint_from_skb`) and on each authenticated data
  packet (`wg_packet_consume_data_done` calls
  `wg_socket_set_peer_endpoint` directly). `tswg_peer_may_roam()` (in
  `peer.h`) gates the learned updates, not `wg_socket_set_peer_endpoint`
  itself, which netlink also uses for explicit updates.
* With the flag set, the first authenticated packet still sets the
  endpoint if the peer doesn't have one yet; after that only userspace
  changes it. That keeps a peer reachable if it contacts us before
  tailscaled has given it an endpoint.
* The flag is applied before `WGPEER_A_ENDPOINT` in the same request, so
  pinning and setting an endpoint are one step.
* Per-peer rather than device-wide, for now. tailscaled will set it on
  every peer; a device-wide default is easy to add if per-peer turns out
  to be a hassle.
* Pinning also stops learning the local source address that upstream
  records alongside the endpoint (for replying from the same local IP on
  multihomed hosts); the kernel picks the source address by routing, as
  in userspace Tailscale.

Changing a peer's endpoint does not re-key or reset the noise session in
upstream WireGuard either; that is already fine.

### DERP, peer relays and spray: the loopback bridge

Implemented 2026-11-07 in tailscaled (`wgengine/kerneldp_linux.go`); it
needed no kernel changes. The rule: the kernel handles direct UDP paths
by itself; everything else (DERP, peer relays, and the untrusted-path
spray) goes through tailscaled's loopback bridge.

* The bridge is one UDP socket bound to `0.0.0.0:P` with
  `SO_BINDTODEVICE lo` (so only local traffic reaches it) and `IP_PKTINFO`.
* Each peer gets its own address in 127.0.0.0/8 (127.0.0.2 upwards; the
  mapping lives for the process's lifetime). When the kernel shouldn't
  send to a peer directly, the peer's kernel endpoint is set to that
  address and port P. The bridge reads what the kernel sends there, maps
  the destination (from `IP_PKTINFO`) back to the peer, and hands the
  ciphertext to magicsock's `endpoint.send`, which sends it the way it
  would a packet from wireguard-go: DERP, a peer relay, or both DERP and
  the candidate UDP path while that isn't trusted yet (the spray).
* In kernel mode, magicsock passes every WireGuard packet it would have
  handed to wireguard-go (from DERP, or Geneve-wrapped from a peer relay)
  to the bridge instead (`magicsock.Options.KernelWGRecv`), which injects
  it into the kernel by sending it to `127.0.0.1:<kernel listen port>`
  from the peer's 127.x.y.z:P (`ipi_spec_dst`). The kernel finds the peer
  by receiver index (or, for handshake initiations, by decrypting the
  static key), so the source only matters for handshake rate limiting and
  cookie replies, which stay per-peer because each peer has its own
  address. Packets from unknown peers are injected from 127.0.0.1.
* Each peer's kernel endpoint is magicsock's best address if it's direct
  and trusted (`magicsock.Conn.KernelPeerPath`), else the peer's bridge
  address; see "No polling" for how changes reach the kernel.

### tailscaled integration

Implemented 2026-11-07 on the tailscale.com `bradfitz/tswg` branch. Opt
in with `TS_DEBUG_TSWG=1` on Linux; the code is behind the `tswg` feature
tag (`ts_omit_tswg` drops it, and the minimal builds don't include it).

* Startup: if the module is loaded, tailscaled creates a tswg device
  named tailscale0 (replacing any stale one) with the usual TUN MTU, and
  gives the engine and router a fake `tun.Device` that only reports that
  name (`tswg.NewTailscaleDevice`), so the router configures addresses
  and routes on the tswg device. If the module isn't loaded, tailscaled
  logs why and falls back to TUN and wireguard-go. tailscaled doesn't load
  the module itself.
* The engine (`wgengine.Config.KernelWG`) keeps wireguard-go running with
  no peers, since its receive loops are what drive magicsock's socket
  reads (disco, STUN). The kernel data plane:
  * sets the device fwmark to Tailscale's bypass mark
    (`tsconst.LinuxBypassMarkNum`), so the kernel's encrypted packets
    don't route into tailscale0 (for example via an exit node's default
    route), as magicsock's sockets do;
  * shares magicsock's first UDP socket per family with the kernel, again
    after every rebind (`magicsock.Conn.SetKernelSocketHook`);
  * reconciles the kernel's peers with magicsock's peers and the live
    per-peer config (`SetPeerConfigFunc`, whose peer set is otherwise
    lazy): allowed IPs, preshared key, endpoint, and no-roam on all of
    them, in netlink messages of at most 32 peers;
  * feeds direct-path activity, from the kernel's peer events, to
    magicsock (`NoteKernelActivity`), so it keeps heartbeating active
    sessions and the direct path stays trusted, and reports per-peer
    status (bytes, last handshake) in the engine status, from a dump
    when asked.
* Tests: `TestTSWGTailscaledDirect` (two gokrazy VMs behind easy NATs;
  the kernel ends up sending directly to the peer's NAT-traversed public
  address) and `TestTSWGTailscaledDERP` (hard NATs on both sides; the
  kernel peer stays on its bridge address and everything flows over
  DERP). Both start tailscaled before the module is loaded, so they also
  cover the TUN fallback, then load the module and restart tailscaled.

* wireguard-go must never get peers in kernel mode: if it did (from its
  lazy peer lookup on an outbound packet or an incoming handshake), it
  would handshake over magicsock with our keys and fight the kernel's
  sessions. So in kernel mode the engine doesn't install wireguard-go's
  `PeerLookupFunc` or `PeerByIPPacketFunc` (decided 2026-11-07).

### TSMP and other packets tailscaled sends to peers

Implemented 2026-11-07 (`wgengine/kerneldp_tsmp_linux.go`). With
wireguard-go, TSMP (IP protocol 99) and the other packets tailscaled
itself exchanges with peers pass through the tstun.Wrapper between the
TUN device and wireguard-go. In kernel mode:

* Outbound: tstun gets an outbound inject hook
  (`tstun.Wrapper.SetOutboundInjectHook`). In kernel mode, everything
  tailscaled injects towards peers (TSMP pings, pongs and disco key
  advertisements, ICMP echo replies, netstack output) goes to it instead
  of wireguard-go's queue, and the kernel data plane writes it, header
  and all, to a raw `IPPROTO_RAW` socket bound to tailscale0 (IPv4 and
  IPv6), so the kernel routes it into the tswg device, which encrypts it.
* Inbound: raw `IPPROTO_TSMP` sockets bound to tailscale0 receive the
  TSMP packets peers send, and the data plane feeds them to
  `tstun.Wrapper.Write` as wireguard-go would, which handles them as
  usual (answering pings, delivering pongs, learning disco keys). IPv6
  raw sockets don't return the IP header, so it's rebuilt from the
  source address and the `IPV6_PKTINFO` and `IPV6_HOPLIMIT` control
  messages. With such a raw socket open, the kernel doesn't answer TSMP
  with ICMP protocol unreachable.
* wireguard-go sends a "priority message" (a TSMP disco key
  advertisement) whenever it establishes a session. The kernel data plane
  does the same on the kernel's session event for the peer (see "No
  polling").
* Tested by `TestTSWGTailscaledTSMP`: TSMP pings both ways, and each side
  receives the other's disco key advertisement
  (`magicsock_tsmp_disco_key_advertisement_received`).

### No polling

Done 2026-11-07 (at first the data plane polled every second). Nothing
in the kernel data plane runs on a timer now; everything is driven by
events:

* Peer set and config: `SyncDevicePeer`, `SetPeerConfigFunc` and private
  key changes request a full sync.
* Paths: magicsock calls a hook (`Conn.SetKernelPathHook`) whenever a
  peer's kernel path flips between direct-and-trusted and not. All
  changes to `bestAddr` go through `setBestAddrLocked` and all changes to
  `trustBestAddrUntil` through `setTrustBestAddrUntilLocked`, which check
  for a flip. Trust lapsing is an event with no packet attached, so while
  a peer's kernel path is direct, magicsock keeps a timer armed for
  `trustBestAddrUntil` (re-armed if trust was extended meanwhile). The
  data plane then updates just that peer's endpoint.
* While a session is active, the fallback when a direct path dies comes
  from magicsock's heartbeat ping timing out after trust lapsed
  (`discoPingTimeout` clears the best address). The trust timer is what
  covers idle sessions: once magicsock stops heartbeating (45 seconds
  without traffic), trust lapses silently, and the kernel must stop
  sending directly so that the next packets go through magicsock (DERP
  plus the candidate path) until the path is trusted again, as with
  wireguard-go.
* Kernel to tailscaled: the module multicasts peer events
  (`TSWG_CMD_PEER_EVENT` on the "events" genetlink group): a new session
  (`TSWGEVENT_F_SESSION`, from `wg_timers_session_derived`), and TX and
  RX activity (`TSWGEVENT_F_TX`, `TSWGEVENT_F_RX`), each rate limited to
  one per peer every 2 seconds (`TSWG_ACTIVITY_EVENT_INTERVAL`) with a
  single comparison on the packet path. Messages are only built when
  someone listens. tailscaled sends the disco key advertisement on session
  events and feeds direct-path activity to magicsock. If the event socket
  overruns, events are lost but harmlessly: activity recurs, and the
  advertisement is an optimization.
* All changes to the kernel's peers are applied by one goroutine: hooks
  only record what to do (full sync, dirty paths, session clears) and
  kick it, so a sync that read paths a moment ago can't overwrite a
  newer endpoint, and callers holding LocalBackend locks never wait on
  a sync that needs them.
* Tests: `TestTSWGTailscaledPathFallback` (a direct path dies mid-session;
  the kernel falls back to the bridge and DERP about 8 seconds later) and
  `TestTSWGTailscaledIdleTrustExpiry` (a session goes idle; the kernel
  moves to the bridge once trust lapses, and back to direct when traffic
  resumes; fails without the trust timer).

### Peer restarts

Implemented 2026-11-07. When a peer's disco key changes in a way that
means it restarted (and so lost its WireGuard keys), ipnlocal calls
`Engine.MarkDevicePeerForHandshake`. wireguard-go then handshakes after
the next outbound packet. In kernel mode, the data plane instead clears
the kernel's session with the peer (`TSWGPEER_A_CLEAR_SESSION`: forget
the keypairs and any handshake in progress, as on suspend, and reset the
handshake rate limit), so the next packet is staged and starts a new
handshake right away. In the same request it updates the peer's endpoint
from magicsock's current path, since a restarted peer usually has a new
port, and the handshake should go there rather than wait for the next
reconcile.

Without this, the kernel keeps sending with dead keys until WireGuard's
own timers start a new handshake about 15 seconds later.
`TestTSWGTailscaledPeerRestart` checks that the first pings after a peer
restart get through (and fails without the session clearing).

### Known gaps in kernel mode

Deliberately deferred (2026-11-07: "easy later, not a priority yet"):

* No packet filter: the engine's filter runs on packets passing through
  userspace, which kernel-mode packets don't. Peers can reach anything
  on the node. Must be done (nftables, or in the module) before anyone
  uses this for real.
* No MagicDNS at 100.100.100.100 (or other netstack-provided services).

Other TODOs:

* Only magicsock's first socket per family is shared; `UDPSockets` > 1
  isn't supported.
* A full sync (on any config change) still walks every peer; fine for
  now, but worth making incremental for huge tailnets.

### Hybrid post-quantum handshakes

Found 2026-11-07: Tailscale's wireguard-go fork has a hybrid
post-quantum handshake (`wgcfg.PeerConfig.Hybrid`, different message
sizes), wired up in tailscale.com on 2026-10-29, with a control
"disable hybrid" capability for the initial rollout (2026-11-03). Nothing
sets `Hybrid` yet, but once it's in use between two nodes, a kernel-mode
node can't talk to a hybrid-only peer, since tswg only does classic
WireGuard. So the "wire-compatible with every Tailscale peer" assumption
no longer holds. Options:

* a kernel-mode node advertises (to control) that it doesn't do hybrid
  handshakes, so peers use classic handshakes with it; or
* implement the hybrid handshake in tswg (needs a kernel ML-KEM, or a
  vendored one).

For now the kernel data plane logs any peer that asks for a hybrid
handshake and uses a classic handshake.

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
  `build-for-gokrazy.sh` (gokrazy kernels), `gokrazy-debug-kernel.sh`
  (a KASAN/lockdep build of a gokrazy kernel), `extract-ikconfig`
  (vendored from Linux), `vmtest.sh` (run the natlab vmtests),
  `bench.sh` (natlab benchmark), `leanbench.sh` (lean benchmark and
  smoke test) and `leancompare.sh` (quick A/B medians).

## TODO

Performance (the primary motivation; see "Performance"):

- [x] natlab benchmark harness: tailscaled kernel mode vs. TUN mode on the
      same VMs (`TestTSWGBenchmark`, `scripts/bench.sh`).
- [x] Lean benchmark harness without natlab (tap + vhost-net, gokrazy
      kernel, initramfs agent): plaintext, kernel WireGuard, tswg and
      wireguard-go, over IPv4 and IPv6 (`TestLeanBenchmark`,
      `scripts/leanbench.sh`).
- [x] Profile the bulk path in the lean harness (an in-agent sampling
      profiler, `TestLeanProfile`).
- [x] Crypt worker kicks on demand, not per packet.
- [x] Outer UDP GSO on send: encrypt into page frags, as
      `SKB_GSO_UDP_L4` packets.
- [x] Outer UDP GRO on receive (`gro_receive`/`gro_complete`), decrypting
      merged packets whole.
- [x] TCP backpressure (TSQ) through the NIC, and the tx worker on a CPU
      that isn't starved.
- [x] Debug kernel (KASAN, lockdep) for the lean harness.
- [x] Beat wireguard-go on bulk TCP and CPU per byte (2026-11-07; at
      parity to 1.05x on throughput, 0.90-0.94x CPU per byte; see
      "Performance").
- [ ] p99 RTT under load (3.7x wireguard-go's here): find why crypt and tx
      workers sometimes don't run for 10-40ms on a loaded receiver; try
      bare metal, fewer NIC queues, and the scheduler's view
      (`/proc/schedstat`, steal time).
- [ ] Idle latency in VMs: cut cross-CPU handoffs for lone small packets
      when nothing is busy (encrypt or decrypt inline, send from the
      encrypt worker), without bringing back softirq starvation of
      workers on the NIC's CPU under load.
- [ ] Zero-copy receive: decrypt in place in the GRO packet's page frags
      (when not shared) and hand out page-frag packets, instead of
      copying each message out (`tswg_decrypt_gso`).
- [ ] TSO from the inner GSO packet: encrypt straight from it, building
      each segment's headers, instead of `skb_gso_segment` in `wg_xmit`
      (per-segment skb allocation).
- [ ] Device-coalesced input: UDP packets that arrive already GSO from
      the NIC (VM-to-VM with guest USO) skip GRO, so UDP segments them,
      with software checksums, before `encap_rcv`.
- [ ] Benchmark subnet router and exit node forwarding.
- [ ] Benchmarks on real NICs (bare metal or cloud VMs), not just natlab.
- [ ] vmtest: shared socket with `UDP_GRO` enabled still works.
- [ ] Profile the encrypt/decrypt path under many-flow and many-peer
      loads.
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
- [x] Per-peer no-auto-roam flag (`TestTSWG{Gokrazy,Ubuntu}NoRoam`).
- [x] Loopback DERP endpoints; vmtest with DERP-only path
      (`TestTSWGTailscaledDERP`).
- [x] tailscaled integration on the tailscale.com `bradfitz/tswg` branch
      (`TestTSWGTailscaledDirect`).
- [ ] Kernel mode: packet filter (security; required before real use;
      deferred).
- [ ] Kernel mode: hybrid PQ handshakes (advertise no support, or
      implement them in tswg).
- [x] Kernel mode: TSMP (`TestTSWGTailscaledTSMP`).
- [ ] Kernel mode: MagicDNS and the other netstack-provided services
      (deferred).
- [x] Kernel mode: clear the session on MarkDevicePeerForHandshake
      (`TestTSWGTailscaledPeerRestart`).
- [x] Kernel mode: event-driven everything, no polling
      (`TestTSWGTailscaledPathFallback`, `TestTSWGTailscaledIdleTrustExpiry`).
- [x] IPv6 underlay tests for tswg (`TestLeanSmoke`).
- [ ] Kernel mode (tailscaled) over IPv6: needs control and DERP outside
      natlab, or IPv6 in natlab.
- [ ] Flake: in 1 of 4 natlab benchmark runs, after both nodes restarted
      tailscaled into kernel mode at nearly the same time, the tunnel
      didn't carry traffic for over 10 seconds (n1 had cleared its
      session with n2, and the kernel endpoints looked direct). Restarting
      one peer at a time (`TestTSWGTailscaledPeerRestart`) is fine.
      Investigate.
- [x] Fallback to wireguard-go when tswg is unavailable (module not
      loaded).
- [ ] Fallback on version or feature mismatch between tailscaled and
      the loaded module.
- [ ] Decide minimum supported kernel.
- [ ] dkms.conf and packaging.
- [ ] Custom debug kernel (KASAN, lockdep) in the testbed.
