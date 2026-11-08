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

### Results at a glance

The current numbers, kept up to date as results come in (details, setups
and history in the sections below). "CPU-s/GB" is CPU seconds per GB
delivered or forwarded on the measured machine (lower is better); ratios
are tswg over wireguard-go. MTU 1280 (Tailscale's) unless noted.

Subnet router on EC2 (`TestLeanSubnetRouter`): clients, each a peer of
the router, with many TCP flows each to a backend on the router's LAN,
which the router forwards to, masquerading. Updated 2026-11-07.

| router | clients x flows | tswg | wireguard-go | kernel WG | tswg/wggo throughput | CPU-s/GB tswg / wggo / kernel WG | tswg/wggo CPU per GB |
|---|---|---|---|---|---|---|---|
| c7i.16xlarge, 4 CPUs online | 20 x 8 | 13.9 Gbps | 6.3 | 10.2 | 2.2x | 2.38 / 3.87 / 3.35 | 0.61x |
| c7i.16xlarge, 8 CPUs online | 20 x 8 | 23.0 Gbps | 6.4 | 16.9 | 3.6x | 2.62 / 4.56 / 3.98 | 0.57x |
| c7i.48xlarge, 192 CPUs | 8 x 16 | 31.5 Gbps | 7.2 | 12.3 | 4.3x | 3.90 / 3.87 / 94.7 | 1.01x |
| c7i.48xlarge, 192 CPUs | 24 x 8 | 40.0 Gbps | 7.1 | 13.5 | 5.6x | 4.49 / 4.60 / 95.4 | 0.98x |
| c6in.32xlarge, 128 CPUs | 20 x 8 | 57.6 Gbps | 5.8 | 8.1 | 9.9x | 5.26 / 4.72 / 130 | 1.11x |
| c6in.32xlarge, 128 CPUs | 40 x 8 | 72.1 Gbps | | | | 6.14 / - / - | |
| **c6in.32xlarge, 128 CPUs** | **60 x 4** | **74.3 Gbps** | 6.2 | 8.1 | **12.0x** | 6.25 / 5.57 / 130 | 1.12x |
| c7i.48xlarge, MTU 8920 (data point only) | 8 x 16 | 49.6 Gbps (line rate) | 17.5 | 49.2 | 2.8x | 2.18 / 1.86 / 15.0 | 1.17x |
| **c6in.32xlarge, 128 CPUs, idle-residency CPU accounting** | **37 x 4** | **70.9 Gbps** | 6.2 | 8.5 | **11.5x** | **6.50 / 8.57 / 124.6** | **0.76x** |
| **real tailscaled, kernel vs. TUN mode** (c6in.32xlarge) | **37 x 4** | **69.2 Gbps** | 6.9 (TUN) | | **10.0x** | **6.47 / 8.80 / -** | **0.74x** |

The last row runs real tailscaled (2026-11-08; `tskernel` and `tstun`
in `TestLeanSubnetRouter`): the router advertises the backend's address
with SNAT, the clients (kernel mode) accept it, and a self-contained
control plane (`tstest/tswgbench/benchcontrol`) runs on the backend.
Kernel mode matches the bare tswg tunnel (70.9 Gbps), so tailscaled adds
no cost on the data path; plain routing on the same clients: 89.5 Gbps.

The same 37 clients through the same router with no tunnel, the
clients' routes clamped to MTU 1280 (so the same size packets as through
the tunnels): 88.9 Gbps at 1.27 CPU-s/GB, so tswg gets 0.80x of plain
routing. Unclamped (jumbo frames), plain routing reaches 165 Gbps; at
normal MTUs, the platform's per-packet costs limit it too.

CPU accounting: rows before the last measured CPU from `/proc/stat`,
which on Ubuntu's AWS kernels (no `CONFIG_IRQ_TIME_ACCOUNTING`) counts
interrupt and softirq work done on otherwise idle CPUs as idle: it showed
plain routing at 9M packets per second as 1% busy, against 10.5% from
the CPUs' idle-state residencies, which netbench uses since 2026-11-07.
So earlier CPU-s/GB figures understate softirq-heavy work: plain routing
and kernel WireGuard most, tswg somewhat (its crypto runs in kworkers,
which `/proc/stat` counts), wireguard-go least (mostly user time).

* Limits: wireguard-go about 6-7 Gbps however many peers or CPUs (a
  serial stage). tswg: on small routers, its CPUs; on the c7i.48xlarge,
  EC2's packet rate allowance (about 12M packets per second through the
  router at 40 Gbps); on the c6in.32xlarge (200 Gbps, and no EC2
  allowance exceeded), about 75 Gbps, where the NIC's interrupt CPUs
  saturate: ENA allocates a fresh page per received packet, and pages
  allocated on one CPU and freed on another (transmit completions) contend
  for the page allocator's zone lock, 14-20% of those CPUs, plus zeroing
  (`init_on_alloc`). Tried there, no better: RPS, bigger per-CPU page
  lists (`vm.percpu_pagelist_high_fraction=8`), capping wg0's GRO size
  (for hardware TSO on forwarding), and zero-copy receive (module
  parameter `rx_zerocopy`, off by default), which took tswg's own page
  allocations out (page zeroing 4.7% to 1.1%, zone lock time 9-11% to
  7%) but cost more in scatterlist decryption: with 24 clients, 62.5-63.3
  Gbps and 6.05 CPU-s/GB against 63.4-64.7 and 5.47 copying. So tswg's
  allocations weren't what binds; ENA's page per received packet is. More clients helped until about 40
  (20: 56 Gbps, 40: 72, 60: 74).
* On the big routers, tswg isn't CPU-bound (45% of 128 CPUs at 74 Gbps),
  so its CPU per byte is about even with wireguard-go's; where CPU is the
  limit, tswg uses about 0.6x wireguard-go's. Kernel WireGuard's
  per-packet round-robin worker kicks keep all of a big machine's CPUs
  busy (98% of 128 for 8 Gbps).
* Clients on c6in were c6in.2xlarge and c6in.large; none was busy (5-27%
  CPU), nor the backend (13%).

Point to point (`TestLeanBenchmark`, `scripts/leanbench.sh`): one tunnel
between two machines, 4 vCPUs each. Updated 2026-11-07.

| testbed | metric | tswg | wireguard-go | kernel WG | tswg/wggo |
|---|---|---|---|---|---|
| QEMU lab (nested) | TCP 1 stream | 10.2 Gbps | 10.2 | 3.6 | 1.0x |
| QEMU lab (nested) | TCP 4 streams | 11.7 Gbps | 11.1 | 4.2 | 1.05x |
| QEMU lab (nested) | sender / receiver CPU-s/GB, 1 stream | 1.81 / 2.12 | 1.93 / 2.37 | 2.95 / 5.20 | 0.94x / 0.90x |
| QEMU lab (nested) | UDP 64B received (loss) | 263k pps (0%) | 242k (79%) | 166k (16%) | 1.08x |
| QEMU lab (nested) | RTT idle / under load p50 | 0.51 / 1.50 ms | 0.60 / 1.79 | 1.07 / 1.07 | 0.85x / 0.84x |
| QEMU lab (nested) | RTT idle / under load p99 | 1.27 / 12.3 ms | 1.28 / 3.78 | | 0.99x / 3.3x |
| EC2 c7i.xlarge | TCP 1 or 4 streams | 7.25 Gbps | 7.25 | 5.3 | 1.0x (EC2's per-flow limit) |
| EC2 c7i.xlarge | sender / receiver CPU-s/GB, 1 stream | 2.48 / 2.47 | 2.59 / 2.97 | 2.68 / 3.80 | 0.96x / 0.83x |
| EC2 c7i.xlarge | UDP 64B received (loss) | 536k pps (0.06%) | 328k (58%) | 430k (1.7%) | 1.6x |
| EC2 c7i.xlarge | RTT idle / under load p50, before inline crypto | 0.92 / 0.82 ms | 0.47 / 3.57 | 0.85 / 1.28 | 1.96x / 0.23x |
| EC2 c6in.32xlarge | RTT idle / under load p50 | 0.75 / 1.61 ms | 0.97 / 3.92 | | 0.77x / 0.41x |
| EC2 c6in.32xlarge | RTT idle / under load p99 | 0.96 / 6.04 ms | 1.24 / 6.42 | | 0.77x / 0.94x |

RTT rows are UDP ping-pong (`TSWG_COMPARE_LOAD=rtt`, medians of 4
runs), idle and under one TCP stream; updated 2026-11-08 with inline
crypto (item 9 below) and softirq NAPI. The kernel WG column is from
before.

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
9. Inline crypto for lone packets (idle RTT p50 in the lab 0.92 ->
   0.51ms, wireguard-go 0.60; on EC2 0.75ms against 0.97). Every
   handoff to a worker on another CPU can wake a halted vCPU, a VM exit
   and a trip through the host's scheduler. So a packet that isn't part
   of a batch (not GSO) is encrypted or decrypted where it is when the
   workers look idle (`tswg_crypt_idle`: empty ring, last-kicked worker
   not busy), after going on the peer's in-order queue as usual. Under
   load, workers drain TCP ACKs fast enough that the ring often looks
   empty, and inlining them moved that work onto the CPUs taking the
   NIC's interrupts: 8% off a subnet router. Two limits fixed that: at
   most 8 inline packets per CPU per jiffy (`tswg_inline_ok`), and no
   inline encryption from softirq (forwarding, and replies sent from
   softirq), which alone left 6% behind. Module parameter
   `inline_crypto` turns it off.
10. NAPI in softirq, not threads. Upstream has each peer's NAPI run in
   a kthread (`netif_threaded_enable`), one more wakeup per received
   packet. Threads give a CPU-bound subnet router 4-5% more throughput,
   but cost idle latency, so it's softirq unless module parameter
   `napi_threaded` is set (or per device, `/sys/class/net/*/threaded`).

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
* Idle latency was worse (since fixed by inline crypto; see "Results at
  a glance"), and it's the VM: with the guests booted with
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

On EC2 (2026-11-07), with the lean harness in remote mode (below): two
c7i.xlarge instances (4 vCPUs, Nitro, ENA, Ubuntu 24.04's 7.0.0-1014-aws
kernel) in a cluster placement group in us-west-2, one level of
virtualization instead of the lab's two:

| metric (IPv4; IPv6 in parentheses) | wireguard-go | tswg | kernel WG |
|---|---|---|---|
| TCP 1 stream, Mbps | 7244 (7027) | 7253 (7033) | 5349 (6605) |
| TCP 1 stream, sender / receiver CPU-s per GB | 2.59 / 2.97 | 2.48 / 2.47 | 2.68 / 3.80 |
| TCP 4 streams, Mbps | 7265 | 7266 | 5646 |
| TCP 4 streams, sender / receiver CPU-s per GB | 2.53 / 2.95 | 2.59 / 2.94 | 2.70 / 3.80 |
| UDP 64B received, pps (loss) | 328k (58%) | 536k (0.06%) | 430k (1.7%) |
| UDP 64B receiver CPU per packet, us | 3.5 | 2.4 | 4.9 |
| RTT idle p50 / p99, ms | 0.47 / 0.71 | 0.92 / 1.18 | 0.85 / 1.23 |
| RTT under TCP load p50 / p99, ms | 3.57 / 5.12 | 0.82 / 5.01 | 1.28 / 3.13 |

* Both tunnels hit the same cap of about 7.25 Gbps (inner), with 1 or 4
  streams: EC2's limit for the one outer UDP flow (or its packet rate),
  not either data plane. So on EC2, CPU per byte is what tells them
  apart: tswg's receiver uses up to 17% less, and the sender up to 7%.
  Smaller instances (c7i.large), where CPU is the limit, are next.
* Small packets: 1.6x wireguard-go's packets delivered, at 0.7x the CPU.
* Latency under load: p50 is a quarter of wireguard-go's (TCP
  backpressure keeps tswg's queues short), p99 the same (IPv6: 2.3x).
* Idle latency was about twice wireguard-go's, as in the lab, so the
  vCPU-wakeup cost of tswg's handoffs (see above) is real on Nitro
  too. Inline crypto fixed it (2026-11-08): on a c6in.32xlarge pair,
  idle p50 / p99 is 0.75 / 0.96ms against wireguard-go's 0.97 / 1.24.

#### Subnet router (2026-11-07)

Tailscale's most important server role for customers: clients on the
tailnet reach a private LAN (10.0.0.0/24, say) through a subnet router,
which forwards between its tunnel and the LAN, masquerading the clients
(the default, `--snat-subnet-routes`); the LAN's machines aren't on
Tailscale. wireguard-go is known to fall over with many clients and
flows. `TestLeanSubnetRouter` (`scripts/subnetbench.sh [ROUTER_CPUS...]`)
sets this up on EC2: a router (c7i.16xlarge, 25 Gbps, with CPUs taken
offline to make CPU the limit), a backend on the same VPC subnet (also
c7i.16xlarge), and 4 clients (c7i.4xlarge) running tswg, each a peer of
the router, each with 16 TCP flows to the backend at once. `plain`
routes the clients through the router without a tunnel: the ceiling.

| router CPUs | tswg | wireguard-go | kernel WG | plain | tswg/wg |
|---|---|---|---|---|---|
| 4 | 13976 Mbps (96% CPU) | 6627 (68%) | 9756 (91%) | 24890 | 2.1x |
| 8 | 21868 (86%) | 6808 (39%) | 10009 (70%) | 24897 | 3.2x |
| 16 | 22654 (49%) | 8217 (19%) | 11489 (65%) | 24898 | 2.8x |
| 8, 64 flows per client | 21088 (91%) | 6490 (41%) | 9665 (74%) | | 3.2x |

Router CPU seconds per GB forwarded: tswg 2.3-2.9, wireguard-go 2.9-4.2,
kernel WireGuard 3.2-7.3, plain 0.2-0.4. Medians of 3 interleaved runs.

* tswg scales with the router's CPUs until the network is the limit (at
  16 CPUs, 22.7 Gbps of inner traffic is about the 25 Gbps link with
  WireGuard's overhead), at the lowest CPU cost per byte.
* wireguard-go uses about 3 CPUs however many it has (2.7 of 4, 3.1 of 8,
  3.0 of 16), with the rest idle: each peer is capped at about 1.6 Gbps
  by a serial stage (its profile is mostly idle CPUs and context
  switches; most likely each peer's receive goroutine, which writes to
  TUN), so it only scales with more peers. Every tswg client got at
  least 4.6 Gbps.
* Upstream kernel WireGuard does better than wireguard-go but well below
  tswg, and least fairly (clients from 0.8 to 2.8 Gbps).

With many more peers (20 clients: the 4 above plus 16 c7i.large, 8
flows each, 160 flows; after the optimizations below):

| router CPUs | tswg | wireguard-go | kernel WG | plain | tswg/wg |
|---|---|---|---|---|---|
| 4 | 13893 Mbps (2.38 CPU-s/GB) | 6268 (3.87) | 10155 (3.35) | 24908 | 2.2x |
| 8 | 23031 (2.62) | 6444 (4.56) | 16935 (3.98) | 24940 | 3.6x |

wireguard-go doesn't scale with peers either (6.4 Gbps with 4 or 20, at
45% of 8 CPUs), so its limit is global rather than per peer: most likely
its one goroutine reading the UDP socket. Upstream kernel WireGuard
scales with peers (each has its own tx worker and NAPI), from 10.0 to
16.9 Gbps at 8 CPUs.

At 50 Gbps (2026-11-07): router and backend c7i.48xlarge (192 vCPUs,
50 Gbps), 8 clients c7i.8xlarge (12.5 Gbps sustained), 16 flows each, all
192 router CPUs:

| tunnel MTU | tswg | wireguard-go | kernel WG | plain |
|---|---|---|---|---|
| 1280 | 31504 Mbps (3.90 CPU-s/GB) | 7247 (3.87) | 12335 (94.7) | 49911 |
| 8920 | 49611 (2.18) | 17475 (1.86) | 49156 (15.0) | 49900 |

* Jumbo MTUs are rare among Tailscale's customers (decided 2026-11-07:
  the target is MTU 1280; jumbo results are only a data point). With
  them (the VPC's MTU is 9001), tswg forwards at line rate, 2.8x
  wireguard-go, using about 13 of the 192 CPUs. Kernel
  WireGuard gets there too but with 7x the CPU per byte: its per-packet
  round-robin worker kicks reach all 192 CPUs (at MTU 1280, 137 of them
  busy for 12 Gbps), which tswg's on-demand kicks avoid.
* At Tailscale's MTU, 1280, EC2 limits each NIC receive queue to about
  715k packets per second (the router's ENA has 16), about 7.3 Gbps of
  tunnel packets, and a peer's tunnel is one UDP flow, so one queue: a
  single tunnel tops out there (tswg and wireguard-go alike, between any
  c7i sizes), and with 8 peers, flows collide on queues (4 clients on 3
  queues: the two sharing got half each). More peers spread better; a
  larger MTU needs 7x fewer packets. The router's CPUs weren't the limit.
* With more peers at MTU 1280 (24 clients: the 8 above plus 16
  c7i.2xlarge, 8 flows each, 192 flows), traffic spreads over all the
  queues: tswg 39996 Mbps (4.49 CPU-s/GB, about 22 of the 192 CPUs busy),
  wireguard-go 7107 (5.6x less), kernel WireGuard 13463 (78% of 192
  CPUs). There the limit is EC2's packet rate allowance for the
  instance (ENA's `pps_allowance_exceeded` rises during tswg's runs): at
  MTU 1280 everything the router handles is small (tunnel packets in,
  1280-byte TCP segments out to the backend, ACKs both ways), about 12M
  packets per second at 40 Gbps. (The plain baseline isn't comparable
  here: without a tunnel, the clients' TCP uses the VPC's 9001-byte MTU.)
* For more: instances with higher packet rate allowances, such as c6in
  (network optimized, up to 200 Gbps), which the IAM policy doesn't allow
  yet.

Profile of the tswg router at 4 CPUs (CPU-bound), before the
optimizations: ChaCha20-Poly1305 about 23% (of which 5.5% was a scalar
ChaCha20 block per message for its Poly1305 key), the ENA driver about
20%, packet allocation and freeing about 15%, copying decrypted messages
out 8%, zeroing new pages 5% (Ubuntu enables `init_on_alloc`).

* Kept: decrypting straight from the received packet when a message is
  contiguous there (`tswg_contig`), and our own ChaCha20-Poly1305
  (`tswg_aead.h`), which gets the Poly1305 key in the same SIMD pass as
  the message by running ChaCha20 from block 0 over the 64 bytes before
  it too and XORing them back out. With 4 clients: 14.1 to 14.9 Gbps,
  2.30 to 2.18 CPU-s/GB.
* Tried, not kept: zero-copy receive (decrypting in place in the received
  pages, handing out packets that reference them), 7% worse:
  scatterlist decryption costs more than linear decryption of an L1-hot
  copy, and page-fragment packets cost more downstream (header pulls for
  NAT, more transmit descriptors). A page pool per decrypt worker for
  decrypted packets, to avoid allocating and zeroing pages: they didn't
  come back in time, so it still allocated, and was no better. Capping
  wg0's `gro_max_size` at 17 segments (so forwarded GRO packets have no
  frag_list and the NIC does TSO in hardware): worse, since bigger GRO
  packets save more in forwarding than software segmentation costs.

EC2 tooling: `scripts/ec2.sh` (`up`, `start`, `stop`, `down`, `ssh`,
`status`) manages instances in the sandbox account (profile
`tswg-sandbox`, us-west-2: the org's SCP allows only some regions, and
requires IMDSv2). Everything it creates is named `bradfitz-tswg...` and
tagged `owner=claude-tswg`, the only instances the IAM user may manage.
`scripts/ec2-idle-stop.sh install` sets up a systemd user timer on the
(always-on) dev host that stops the instances once
`~/.cache/tslinux/ec2/last-used` is 30 minutes old; `ec2.sh` and the
harness's remote mode touch it while in use. Remote mode
(`TSWG_REMOTE=~/.cache/tslinux/ec2/hosts.json`, which `ec2.sh` writes)
copies the agent and the module sources to the instances, builds tswg.ko
on each against its own kernel (with the compiler in `/proc/version`),
and runs the agent there under systemd; every lean test and script
(`leanbench.sh`, `leancompare.sh`) then runs unchanged.

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
  smoke test), `leancompare.sh` (quick A/B medians), `ec2.sh` and
  `ec2-idle-stop.sh` (EC2 instances for the harness's remote mode), and
  `subnetbench.sh` (the subnet router benchmark).

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
- [x] Idle latency in VMs (2026-11-08): inline crypto for lone packets
      when the workers are idle, and softirq NAPI; 0.77-0.85x
      wireguard-go's idle RTT p50, with subnet router throughput
      unchanged. Sending from the encrypt worker (skipping the tx
      worker) wasn't needed.
- [x] Zero-copy receive: tried, 7% worse on a CPU-bound subnet router,
      and no better on a 200 Gbps one where page allocation is the limit
      (see "Results at a glance"); kept behind `rx_zerocopy`, off.
- [ ] TSO from the inner GSO packet: encrypt straight from it, building
      each segment's headers, instead of `skb_gso_segment` in `wg_xmit`
      (per-segment skb allocation).
- [ ] Device-coalesced input: UDP packets that arrive already GSO from
      the NIC (VM-to-VM with guest USO) skip GRO, so UDP segments them,
      with software checksums, before `encap_rcv`.
- [x] Benchmark a subnet router with many clients and flows
      (`TestLeanSubnetRouter`): 2.1-3.2x wireguard-go.
- [ ] Subnet router with many more peers than client machines (several
      tunnels per client machine, in network namespaces), and an exit
      node benchmark.
- [ ] tailscaled: loading tswg.ko from an image (rather than modprobe, as
      DKMS would) must load its dependencies first on distro kernels
      (udp_tunnel, ip6_udp_tunnel, libcurve25519 are modules on Ubuntu);
      the harness agent does (`loadModuleDeps`).
- [x] Benchmarks on cloud VMs (EC2, harness remote mode, `scripts/ec2.sh`).
- [x] Subnet router beyond 40 Gbps at MTU 1280: c6in.32xlarge, 74 Gbps
      with 60 clients (12x wireguard-go).
- [ ] Subnet router past 75 Gbps at MTU 1280: the ENA interrupt CPUs'
      page allocator contention, from ENA allocating a page per received
      packet (zero-copy receive, taking tswg's own allocations out, didn't
      help). Ideas: ENA with a page pool (upstream driver work); NICs
      outside EC2 (mlx5 has a page pool); EC2 metal uses ENA too.
- [ ] EC2: c7i.large (2 vCPUs, CPU-bound), and the QEMU lab on a
      c7i.metal-24xl (to see what nesting cost the lab's numbers).
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
- [x] Kernel mode (tailscaled) over IPv6: exercised on EC2 (some of the
      subnet router benchmark's clients took direct IPv6 paths).
- [x] Kernel mode bugs found by the EC2 tailscaled benchmark: a reconcile
      race that left a node's kernel device without its private key (more
      likely with many peers), and the engine never closing the kernel
      data plane, leaving tailscale0 behind for a later TUN-mode
      tailscaled to trip over.
- [ ] A natlab test with many peers (the key race only showed with
      dozens), and one for switching between kernel and TUN mode.
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
