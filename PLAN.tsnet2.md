# tsnet2 — Out-of-Process tsnet with Traffic Auditing

## Goal

Replace `tailscale.com/tsnet` for the user's corporate deployments with a drop-in
variant where the WireGuard cryptography, control-plane state, and `LocalBackend`
all live in a separate long-lived daemon process. The application links only a
thin shim that talks to the daemon over a Unix socket. This gives a single
chokepoint for auditing/logging cleartext traffic to/from the app — which is
impossible with stock tsnet because everything outside the process is encrypted
WireGuard.

Non-goal: replacing `tailscaled` itself. tsnet2 sits at the same layer as tsnet.

## Why not reuse the built-in netlog feature

Tailscale already has flow logging in `wgengine/netlog/`. It is **not** a fit
for this use case because:

- It only records aggregated 5-tuple counters (TxPackets/TxBytes/RxPackets/RxBytes)
  over a fixed time window — no payload data, no application visibility.
- Its destination is hard-wired to `tailtraffic.log.tailscale.io` (Tailscale's
  cloud log collector), not a local file.
- It's gated by a control-plane capability (`CapabilityDataPlaneAuditLogs`) — the
  control server has to opt the node in.
- Its callback interface (`netlogfunc.ConnectionCounter`) receives counts, not
  packet data; capturing payloads would require deeper hooks the netlog package
  doesn't expose.

We want a *local* logger that sees full cleartext bytes at the application
boundary. The architectural seam where the daemon hands cleartext bytes back to
the app process is exactly the right tap point.

## Architecture

```
+----------------------------------+
|   Application process            |
|                                  |
|   import "tailscale.com/tsnet2"  |
|                                  |
|   s := &tsnet2.Server{...}       |
|   s.Listen("tcp", ":80")  -----> | thin shim, ~all logic delegated
|   s.Dial(...)                    |
|   s.LocalClient().WhoIs(...)     |
+--------------+-------------------+
               |
               | Unix socket: ${state}/tsnet2.sock
               |
+--------------v-------------------+
|   tsnet2d daemon                 |
|                                  |
|   - wgengine + magicsock + netstack
|   - controlclient                |
|   - ipnlocal.LocalBackend        |
|   - localapi.Handler             |
|   - traffic logger (JSON lines)  |
|                                  |
|   one tsnet2d per Server (1:1)   |
+----------------------------------+
```

**Key principle:** push everything we can out of the application process. The
in-app shim should be small enough that a security reviewer can read it in one
sitting. The motivation is "what if we want to run less-trusted code in the app
process" — the audit log should be tamper-resistant from the app's perspective
because the app simply doesn't have the keys or the network access that produced
the cleartext.

**Process lifecycle:** the daemon is **not** auto-spawned. The user runs
`tsnet2d` separately (e.g., as a systemd unit). The `Server` config gets a new
field `SocketPath string` pointing at its daemon's socket. One daemon per app
instance (1:1) keeps state isolation simple; if the user later wants multiplexing
we can extend the protocol.

## Wire protocol

Single Unix socket. Each TCP-like connection on the socket is one of three
"channel kinds", chosen by a small framed handshake the client sends after
connecting:

1. **control** — long-lived; framed JSON-or-protobuf RPC for lifecycle
   (`Start`, `Up`, `Close`), listener registration/unregistration, fallback
   handler registration, callbacks for IPN bus events the shim needs. One per
   Server.
2. **localapi** — short-lived; after the handshake byte/header, the rest of the
   connection is plain HTTP/1.1 speaking to `localapi.NewHandler()` on the
   daemon side. `tsnet2.Server.LocalClient()` returns a `*local.Client` whose
   `Dial` field opens one of these per request. This works because the existing
   `local.Client` already speaks HTTP-over-arbitrary-Dial — we are reusing
   exactly the same trick stock tsnet uses with `memnet`, but with a real Unix
   socket instead of an in-memory pipe.
3. **datapath** — short-lived; one per accepted/dialed application connection.
   Carries a small metadata header (listener id or dial id, 5-tuple, direction,
   timestamps) followed by raw cleartext bytes flowing bidirectionally between
   the app and netstack's gVisor TCP/UDP socket inside the daemon.

For the **inbound (Listen + Accept)** path, two reasonable shapes exist; we'll
pick (b):

- (a) Client opens K "accept" connections and parks them; daemon writes accepted
  metadata when ready. Simpler framing, harder to size K.
- (b) Daemon listens on a *second* small socket that the client connects to on
  demand for each accept. Daemon accepts on its main socket only; for each
  inbound netstack flow, daemon dials *back* to a unix socket the client owns
  (`${state}/tsnet2-app.sock`). This inverts the usual direction but matches
  semantics: the client is acting as a server for tailnet traffic, and the
  daemon delivering accepted conns to it is the natural shape. The control
  channel pre-registers the listener so the daemon knows where to dial.

For the **outbound (Dial)** path: client opens a datapath connection, sends a
`DialRequest{network, addr}` header, daemon dials via netstack/`tsdial`, then
bytes stream.

### Datapath framing

For v1 keep it dumb: after the metadata header line (one JSON object terminated
by `\n`), the rest of the connection is raw bytes in both directions, just like
a normal TCP relay. The daemon tees these bytes into the traffic log as it
proxies them.

UDP listeners (`ListenPacket`) need a packet-framed variant — length-prefixed
datagrams. Defer that to v2 if no consumer in the repo needs it (most do TCP);
a quick grep shows `cmd/natc` uses `RegisterFallbackUDPHandler` so we can't
ignore it forever, but it's not on the critical path.

## In-app API surface

Goal: same names and signatures as `tailscale.com/tsnet.Server` so existing
consumers (k8s-operator, sniproxy, tsidp, pgproxy, tsnet-proxy, etc.) can
migrate by changing one import line.

Required for v1 (every method real consumers in this repo touch):

- Fields: `Dir`, `Store`, `Hostname`, `UserLogf`, `Logf`, `Ephemeral`, `AuthKey`,
  `ControlURL`, `Port`, `Tun` (probably nil-only — daemon owns the TUN),
  `AdvertiseTags`. **New fields:** `SocketPath` (daemon socket),
  `TrafficLogPath` *(optional override — by default daemon controls)*.
- Methods: `Start`, `Up`, `Close`, `Listen`, `ListenTLS`, `Dial`,
  `LocalClient`, `TailscaleIPs`, `GetRootPath`, `RegisterFallbackTCPHandler`,
  `CertDomains`.
- Deferred to v2 (in-repo consumers exist but they're fewer / more complex):
  `ListenPacket`, `ListenFunnel`, `ListenService`, `Loopback`, `LogtailWriter`,
  `CapturePcap`, `Sys`, `RegisterFallbackUDPHandler`.

`LocalClient` returns a real `*local.Client` with `Dial` pointed at the
LocalAPI channel handshake on the daemon socket. Every existing LocalClient
method (`WhoIs`, `Status`, `EditPrefs`, `GetServeConfig`, `SetServeConfig`,
`WatchIPNBus`, `GetCertificate`, `ExpandSNIName`, `StartLoginInteractive`, etc.)
works for free — they all just speak HTTP to the handler, and the handler is in
the daemon now.

### Endpoints with proxying gotchas

The exploration of localapi turned up a few endpoints we can't just dumb-proxy:

- **`/localapi/v0/dial`** — uses `http.Hijacker` to splice a raw TCP socket.
  Our localapi channel is already a raw socket after the HTTP exchange, so
  hijack works if we don't impose buffered framing. Test this explicitly.
- **`/localapi/v0/watch-ipn-bus`** and **`/localapi/v0/logtap`** — streaming
  with `http.Flusher`. The proxy must flush as bytes arrive, not buffer.
  Because the localapi channel is just `conn ↔ http.Handler`, Flusher works
  natively. Test this too.
- **`/localapi/v0/bugreport`** — long-lived POST. Don't set timeouts on the
  channel.

These are not blockers; they're tests we need to remember to write.

## Traffic logging

Default: JSON Lines to a file in the daemon's state dir, rotated by size (use
`tailscale.com/logtail/filch` or a simple log-rotation lib — defer the decision
to implementation). Three record types:

```jsonc
{"t":"...","kind":"open","conn_id":"...","dir":"in","listener_id":"...",
 "local":"100.64.0.1:80","remote":"100.64.0.2:54321",
 "proto":"tcp","whois":{"node":"...","user":"..."}}

{"t":"...","kind":"data","conn_id":"...","dir":"app->peer","seq":12,
 "len":1460,"payload_b64":"..."}

{"t":"...","kind":"close","conn_id":"...","bytes_in":4096,"bytes_out":12340,
 "duration_ms":3210,"error":""}
```

User wants per-connection metadata **plus** payload bytes. Payload records are
big — provide a size cap per record (default ~16 KiB; bigger chunks get split)
and let the user configure max-payload-per-conn (or unbounded). Make the logger
pluggable behind a Go interface (`TrafficLogger`) so the JSON-to-file emitter
is one of N possible implementations.

WhoIs enrichment on `open`: when the daemon accepts an inbound conn from a
tailnet peer, do a single in-process WhoIs and embed the result. This is the
thing the user can't easily do at any other layer.

## Code layout

```
tsnet2/                          # in-app shim, public API
  tsnet2.go                      # Server struct, Start/Up/Close/Listen/Dial/...
  localclient.go                 # LocalClient() returns *local.Client with custom Dial
  conn.go                        # net.Conn wrapper over a datapath channel
  listener.go                    # net.Listener wrapper
  proto/                         # wire protocol types (control / handshake / datapath header)
  internal/clientsock/           # socket dialer + handshake helpers

cmd/tsnet2d/                     # the daemon binary
  main.go                        # flag parsing, socket setup, supervisor loop
  daemon/                        # daemon-side: wgengine + LocalBackend + listener server
    server.go
    controlchan.go               # control channel RPC server
    localapichan.go              # localapi channel handler
    datapath.go                  # datapath channel handler + tee into logger
    netlistener.go               # binds netstack listeners and dials back to app socket
  logger/                        # TrafficLogger interface + JSONL file impl
```

Reuse from existing tailscale code without forking:

- `wgengine`, `magicsock`, `netstack`, `tsdial`, `ipn/ipnlocal`,
  `ipn/localapi`, `tsd` — all imported into `cmd/tsnet2d` exactly as
  `cmd/tailscaled` and `tsnet` do.
- `client/local` — imported into both processes; client uses it directly with a
  custom Dial.
- `safesocket` and `ipnauth/peercred` — for Unix socket auth between daemon and
  app (same UID check tailscaled already does).

## Auth between app and daemon

Use `peercred` exactly like tailscaled: daemon's socket accepts only
connections from its own UID (configurable). Set
`ipnauth.Actor = ipnauth.Self` inside the daemon for proxied LocalAPI calls,
since the daemon has already validated the app identity at the socket layer.

## Test strategy

1. **Compile/smoke test** (skeleton phase): import the package, instantiate a
   `Server{}`, assert public methods exist. No daemon needed.
2. **End-to-end test** (the failing test set up in the RED phase): spin up a
   `testcontrol.Server` like the existing `tsnet/tsnet_test.go` does. Launch
   `tsnet2d` as a subprocess (use `go test` with `os.Executable` + a helper
   `TestMain` mode, or build the binary into a temp dir). Stand up two tsnet2
   `Server`s pointing at two daemons, do a TCP listen on one and a dial from
   the other, check bytes flow, then assert the JSONL traffic log contains
   `open`, `data` (with the bytes), and `close` records for the conn.
3. **LocalClient test**: same setup; from the app process, call
   `LocalClient().Status()` and `WhoIs(peerIP)`; assert results match.
4. **Streaming endpoint test**: call `WatchIPNBus` over the proxied LocalAPI,
   confirm events arrive in time-ordered chunks (validates Flusher passthrough).

Model #2's harness on `tsnet/tsnet_test.go:TestConn` — it already does most of
what we need (testcontrol + DERP/STUN + two-server topology).

## Migration path for in-repo consumers (not in scope for v1, just keeping it
in mind to size the API correctly)

Tier-1 (covered by v1 API surface): `cmd/tsnet-proxy`, `cmd/pgproxy`,
`cmd/proxy-to-grafana`, `cmd/checkmetrics`, simple tsnet/examples.

Tier-2 (need v2 features: ListenFunnel, ListenService, Loopback, UDP):
`cmd/k8s-operator`, `cmd/k8s-proxy`, `cmd/sniproxy`, `cmd/tsidp`, `cmd/natc`.

`cmd/checkmetrics` reaches into `Sys()` to grab internal metrics — that's the
only consumer that needs the in-process internal-types escape hatch, and we
can't proxy `*tsd.System` across a socket. Document this as a known
limitation: callers of `Sys()` cannot use tsnet2.

## Open questions (to revisit during implementation)

- TUN device passthrough: stock tsnet supports `Tun tun.Device` in the Server.
  In tsnet2 the TUN has to live in the daemon. v1 ignores the field;
  intercepting/passing through a host TUN can come later.
- Auth-key flow that uses interactive login: the user-visible login URL is
  printed via `UserLogf`. We need to forward those log lines from the daemon
  back to the app's `UserLogf` (control-channel notification kind).
- Restart semantics: if the daemon restarts, do listeners on the app side
  re-register automatically? v1: the control channel disconnect kills the app
  Server with an error; user restarts. v2: auto-reconnect.
