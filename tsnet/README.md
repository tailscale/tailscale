# tsnet

Package `tsnet` embeds a Tailscale node directly into a Go program, allowing it to join a tailnet and accept or dial connections without running a separate `tailscaled` daemon or requiring any system-level configuration.

## Overview

Normally, Tailscale runs as a background system service (`tailscaled`) that manages a virtual network interface for the whole machine. `tsnet` takes a different approach: it runs a fully self-contained Tailscale node inside your process using a userspace TCP/IP stack (gVisor). This means:

- No root privileges required.
- No system daemons to install or manage.
- Multiple independent Tailscale nodes can run within a single binary.
- The node's [identity](https://tailscale.com/docs/concepts/tailscale-identity) and state are stored in a directory you control.

The core type is `Server`, which represents one embedded Tailscale node. Calling `Listen` or `Dial` on a `Server` routes traffic exclusively over the tailnet. The standard library's `net.Listener` and `net.Conn` interfaces are returned, so any existing Go HTTP server, gRPC server, or other net-based code works without modification.

## Usage

```go
import "tailscale.com/tsnet"

s := &tsnet.Server{
    Hostname: "my-service",
    AuthKey:  os.Getenv("TS_AUTHKEY"),
}
defer s.Close()

ln, err := s.Listen("tcp", ":80")
if err != nil {
    log.Fatal(err)
}

log.Fatal(http.Serve(ln, myHandler))
```

On first run, if no `AuthKey` is provided and the node is not already enrolled, the server logs an authentication URL. Open it in a browser to add the node to your tailnet.

## Server fields

| Field | Description |
|---|---|
| `Hostname` | The node name shown on the tailnet. Defaults to the binary name. |
| `Dir` | Directory for persistent state (node key, logs). Defaults to a subdirectory of `os.UserConfigDir()` named after the binary. Must exist if set. |
| `Store` | Custom `ipn.StateStore`. If nil, a `FileStore` is used at `Dir/tailscaled.state`. An in-memory store (`store/mem`) is only supported for ephemeral nodes. |
| `AuthKey` | Auth key for initial enrollment. Falls back to `TS_AUTHKEY` / `TS_AUTH_KEY` env vars. Ignored if the node is already enrolled. |
| `ClientSecret` | OAuth client secret for generating auth keys. Falls back to `TS_CLIENT_SECRET`. |
| `ClientID` | Client ID for workload identity federation. Falls back to `TS_CLIENT_ID`. |
| `IDToken` | ID token for workload identity federation. Falls back to `TS_ID_TOKEN`. |
| `Audience` | Audience for requesting an ID token from a well-known provider. Falls back to `TS_AUDIENCE`. |
| `ControlURL` | Coordination server URL. Falls back to `TS_CONTROL_URL`, then the Tailscale default. |
| `Ephemeral` | If true, registers as an ephemeral node that is removed from the tailnet when the process exits. |
| `AdvertiseTags` | ACL tags to apply to the node (e.g. `[]string{"tag:server"}`). The control server must permit the node to use these tags. |
| `RunWebClient` | If true, runs the Tailscale web client on port 5252 of the node's Tailscale IP. |
| `Port` | UDP port for WireGuard traffic. Zero (default) selects automatically. |
| `Tun` | Custom `tun.Device` for packet I/O. Must be set before `Start`. When set, packets flow through the TUN rather than the internal userspace stack. |
| `Logf` | Verbose backend logger (MagicSock, LocalBackend). Logs are discarded if nil. |
| `UserLogf` | User-facing logger for auth URLs and status. Defaults to `log.Printf`. |

## Key methods

| Method | Description |
|---|---|
| `Start() error` | Connects to the tailnet. Called implicitly by `Listen`/`Dial`. |
| `Up(ctx) (*Status, error)` | Starts the server and blocks until the node is `Running`, returning the current status. |
| `Close() error` | Shuts down the node and releases all resources. |
| `Listen(network, addr) (net.Listener, error)` | Listens for inbound connections on the tailnet only. |
| `ListenTLS(network, addr) (net.Listener, error)` | Like `Listen` but wraps the listener in TLS using a Tailscale-managed certificate. Requires MagicDNS and HTTPS to be enabled in the admin console. |
| `ListenPacket(network, addr) (net.PacketConn, error)` | Listens for UDP packets on the tailnet. The address must include an explicit IP. |
| `ListenFunnel(network, addr, ...opts) (net.Listener, error)` | Exposes the service on the public internet via [Tailscale Funnel](https://tailscale.com/docs/features/tailscale-funnel). Supports `:443`, `:8443`, and `:10000`. Returns a TLS listener. Use `FunnelOnly()` to restrict to public connections only. |
| `ListenService(name, mode) (*ServiceListener, error)` | Advertises a [Tailscale Service](https://tailscale.com/docs/features/tailscale-services) on the tailnet. The node must be tagged. |
| `Dial(ctx, network, address) (net.Conn, error)` | Dials an address on the tailnet. |
| `HTTPClient() *http.Client` | Returns an `*http.Client` whose transport dials via the tailnet. |
| `LocalClient() (*local.Client, error)` | Returns an in-process client for the LocalAPI (WhoIs, GetCertificate, etc.). |
| `Loopback() (addr, proxyCred, localAPICred string, err error)` | Starts a localhost SOCKS5 proxy and LocalAPI HTTP server. Useful for non-Go callers. |
| `TailscaleIPs() (ip4, ip6 netip.Addr)` | Returns the node's IPv4 and IPv6 Tailscale addresses. |
| `CertDomains() []string` | Returns the DNS names for which the node can obtain TLS certificates. |
| `RegisterFallbackTCPHandler(cb) func()` | Registers a handler of last resort for TCP flows with no matching listener. Returns a deregister function. |
| `CapturePcap(ctx, file) error` | Writes a pcap of all netstack traffic to a file for debugging with Wireshark. |
| `GetRootPath() string` | Returns the state directory path. |
| `Sys() *tsd.System` | Returns internal Tailscale subsystems. Not a stable API. |

## Authentication

A `Server` authenticates using (in order of precedence):

1. `Server.AuthKey`
2. `TS_AUTHKEY` environment variable
3. `TS_AUTH_KEY` environment variable
4. OAuth client secret (`Server.ClientSecret` / `TS_CLIENT_SECRET`) to generate an auth key
5. Workload identity federation (`Server.ClientID` + `Server.IDToken` or `Server.Audience`)
6. Interactive login URL printed to `UserLogf`

If the node is already enrolled (state found in `Store`), the auth key is ignored unless `TSNET_FORCE_LOGIN=1` is set.

## Running multiple nodes in one process

Each `Server` instance is an independent node. Give each a unique `Dir` and `Hostname`:

```go
for _, name := range []string{"frontend", "backend"} {
    srv := &tsnet.Server{
        Hostname:  name,
        Dir:       filepath.Join(baseDir, name),
        AuthKey:   os.Getenv("TS_AUTHKEY"),
        Ephemeral: true,
    }
    srv.Start()
}
```

## Tailscale Funnel

`ListenFunnel` exposes your service on the public internet. [Tailscale Funnel](https://tailscale.com/docs/features/tailscale-funnel) currently supports TCP on ports 443, 8443, and 10000. HTTPS must be enabled in the Tailscale admin console.

```go
ln, err := srv.ListenFunnel("tcp", ":443")
// ln is a TLS listener; connections can come from anywhere on the internet
// as well as from your tailnet.

// To restrict to public traffic only:
ln, err = srv.ListenFunnel("tcp", ":443", tsnet.FunnelOnly())
```

## Tailscale Services

`ListenService` advertises the node as a host for a named [Tailscale Service](https://tailscale.com/docs/features/tailscale-services). The node must use a tag-based identity. To advertise multiple ports, call `ListenService` once per port.

```go
srv.AdvertiseTags = []string{"tag:myservice"}

ln, err := srv.ListenService("svc:my-service", tsnet.ServiceModeHTTP{
    HTTPS: true,
    Port:  443,
})
log.Printf("Listening on https://%s", ln.FQDN)
```

## Identifying callers

Use `LocalClient.WhoIs` to identify who is making a request:

```go
lc, _ := srv.LocalClient()

http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    fmt.Fprintf(w, "Hello, %s!", who.UserProfile.LoginName)
}))
```

## Building

`tsnet` is a regular Go package. Build it like any other:

```bash
go build tailscale.com/tsnet
```

To build and run the included `tshello` example:

```bash
go run tailscale.com/tsnet/example/tshello
```

Other runnable examples are in the `example/` subdirectory:

| Example | Description |
|---|---|
| `example/tshello` | Simple HTTP server that greets the caller by their Tailscale identity |
| `example/tsnet-funnel` | HTTP server exposed to the public internet via Funnel |
| `example/tsnet-http-client` | Makes outbound HTTP requests over the tailnet |
| `example/tsnet-services` | Demonstrates Tailscale Services |
| `example/web-client` | Runs the Tailscale web management client |

### Running tests

```bash
go test tailscale.com/tsnet/...
```

Tests that exercise real network behavior are integration-style and may take longer. Use `-count=1` to bypass test caching.

## Environment variables

| Variable | Effect |
|---|---|
| `TS_AUTHKEY` / `TS_AUTH_KEY` | Auth key used when `Server.AuthKey` is not set |
| `TS_CLIENT_SECRET` | OAuth client secret when `Server.ClientSecret` is not set |
| `TS_CLIENT_ID` | Client ID for workload identity federation |
| `TS_ID_TOKEN` | ID token for workload identity federation |
| `TS_AUDIENCE` | Audience for requesting an ID token |
| `TS_CONTROL_URL` | Override the coordination server URL |
| `TSNET_FORCE_LOGIN` | Set to `1` to force re-enrollment even if the node already has state |

## Limitations

- The `Loopback()` SOCKS5 proxy only supports TCP (no HTTP CONNECT proxy yet).
- `ListenFunnel` only supports TCP on ports 443, 8443, and 10000.
- `ListenService` requires the node to have at least one ACL tag.
- An in-memory `Store` is only supported for ephemeral nodes.
- UDP `ListenPacket` requires an explicit IP address in the `addr` argument.
- Listeners without a specified IP address only match traffic destined for the node's own Tailscale IPs. To handle subnet-routed traffic, specify the IP explicitly or use `RegisterFallbackTCPHandler`.

## Additional resources

For more information, refer to the Tailscale [tsnet](https://tailscale.com/docs/features/tsnet) topic.
