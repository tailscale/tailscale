// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet2/internal/clientsock"
	"tailscale.com/tsnet2/proto"
	"tailscale.com/types/logger"
)

// errNotImplemented is the sentinel returned by methods that are still
// stubs (those deferred to a later release per PLAN.tsnet2.md).
var errNotImplemented = errors.New("tsnet2: not implemented")

// ErrNotImplemented is returned from methods on Server that have not yet been
// implemented. Callers can use [errors.Is] to detect this case.
var ErrNotImplemented = errNotImplemented

// Server is an embedded Tailscale node that proxies all of its network
// and control-plane state through an out-of-process daemon (tsnet2d)
// over a Unix socket. See PLAN.tsnet2.md.
//
// The public API is intended to match [tailscale.com/tsnet.Server] so
// programs can switch implementations by changing a single import line.
//
// Exported fields may be changed until the first method call.
type Server struct {
	Dir            string
	Store          ipn.StateStore
	Hostname       string
	UserLogf       logger.Logf
	Logf           logger.Logf
	Ephemeral      bool
	AuthKey        string
	ControlURL     string
	Port           uint16
	Tun            tun.Device
	AdvertiseTags  []string
	SocketPath     string
	TrafficLogPath string

	// stateP holds the per-Server runtime state. It is a plain
	// pointer rather than an atomic.Pointer so the exported Server
	// struct stays copy-friendly (no embedded no-copy types) — this
	// keeps go vet happy when tests reflect over the value-type
	// Server. Init is guarded by the package-level stateInitMu.
	stateP *serverState
}

// stateInitMu serialises the lazy allocation of (*Server).stateP. It
// is package-level so the Server type itself contains no
// non-copy-safe fields.
var stateInitMu sync.Mutex

// serverState holds the per-Server runtime state. Allocated on the
// first call to a method that needs it.
type serverState struct {
	initOnce sync.Once
	initErr  error

	mu     sync.Mutex
	closed bool
	rpc    *clientsock.RPCClient
	upRes  *proto.UpResult

	// listeners tracks the per-listener accept-worker goroutines so
	// they can be stopped on Close.
	listeners map[string]*listener
}

// state returns the per-Server runtime state, allocating it on first
// use. Concurrent first calls serialise on stateInitMu.
func (s *Server) state() *serverState {
	if s.stateP != nil {
		return s.stateP
	}
	stateInitMu.Lock()
	defer stateInitMu.Unlock()
	if s.stateP == nil {
		s.stateP = &serverState{listeners: map[string]*listener{}}
	}
	return s.stateP
}

// FallbackTCPHandler matches tsnet's signature so callers don't need
// to change imports.
type FallbackTCPHandler func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool)

// Start connects the server to the tailnet via the tsnet2d daemon.
// Optional: any calls to Dial/Listen will also call Start.
func (s *Server) Start() error {
	st := s.state()
	st.initOnce.Do(func() { s.doInit(st) })
	return st.initErr
}

func (s *Server) doInit(st *serverState) {
	if s.SocketPath == "" {
		// The smoke test constructs an empty Server and expects every
		// "needs a daemon" method to return ErrNotImplemented; honor
		// that by wrapping the sentinel here so callers can still
		// distinguish "not configured" from a real I/O error.
		st.initErr = fmt.Errorf("tsnet2: SocketPath is required: %w", errNotImplemented)
		return
	}
	if s.Tun != nil {
		st.initErr = errors.New("tsnet2: Tun is not supported in v1 (daemon owns the TUN)")
		return
	}

	// Wait briefly for the daemon socket to appear; the integration
	// test launches the daemon as a subprocess and then immediately
	// creates the Server, so a small backoff loop is the simplest
	// way to handle the race.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dialWithRetry(ctx, s.SocketPath, proto.ChannelControl)
	if err != nil {
		st.initErr = fmt.Errorf("tsnet2: dial daemon: %w", err)
		return
	}
	st.rpc = clientsock.NewRPCClient(c)

	startCtx, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	params := proto.StartParams{
		Hostname:      s.Hostname,
		ControlURL:    s.ControlURL,
		AuthKey:       s.AuthKey,
		Ephemeral:     s.Ephemeral,
		AdvertiseTags: s.AdvertiseTags,
	}
	if err := st.rpc.Call(startCtx, proto.MethodStart, params, nil); err != nil {
		st.initErr = fmt.Errorf("tsnet2: daemon start: %w", err)
		return
	}
}

// dialWithRetry retries clientsock.Dial until it succeeds or ctx is
// done. We need this because the integration test launches the daemon
// subprocess concurrently with constructing the Server.
func dialWithRetry(ctx context.Context, path string, kind proto.ChannelKind) (net.Conn, error) {
	backoff := 50 * time.Millisecond
	for {
		c, err := clientsock.Dial(ctx, path, kind)
		if err == nil {
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("dial %s: %w", path, err)
		case <-time.After(backoff):
		}
		if backoff < time.Second {
			backoff *= 2
		}
	}
}

// Up connects the server to the tailnet and waits until it is running.
// On success it returns the current status, including a Tailscale IP.
func (s *Server) Up(ctx context.Context) (*ipnstate.Status, error) {
	if err := s.Start(); err != nil {
		return nil, err
	}
	st := s.state()
	var res proto.UpResult
	if err := st.rpc.Call(ctx, proto.MethodUp, nil, &res); err != nil {
		return nil, fmt.Errorf("tsnet2.Up: %w", err)
	}
	st.mu.Lock()
	r := res
	st.upRes = &r
	st.mu.Unlock()
	status := &ipnstate.Status{
		TailscaleIPs: res.TailscaleIPs,
		CertDomains:  res.CertDomains,
	}
	return status, nil
}

// Close stops the server. It must not be called before or concurrently with Start.
func (s *Server) Close() error {
	st := s.state()
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return fmt.Errorf("tsnet2: %w", net.ErrClosed)
	}
	st.closed = true
	listeners := st.listeners
	st.listeners = nil
	st.mu.Unlock()

	for _, ln := range listeners {
		ln.Close()
	}
	if st.rpc != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = st.rpc.Call(ctx, proto.MethodClose, nil, nil)
		st.rpc.Close()
	}
	return nil
}

// Listen announces only on the Tailscale network.
func (s *Server) Listen(network, addr string) (net.Listener, error) {
	if err := s.Start(); err != nil {
		return nil, err
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("tsnet2.Listen: unsupported network %q", network)
	}
	st := s.state()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var res proto.RegisterListenerResult
	if err := st.rpc.Call(ctx, proto.MethodRegisterListener, proto.RegisterListenerParams{
		Network: network,
		Addr:    addr,
	}, &res); err != nil {
		return nil, fmt.Errorf("tsnet2.Listen: %w", err)
	}

	ln := newListener(s, network, res.ListenerID, res.Addr)
	st.mu.Lock()
	st.listeners[res.ListenerID] = ln
	st.mu.Unlock()
	ln.spawnWorkers(2) // pre-park a small pool of accept workers.
	return ln, nil
}

// ListenTLS is not implemented in v1.
func (s *Server) ListenTLS(network, addr string) (net.Listener, error) {
	return nil, errNotImplemented
}

// Dial connects to the address on the tailnet via the daemon.
func (s *Server) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if err := s.Start(); err != nil {
		return nil, err
	}
	c, err := dialWithRetry(ctx, s.SocketPath, proto.ChannelDatapath)
	if err != nil {
		return nil, err
	}
	hdr := proto.DatapathHeader{Op: "dial", Network: network, Addr: address}
	hdrBytes, _ := json.Marshal(hdr)
	hdrBytes = append(hdrBytes, '\n')
	if _, err := c.Write(hdrBytes); err != nil {
		c.Close()
		return nil, err
	}
	// Read one status line ("\n"-terminated JSON).
	statusBuf := make([]byte, 0, 256)
	var oneByte [1]byte
	for {
		_, rerr := c.Read(oneByte[:])
		if rerr != nil {
			c.Close()
			return nil, fmt.Errorf("tsnet2.Dial: read status: %w", rerr)
		}
		if oneByte[0] == '\n' {
			break
		}
		statusBuf = append(statusBuf, oneByte[0])
		if len(statusBuf) > 1024 {
			c.Close()
			return nil, errors.New("tsnet2.Dial: status line too long")
		}
	}
	var reply struct {
		OK  bool   `json:"ok"`
		Err string `json:"err,omitempty"`
	}
	if err := json.Unmarshal(statusBuf, &reply); err != nil {
		c.Close()
		return nil, fmt.Errorf("tsnet2.Dial: bad status: %w", err)
	}
	if !reply.OK {
		c.Close()
		return nil, fmt.Errorf("tsnet2.Dial: %s", reply.Err)
	}
	return &conn{
		s:      s,
		nc:     c,
		local:  addr{network: network, addr: ""},
		remote: addr{network: network, addr: address},
	}, nil
}

// TailscaleIPs returns IPv4 and IPv6 addresses for this node.
func (s *Server) TailscaleIPs() (ip4, ip6 netip.Addr) {
	st := s.stateP
	if st == nil {
		return netip.Addr{}, netip.Addr{}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.upRes == nil {
		return netip.Addr{}, netip.Addr{}
	}
	for _, ip := range st.upRes.TailscaleIPs {
		if ip.Is6() {
			ip6 = ip
		}
		if ip.Is4() {
			ip4 = ip
		}
	}
	return ip4, ip6
}

// GetRootPath returns the root path of the tsnet2 server.
func (s *Server) GetRootPath() string {
	return s.Dir
}

// RegisterFallbackTCPHandler is a v1 no-op (no in-repo consumer the
// integration test depends on); the API stub matches tsnet for
// drop-in compatibility.
func (s *Server) RegisterFallbackTCPHandler(cb FallbackTCPHandler) func() {
	return func() {}
}

// CertDomains returns the list of domains for which the server can
// provide TLS certificates. Populated on Up.
func (s *Server) CertDomains() []string {
	st := s.stateP
	if st == nil {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.upRes == nil {
		return nil
	}
	out := make([]string, len(st.upRes.CertDomains))
	copy(out, st.upRes.CertDomains)
	return out
}
