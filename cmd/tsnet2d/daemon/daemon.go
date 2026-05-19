// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package daemon implements the body of the tsnet2d daemon: it brings
// up wgengine + magicsock + netstack + LocalBackend + localapi, serves
// the Unix socket protocol described in tsnet2/proto, and
// tees cleartext bytes between netstack and the application process
// into the traffic logger.
package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/ipn/store"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsd"
	"tailscale.com/tsnet2/proto"
	"tailscale.com/tsnet2/traffic"
	"tailscale.com/types/bools"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/nettype"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
)

// Config configures the daemon.
type Config struct {
	// SocketPath is the Unix socket the daemon listens on for client
	// (tsnet2.Server) connections.
	SocketPath string

	// StateDir is the directory where persistent state (state store,
	// magicsock prefs, debug log) is kept.
	StateDir string

	// TrafficLogPath is the JSON Lines file to write cleartext traffic
	// records to. If empty, defaults to StateDir/traffic.jsonl.
	TrafficLogPath string

	// Logf, if set, is used for daemon debug logs. If nil, logs are
	// discarded.
	Logf logger.Logf
}

// Daemon is the running tsnet2d server. Construct with New and call
// Run to serve until the context is cancelled.
type Daemon struct {
	cfg     Config
	logf    logger.Logf
	traffic *traffic.Logger
	logid   logid.PublicID

	// State established lazily by Start; protected by initMu.
	initMu         sync.Mutex
	started        bool
	sys            *tsd.System
	lb             *ipnlocal.LocalBackend
	ns             *netstack.Impl
	dialer         *tsdial.Dialer
	netMon         *netmon.Monitor
	localAPI       *localapi.Handler
	startErr       error
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	// Listener tracking.
	lmu           sync.Mutex
	listeners     map[string]*regListener // listener_id -> listener
	listenerByKey map[listenerKey]*regListener

	// Pending accept slots indexed by listener_id (FIFO of parked
	// accept-channel sockets).
	amu        sync.Mutex
	acceptWait map[string][]*acceptSlot
	acceptCond *sync.Cond

	closeOnce sync.Once
	closeErr  error
}

// listenerKey indexes a (network, port) registered listener so an
// incoming netstack flow can quickly find its owner.
type listenerKey struct {
	network string
	port    uint16
}

// regListener tracks one app-registered listener.
type regListener struct {
	id      string
	key     listenerKey
	address string // resolved bind address, e.g. ":8080"
}

// acceptSlot is a parked accept-channel conn waiting for the daemon
// to hand it an inbound flow.
type acceptSlot struct {
	conn net.Conn
	done chan acceptResult
}

type acceptResult struct {
	c      net.Conn // the netstack TCP conn to splice with the app conn
	hdr    proto.AcceptHeader
	connID string // matches the open record already written
	err    error
}

// New returns a new Daemon.
func New(cfg Config) (*Daemon, error) {
	if cfg.SocketPath == "" {
		return nil, errors.New("daemon: SocketPath is required")
	}
	if cfg.StateDir == "" {
		return nil, errors.New("daemon: StateDir is required")
	}
	if cfg.TrafficLogPath == "" {
		cfg.TrafficLogPath = filepath.Join(cfg.StateDir, "traffic.jsonl")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("daemon: mkdir state dir: %w", err)
	}
	logf := cfg.Logf
	if logf == nil {
		logf = logger.Discard
	}
	tlog, err := traffic.New(cfg.TrafficLogPath)
	if err != nil {
		return nil, err
	}
	d := &Daemon{
		cfg:           cfg,
		logf:          logf,
		traffic:       tlog,
		listeners:     map[string]*regListener{},
		listenerByKey: map[listenerKey]*regListener{},
		acceptWait:    map[string][]*acceptSlot{},
	}
	d.acceptCond = sync.NewCond(&d.amu)
	d.shutdownCtx, d.shutdownCancel = context.WithCancel(context.Background())
	return d, nil
}

// Run serves the daemon's Unix socket until ctx is cancelled. It
// blocks.
func (d *Daemon) Run(ctx context.Context) error {
	// Remove any stale socket file from a prior run.
	_ = os.Remove(d.cfg.SocketPath)
	ln, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("daemon listen: %w", err)
	}
	defer ln.Close()
	// Announce readiness on stderr so the integration test can wait
	// deterministically.
	fmt.Fprintf(os.Stderr, "tsnet2d: pid=%d listening on %s\n", os.Getpid(), d.cfg.SocketPath)

	// Close the listener when the context is cancelled to unblock Accept.
	go func() {
		<-ctx.Done()
		ln.Close()
		d.shutdownCancel()
		// Wake any goroutines blocked in takeAcceptSlot.
		d.amu.Lock()
		d.acceptCond.Broadcast()
		d.amu.Unlock()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("daemon accept: %w", err)
		}
		go d.serveConn(c)
	}
}

// Close releases all daemon resources. Safe to call multiple times.
func (d *Daemon) Close() error {
	d.closeOnce.Do(func() {
		d.shutdownCancel()
		d.initMu.Lock()
		if d.ns != nil {
			d.ns.Close()
		}
		if d.lb != nil {
			d.lb.Shutdown()
		}
		if d.netMon != nil {
			d.netMon.Close()
		}
		if d.dialer != nil {
			d.dialer.Close()
		}
		d.initMu.Unlock()
		if d.traffic != nil {
			d.traffic.Close()
		}
	})
	return d.closeErr
}

// serveConn reads the channel-kind handshake from c and dispatches to
// the matching per-channel handler. Sub-handlers are responsible for
// closing c on exit.
func (d *Daemon) serveConn(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		d.logf("daemon: read handshake: %v", err)
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	switch proto.ChannelKind(b[0]) {
	case proto.ChannelControl:
		d.serveControl(c)
	case proto.ChannelLocalAPI:
		d.serveLocalAPI(c)
	case proto.ChannelDatapath:
		d.serveDatapath(c)
	case proto.ChannelAccept:
		d.serveAccept(c)
	default:
		d.logf("daemon: unknown channel kind %d", b[0])
		c.Close()
	}
}

// startBackendLocked brings up wgengine + LocalBackend + netstack +
// localapi handler on first use. It must be called with d.initMu held.
func (d *Daemon) startBackendLocked(p proto.StartParams) error {
	if d.started {
		return d.startErr
	}
	d.started = true
	hostinfo.SetPackage("tsnet2")

	sys := tsd.NewSystem()
	d.sys = sys

	tsLogf := d.logf
	netMon, err := netmon.New(sys.Bus.Get(), tsLogf)
	if err != nil {
		d.startErr = fmt.Errorf("netmon.New: %w", err)
		return d.startErr
	}
	d.netMon = netMon

	dialer := &tsdial.Dialer{Logf: tsLogf}
	dialer.SetBus(sys.Bus.Get())
	d.dialer = dialer

	eng, err := wgengine.NewUserspaceEngine(tsLogf, wgengine.Config{
		EventBus:      sys.Bus.Get(),
		NetMon:        netMon,
		Dialer:        dialer,
		SetSubsystem:  sys.Set,
		ControlKnobs:  sys.ControlKnobs(),
		HealthTracker: sys.HealthTracker.Get(),
		ExtraRootCAs:  sys.ExtraRootCAs,
		Metrics:       sys.UserMetricsRegistry(),
	})
	if err != nil {
		d.startErr = fmt.Errorf("wgengine.NewUserspaceEngine: %w", err)
		return d.startErr
	}
	sys.Set(eng)
	sys.HealthTracker.Get().SetMetricsRegistry(sys.UserMetricsRegistry())

	ns, err := netstack.Create(tsLogf, sys.Tun.Get(), eng, sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper())
	if err != nil {
		d.startErr = fmt.Errorf("netstack.Create: %w", err)
		return d.startErr
	}
	sys.Tun.Get().Start()
	sys.Set(ns)
	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true
	ns.GetTCPHandlerForFlow = d.getTCPHandlerForFlow
	ns.GetUDPHandlerForFlow = d.getUDPHandlerForFlow
	d.ns = ns

	dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := eng.PeerForIP(ip)
		return ok
	}
	dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		v4, v6 := d.tailscaleIPs()
		src := bools.IfElse(dst.Addr().Is6(), v6, v4)
		return ns.DialContextTCPWithBind(ctx, src, dst)
	}
	dialer.NetstackDialUDP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		v4, v6 := d.tailscaleIPs()
		src := bools.IfElse(dst.Addr().Is6(), v6, v4)
		return ns.DialContextUDPWithBind(ctx, src, dst)
	}

	stateFile := filepath.Join(d.cfg.StateDir, "tsnet2.state")
	st, err := store.New(tsLogf, stateFile)
	if err != nil {
		d.startErr = fmt.Errorf("store.New: %w", err)
		return d.startErr
	}
	sys.Set(st)

	loginFlags := controlclient.LoginDefault
	if p.Ephemeral {
		loginFlags = controlclient.LoginEphemeral
	}
	lb, err := ipnlocal.NewLocalBackend(tsLogf, d.logid, sys, loginFlags|controlclient.LocalBackendStartKeyOSNeutral)
	if err != nil {
		d.startErr = fmt.Errorf("NewLocalBackend: %w", err)
		return d.startErr
	}
	lb.SetVarRoot(d.cfg.StateDir)
	d.lb = lb
	if err := ns.Start(lb); err != nil {
		d.startErr = fmt.Errorf("netstack.Start: %w", err)
		return d.startErr
	}

	prefs := ipn.NewPrefs()
	prefs.Hostname = p.Hostname
	prefs.WantRunning = true
	if cu := cmpOr(p.ControlURL, os.Getenv("TS_CONTROL_URL")); cu != "" {
		prefs.ControlURL = cu
	}
	prefs.AdvertiseTags = p.AdvertiseTags
	authKey := cmpOr(p.AuthKey, os.Getenv("TS_AUTHKEY"), os.Getenv("TS_AUTH_KEY"))
	if err := lb.Start(ipn.Options{UpdatePrefs: prefs, AuthKey: authKey}); err != nil {
		d.startErr = fmt.Errorf("LocalBackend.Start: %w", err)
		return d.startErr
	}
	state := lb.State()
	if state == ipn.NeedsLogin {
		if err := lb.StartLoginInteractive(d.shutdownCtx); err != nil {
			d.startErr = fmt.Errorf("StartLoginInteractive: %w", err)
			return d.startErr
		}
	}

	lah := localapi.NewHandler(localapi.HandlerConfig{
		Actor:    ipnauth.Self,
		Backend:  lb,
		Logf:     tsLogf,
		LogID:    d.logid,
		EventBus: sys.Bus.Get(),
	})
	lah.PermitWrite = true
	lah.PermitRead = true
	d.localAPI = lah

	return nil
}

// cmpOr returns the first non-empty argument, or "".
func cmpOr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// tailscaleIPs returns the node's current IPv4 and IPv6 addresses (or
// the zero value of netip.Addr if not yet known).
func (d *Daemon) tailscaleIPs() (ip4, ip6 netip.Addr) {
	if d.lb == nil {
		return
	}
	nm := d.lb.NetMapNoPeers()
	if nm == nil {
		return
	}
	for _, addr := range nm.GetAddresses().All() {
		ip := addr.Addr()
		if ip.Is6() {
			ip6 = ip
		}
		if ip.Is4() {
			ip4 = ip
		}
	}
	return ip4, ip6
}

// getTCPHandlerForFlow is the GetTCPHandlerForFlow callback registered
// with netstack. It returns a handler that delivers the cleartext conn
// to the registered tsnet2 listener (if any).
func (d *Daemon) getTCPHandlerForFlow(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
	rl, ok := d.lookupListener("tcp", dst)
	if !ok {
		return nil, true // intercept = true (drop, don't forward to host)
	}
	return func(c net.Conn) {
		d.deliverInbound(rl, src, dst, c)
	}, true
}

// getUDPHandlerForFlow accepts no UDP listeners today. UDP packet flows
// are dropped.
func (d *Daemon) getUDPHandlerForFlow(src, dst netip.AddrPort) (handler func(nettype.ConnPacketConn), intercept bool) {
	return nil, true
}

// lookupListener finds a registered listener matching network and dst.
// In v1 we only match on (network, port); host-specific bindings can be
// added when a test exercises them.
func (d *Daemon) lookupListener(network string, dst netip.AddrPort) (*regListener, bool) {
	d.lmu.Lock()
	defer d.lmu.Unlock()
	if rl, ok := d.listenerByKey[listenerKey{network: network, port: dst.Port()}]; ok {
		return rl, true
	}
	return nil, false
}

// deliverInbound hands the netstack conn to a parked accept slot,
// emits the "open" traffic record (with WhoIs enrichment), and lets
// serveAccept perform the splice. If no slot is available within a
// short timeout the conn is dropped.
func (d *Daemon) deliverInbound(rl *regListener, src, dst netip.AddrPort, nsConn net.Conn) {
	slot := d.takeAcceptSlot(rl.id, 10*time.Second)
	if slot == nil {
		d.logf("daemon: no accept slot for listener %s; dropping conn from %v", rl.id, src)
		nsConn.Close()
		return
	}
	connID := newID()
	whois := d.whoIs(src)
	d.traffic.Open(connID, traffic.DirIn, "tcp", dst.String(), src.String(), rl.id, map[string]any{
		"whois": whois,
	})
	hdr := proto.AcceptHeader{
		ListenerID: rl.id,
		Local:      dst.String(),
		Remote:     src.String(),
	}
	slot.done <- acceptResult{c: nsConn, hdr: hdr, connID: connID}
}

// whoIs returns a small map representing the WhoIs result for ipp.
// Returns nil if no peer matches. Only node and user identifiers are
// included so the traffic log doesn't bloat.
func (d *Daemon) whoIs(ipp netip.AddrPort) map[string]any {
	if d.lb == nil {
		return nil
	}
	n, u, ok := d.lb.WhoIs("tcp", ipp)
	if !ok {
		return nil
	}
	m := map[string]any{}
	if n.Valid() {
		m["node"] = n.Name()
		if id := n.StableID(); id != "" {
			m["node_id"] = string(id)
		}
	}
	if u.LoginName != "" {
		m["user"] = u.LoginName
	}
	return m
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// pushAcceptSlot parks an accept-channel conn until the daemon has an
// inbound flow to hand it.
func (d *Daemon) pushAcceptSlot(listenerID string, c net.Conn) *acceptSlot {
	s := &acceptSlot{conn: c, done: make(chan acceptResult, 1)}
	d.amu.Lock()
	d.acceptWait[listenerID] = append(d.acceptWait[listenerID], s)
	d.acceptCond.Broadcast()
	d.amu.Unlock()
	return s
}

// takeAcceptSlot returns the next parked accept slot for listenerID,
// or nil after timeout / daemon shutdown.
func (d *Daemon) takeAcceptSlot(listenerID string, timeout time.Duration) *acceptSlot {
	deadline := time.Now().Add(timeout)
	d.amu.Lock()
	defer d.amu.Unlock()
	for {
		if d.shutdownCtx.Err() != nil {
			return nil
		}
		if q := d.acceptWait[listenerID]; len(q) > 0 {
			s := q[0]
			d.acceptWait[listenerID] = q[1:]
			return s
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil
		}
		// sync.Cond has no timeout; we use a one-shot timer that
		// wakes the cond when expired.
		woken := make(chan struct{})
		go func() {
			select {
			case <-time.After(remaining):
				d.amu.Lock()
				d.acceptCond.Broadcast()
				d.amu.Unlock()
			case <-woken:
			}
		}()
		d.acceptCond.Wait()
		close(woken)
	}
}

// removeAcceptSlot removes a parked slot (e.g. when the app socket
// has gone away before the daemon delivered a flow).
func (d *Daemon) removeAcceptSlot(listenerID string, target *acceptSlot) {
	d.amu.Lock()
	defer d.amu.Unlock()
	q := d.acceptWait[listenerID]
	for i, s := range q {
		if s == target {
			d.acceptWait[listenerID] = slices.Delete(q, i, i+1)
			return
		}
	}
}

// listenAddrFor parses an app-supplied bind string ("[host]:port") and
// returns a (network, port) key plus the canonicalised address. Port 0
// is allocated from a small ephemeral pool to keep tsnet2 self-contained.
func listenAddrFor(network, addr string) (listenerKey, string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return listenerKey{}, "", fmt.Errorf("bad addr %q: %w", addr, err)
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		if _, perr := netip.ParseAddr(host); perr != nil {
			return listenerKey{}, "", fmt.Errorf("bad addr %q: %w", addr, perr)
		}
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return listenerKey{}, "", fmt.Errorf("bad port %q: %w", portStr, err)
	}
	if port == 0 {
		port = pickEphemeralPort()
		addr = ":" + strconv.FormatUint(port, 10)
	}
	return listenerKey{network: network, port: uint16(port)}, addr, nil
}

var ephemPortCounter atomic.Uint32

func pickEphemeralPort() uint64 {
	const first = 10002
	const last = 19999
	v := uint64(ephemPortCounter.Add(1))
	return uint64(first) + (v % uint64(last-first+1))
}
