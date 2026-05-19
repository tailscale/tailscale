// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package daemon implements the body of the tsnet2d daemon: it owns a
// tailscale.com/tsnet.Server (which brings up wgengine + magicsock +
// netstack + LocalBackend + localapi), serves the Unix socket protocol
// described in tsnet2/proto, and tees cleartext bytes between the
// tsnet listeners/dials and the application process into the traffic
// logger.
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
	"sync"
	"time"

	"tailscale.com/tsnet"
	"tailscale.com/tsnet2/proto"
	"tailscale.com/tsnet2/traffic"
	"tailscale.com/types/logger"
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

	// The hosted tsnet.Server. nil until the Start RPC has been
	// dispatched; subsequent reads must hold initMu.
	initMu   sync.Mutex
	ts       *tsnet.Server
	started  bool
	startErr error

	// Listener tracking. The accept-loop goroutine for each entry is
	// started in MethodRegisterListener and exits when the listener
	// (and therefore tsnet's underlying gVisor listener) is closed.
	lmu       sync.Mutex
	listeners map[string]*regListener

	// Pending accept slots indexed by listener_id (FIFO of parked
	// accept-channel sockets). serveAccept parks a slot here; the
	// per-listener acceptLoop pulls one when it Accepts an inbound conn.
	amu        sync.Mutex
	acceptWait map[string][]*acceptSlot
	acceptCond *sync.Cond

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	closeOnce sync.Once
	closeErr  error
}

// regListener tracks one tsnet listener registered by the app.
type regListener struct {
	id   string
	ln   net.Listener // the listener returned by tsnet.Server.Listen
	addr string       // canonicalised bind address as reported by ln.Addr
}

// acceptSlot is a parked accept-channel conn waiting for the daemon
// to hand it an inbound flow.
type acceptSlot struct {
	conn net.Conn
	done chan acceptResult
}

type acceptResult struct {
	c      net.Conn // the tsnet TCP conn to splice with the app conn
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
		cfg:        cfg,
		logf:       logf,
		traffic:    tlog,
		listeners:  map[string]*regListener{},
		acceptWait: map[string][]*acceptSlot{},
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
		// Close every registered tsnet listener so the per-listener
		// acceptLoop goroutines exit.
		d.lmu.Lock()
		for _, rl := range d.listeners {
			rl.ln.Close()
		}
		d.listeners = nil
		d.lmu.Unlock()
		// Tear down tsnet.
		d.initMu.Lock()
		if d.ts != nil {
			d.closeErr = d.ts.Close()
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

// startBackendLocked constructs a tsnet.Server from p and calls
// Start on it. Must be called with d.initMu held.
//
// All of the heavy wiring (wgengine + magicsock + netstack +
// LocalBackend + localapi handler + store + dialer + netmon) is
// delegated to tsnet.Server itself rather than reimplemented here.
func (d *Daemon) startBackendLocked(p proto.StartParams) error {
	if d.started {
		return d.startErr
	}
	d.started = true

	ts := &tsnet.Server{
		Dir:           d.cfg.StateDir,
		Hostname:      p.Hostname,
		ControlURL:    p.ControlURL,
		AuthKey:       p.AuthKey,
		Ephemeral:     p.Ephemeral,
		AdvertiseTags: p.AdvertiseTags,
		Logf:          d.logf,
		// UserLogf intentionally left nil for now; user-visible logs
		// (auth URLs, etc.) end up in tsnet's default log.Printf. A
		// future enhancement is to forward UserLogf over the control
		// channel to the app's UserLogf.
	}
	if err := ts.Start(); err != nil {
		d.startErr = fmt.Errorf("tsnet.Start: %w", err)
		return d.startErr
	}
	d.ts = ts
	return nil
}

// tsServer returns the hosted tsnet.Server, or an error if Start has
// not been dispatched yet.
func (d *Daemon) tsServer() (*tsnet.Server, error) {
	d.initMu.Lock()
	defer d.initMu.Unlock()
	if !d.started {
		return nil, errors.New("daemon: backend not started; call Start first")
	}
	if d.startErr != nil {
		return nil, d.startErr
	}
	return d.ts, nil
}

// whoIs returns a small map representing the WhoIs result for the
// peer at ipp via the daemon's hosted tsnet.LocalClient. Returns nil
// if no peer matches or the lookup fails. Only node and user
// identifiers are included so the traffic log doesn't bloat.
func (d *Daemon) whoIs(ctx context.Context, ipp netip.AddrPort) map[string]any {
	ts, err := d.tsServer()
	if err != nil {
		return nil
	}
	lc, err := ts.LocalClient()
	if err != nil {
		return nil
	}
	resp, err := lc.WhoIs(ctx, ipp.String())
	if err != nil || resp == nil {
		return nil
	}
	m := map[string]any{}
	if resp.Node != nil {
		if resp.Node.Name != "" {
			m["node"] = resp.Node.Name
		}
		if id := resp.Node.StableID; id != "" {
			m["node_id"] = string(id)
		}
	}
	if resp.UserProfile != nil && resp.UserProfile.LoginName != "" {
		m["user"] = resp.UserProfile.LoginName
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// acceptLoop pulls inbound connections from rl.ln (a tsnet listener)
// and hands each to a parked accept slot via deliverInbound. It exits
// when ln.Accept returns net.ErrClosed (i.e. the listener was
// unregistered or the daemon is shutting down).
func (d *Daemon) acceptLoop(rl *regListener) {
	for {
		c, err := rl.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if d.shutdownCtx.Err() != nil {
				return
			}
			d.logf("daemon: accept for listener %s: %v", rl.id, err)
			return
		}
		go d.deliverInbound(rl, c)
	}
}

// deliverInbound hands the tsnet conn to a parked accept slot, emits
// the "open" traffic record (with WhoIs enrichment), and lets
// serveAccept perform the splice. If no slot is available within a
// short timeout the conn is dropped.
func (d *Daemon) deliverInbound(rl *regListener, tsConn net.Conn) {
	slot := d.takeAcceptSlot(rl.id, 10*time.Second)
	if slot == nil {
		d.logf("daemon: no accept slot for listener %s; dropping conn", rl.id)
		tsConn.Close()
		return
	}
	localStr := tsConn.LocalAddr().String()
	remoteStr := tsConn.RemoteAddr().String()
	var srcWhois map[string]any
	if ap, ok := parseAddrPort(remoteStr); ok {
		srcWhois = d.whoIs(d.shutdownCtx, ap)
	}
	connID := newID()
	d.traffic.Open(connID, traffic.DirIn, "tcp", localStr, remoteStr, rl.id, map[string]any{
		"whois": srcWhois,
	})
	hdr := proto.AcceptHeader{
		ListenerID: rl.id,
		Local:      localStr,
		Remote:     remoteStr,
	}
	slot.done <- acceptResult{c: tsConn, hdr: hdr, connID: connID}
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

// parseAddrPort is a tolerant netip.ParseAddrPort wrapper that returns
// (zero, false) on error instead of panicking.
func parseAddrPort(s string) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return ap, true
}
