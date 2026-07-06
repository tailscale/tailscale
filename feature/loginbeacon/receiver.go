// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"tailscale.com/types/logger"
)

// Beacon is the projected view of a MsgBeacon handed to client code. The
// wire types stay unexported; approvers only see stable, opaque IDs and
// display fields.
type Beacon struct {
	RequestID    [16]byte
	Hostname     string
	DeviceKind   string
	DeviceIDHash [16]byte
}

// ReceiverConfig parameterizes StartReceiver.
type ReceiverConfig struct {
	// OnBeacon fires the first time a new (non-ignored) beacon is seen. It
	// runs on the receiver's goroutine; the client should hand off to its
	// own UI thread before touching UI state.
	OnBeacon func(Beacon)
	// OnAuthURL fires after Approve completes: a URL has been received and
	// decrypted successfully, and the URLAllowed check passed. The client
	// should open it in whatever browser flow it normally uses for
	// browseToURL.
	OnAuthURL func(url string)
	// URLAllowed gates whether a decrypted URL is safe to hand to
	// OnAuthURL. It runs on the receiver's goroutine; return false to
	// drop the URL silently. Required.
	URLAllowed func(url string) bool
	Logf       logger.Logf
}

// Receiver joins the beacon multicast group, dispatches beacons to
// OnBeacon, and performs the ephemeral X25519 handshake in response to
// Approve. Everything is in-memory; Stop drops all state.
type Receiver struct {
	cfg  ReceiverConfig
	conn *net.UDPConn
	pc   *ipv4.PacketConn

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	pending  map[requestID]*pendingBeacon
	ignored  map[requestID]bool
	approved map[requestID]bool
}

type pendingBeacon struct {
	beacon    beaconMsg
	src       *net.UDPAddr
	firstSeen time.Time
}

func StartReceiver(ctx context.Context, cfg ReceiverConfig) (*Receiver, error) {
	if cfg.OnBeacon == nil || cfg.OnAuthURL == nil || cfg.URLAllowed == nil {
		return nil, errors.New("loginbeacon: all ReceiverConfig callbacks are required")
	}
	if cfg.Logf == nil {
		return nil, errors.New("loginbeacon: Config.Logf is required")
	}

	// Bind to the well-known port on all interfaces so multiple senders
	// on the LAN can share one receiver socket.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: MulticastPort})
	if err != nil {
		return nil, fmt.Errorf("loginbeacon: ListenUDP: %w", err)
	}
	pc := ipv4.NewPacketConn(conn)
	// Join the multicast group on every up/mcast-capable interface. Failing
	// to join on some interfaces is not fatal (loopback, VPNs, etc).
	ifs, _ := net.Interfaces()
	var joined []string
	for _, iface := range ifs {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		if err := pc.JoinGroup(&iface, &net.UDPAddr{IP: MulticastGroup}); err == nil {
			joined = append(joined, iface.Name)
		} else {
			cfg.Logf("loginbeacon: JoinGroup on %s: %v", iface.Name, err)
		}
	}
	if len(joined) == 0 {
		conn.Close()
		return nil, errors.New("loginbeacon: could not join multicast group on any interface")
	}

	sctx, cancel := context.WithCancel(ctx)
	r := &Receiver{
		cfg:      cfg,
		conn:     conn,
		pc:       pc,
		ctx:      sctx,
		cancel:   cancel,
		pending:  make(map[requestID]*pendingBeacon),
		ignored:  make(map[requestID]bool),
		approved: make(map[requestID]bool),
	}
	r.wg.Add(1)
	go r.recvLoop()
	cfg.Logf("loginbeacon: receiver joined multicast on %v (port %d)", joined, MulticastPort)
	return r, nil
}

// Stop tears down the socket and clears session state. Ignored / approved
// sets are dropped along with everything else; the caller is expected to
// hold those higher up if a longer lifetime is needed.
func (r *Receiver) Stop() {
	r.cancel()
	r.conn.Close()
	r.wg.Wait()
}

// Ignore marks rid so subsequent beacons with the same ID are dropped and
// OnBeacon is not called again.
func (r *Receiver) Ignore(rid [16]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ignored[requestID(rid)] = true
	delete(r.pending, requestID(rid))
}

// Approve completes the handshake for rid: generates an ephemeral X25519
// keypair, unicasts a MsgApproval to the beacon's source, awaits the sealed
// URL, and — if URLAllowed accepts it — invokes OnAuthURL. Any error
// (timeout, decrypt failure, URL rejected) is returned to the caller.
func (r *Receiver) Approve(rid [16]byte) error {
	r.mu.Lock()
	pb, ok := r.pending[requestID(rid)]
	if !ok {
		r.mu.Unlock()
		return errors.New("loginbeacon: no such pending beacon")
	}
	if r.approved[requestID(rid)] {
		r.mu.Unlock()
		return nil
	}
	r.approved[requestID(rid)] = true
	r.mu.Unlock()

	k, err := newEphemeralKey()
	if err != nil {
		r.rollback(rid)
		return err
	}
	defer k.zero()

	approverName, _ := os.Hostname()
	approval := marshalApproval(&approvalMsg{
		RequestID:      requestID(rid),
		ApproverEphPub: k.pub,
		UnixSec:        time.Now().Unix(),
		ApproverName:   approverName,
	})

	// Unicast to the beacon source. We use a fresh short-lived socket so
	// the sender's reply comes back to us and not to the multicast listener.
	uconn, err := net.DialUDP("udp4", nil, pb.src)
	if err != nil {
		r.rollback(rid)
		return err
	}
	defer uconn.Close()

	if _, err := uconn.Write(approval); err != nil {
		r.rollback(rid)
		return err
	}
	if err := uconn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		r.rollback(rid)
		return err
	}
	buf := make([]byte, maxWireSize)
	n, err := uconn.Read(buf)
	if err != nil {
		r.rollback(rid)
		return fmt.Errorf("loginbeacon: awaiting sealed url: %w", err)
	}
	sealed, err := parseSealedURL(buf[:n])
	if err != nil {
		r.rollback(rid)
		return err
	}
	if sealed.RequestID != requestID(rid) {
		r.rollback(rid)
		return errors.New("loginbeacon: sealed URL request id mismatch")
	}
	url, err := openURL(k.priv, pb.beacon.SenderEphPub, sealed)
	if err != nil {
		r.rollback(rid)
		return fmt.Errorf("loginbeacon: opening sealed url: %w", err)
	}
	if !r.cfg.URLAllowed(url) {
		r.rollback(rid)
		return fmt.Errorf("loginbeacon: url not in allowlist")
	}
	r.cfg.OnAuthURL(url)
	r.mu.Lock()
	delete(r.pending, requestID(rid))
	r.mu.Unlock()
	return nil
}

// rollback clears the "approved" mark so the user can retry after a
// transport or crypto failure.
func (r *Receiver) rollback(rid [16]byte) {
	r.mu.Lock()
	delete(r.approved, requestID(rid))
	r.mu.Unlock()
}

func (r *Receiver) recvLoop() {
	defer r.wg.Done()
	buf := make([]byte, maxWireSize)
	for {
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if r.ctx.Err() != nil {
				return
			}
			r.cfg.Logf("loginbeacon: read: %v", err)
			continue
		}
		r.handleBeacon(buf[:n], src)
	}
}

func (r *Receiver) handleBeacon(pkt []byte, src *net.UDPAddr) {
	t, _, err := parseHeader(pkt)
	if err != nil || t != msgTypeBeacon {
		return
	}
	m, err := parseBeacon(pkt)
	if err != nil {
		return
	}
	if delta := time.Now().Unix() - m.UnixSec; delta > 60 || delta < -60 {
		r.cfg.Logf("loginbeacon: dropping stale beacon from %s (delta=%ds)", src, delta)
		return
	}

	r.mu.Lock()
	if r.ignored[m.RequestID] || r.approved[m.RequestID] {
		r.mu.Unlock()
		return
	}
	firstSighting := r.pending[m.RequestID] == nil
	if firstSighting {
		r.pending[m.RequestID] = &pendingBeacon{beacon: *m, src: src, firstSeen: time.Now()}
	} else {
		// Refresh cached src/payload so late unicast approvals still land on
		// the current source, and so `lastSeen` on the client side gets
		// updated by the outgoing OnBeacon fire.
		r.pending[m.RequestID].src = src
		r.pending[m.RequestID].beacon = *m
	}
	r.mu.Unlock()

	if firstSighting {
		r.cfg.Logf("loginbeacon: new beacon from %s rid=%x hostname=%q kind=%q", src, m.RequestID[:4], m.Hostname, m.DeviceKind)
	}
	r.cfg.OnBeacon(Beacon{
		RequestID:    [16]byte(m.RequestID),
		Hostname:     m.Hostname,
		DeviceKind:   m.DeviceKind,
		DeviceIDHash: m.DeviceIDHash,
	})
}

// DefaultURLAllowed accepts only https://*.tailscale.com URLs. Clients on a
// self-hosted control server should supply their own URLAllowed.
func DefaultURLAllowed(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	if u.Host == "login.tailscale.com" {
		return true
	}
	return len(u.Host) > len(".tailscale.com") &&
		u.Host[len(u.Host)-len(".tailscale.com"):] == ".tailscale.com"
}
