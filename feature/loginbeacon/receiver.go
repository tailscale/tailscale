// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"tailscale.com/feature/loginbeacon/api"
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
	RequesterID  string // source-scoped sender identity for client-side replacement
}

// ReceiverConfig parameterizes StartReceiver.
type ReceiverConfig struct {
	// OnBeacon fires for new and repeated, non-deleted beacons. Both callbacks
	// run with the request lock held, preserving discovery/removal ordering.
	// They must not block or reenter Receiver; UI clients must dispatch events.
	OnBeacon func(Beacon)
	// OnRemoved reports withdrawn, expired, deleted, or superseded requests.
	// It runs with the request lock held and must not block or reenter Receiver.
	OnRemoved func([16]byte)
	// IgnoreDeviceIDHash suppresses this daemon's own sender instance.
	IgnoreDeviceIDHash [16]byte
	// URLAllowed validates the decrypted URL before Approve returns it. Required.
	URLAllowed func(url string) bool
	Logf       logger.Logf
}

// Receiver joins the beacon multicast group, dispatches beacons to
// OnBeacon, and performs the ephemeral X25519 handshake in response to
// Approve. Everything is in-memory; Stop drops all state.
type Receiver struct {
	cfg  ReceiverConfig
	conn *net.UDPConn
	pc   multicastGroupConn

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Memberships are owned by the extension receiver loop; discovery and
	// approval state below survives interface changes.
	joined []net.Interface

	mu       sync.Mutex
	disabled bool // user/policy revocation; distinct from foreground socket pause
	pending  map[requestID]*pendingBeacon
	deleted  map[requestID]time.Time // expiry of a suppressed request ID
}

// multicastGroupConn is the membership control surface of ipv4.PacketConn.
type multicastGroupConn interface {
	JoinGroup(*net.Interface, net.Addr) error
	LeaveGroup(*net.Interface, net.Addr) error
}

type pendingBeacon struct {
	beacon    beaconMsg
	src       *net.UDPAddr
	firstSeen time.Time
	lastSeen  time.Time
	key       *ephemeralKey      // retained across transport retries, then zeroed
	authURL   string             // retained until browser handoff succeeds or the request is deleted
	cancel    context.CancelFunc // non-nil while an approval is running
}

const approvalTimeout = 10 * time.Second
const approvalRetryInterval = time.Second

var errNoPendingBeacon = errors.New("loginbeacon: no such pending beacon")
var errApprovalInProgress = errors.New("loginbeacon: approval already in progress")

func StartReceiver(ctx context.Context, cfg ReceiverConfig) (*Receiver, error) {
	if cfg.OnBeacon == nil || cfg.URLAllowed == nil {
		return nil, errors.New("loginbeacon: all ReceiverConfig callbacks are required")
	}
	if cfg.Logf == nil {
		return nil, errors.New("loginbeacon: Config.Logf is required")
	}

	sctx, cancel := context.WithCancel(ctx)
	r := &Receiver{
		cfg: cfg, ctx: sctx, cancel: cancel,
		pending: make(map[requestID]*pendingBeacon),
		deleted: make(map[requestID]time.Time),
	}
	if err := r.listen(); err != nil {
		cancel()
		return nil, err
	}
	return r, nil
}

// listen resumes discovery without resetting pending requests or approvals.
// The extension receiver loop owns listen/pause and all socket fields.
func (r *Receiver) listen() error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: MulticastPort})
	if err != nil {
		return fmt.Errorf("loginbeacon: ListenUDP: %w", err)
	}
	ifs, err := net.Interfaces()
	if err != nil {
		conn.Close()
		return err
	}
	r.conn, r.pc = conn, ipv4.NewPacketConn(conn)
	if err := r.rejoinMulticast(ifs); err != nil {
		conn.Close()
		r.conn, r.pc = nil, nil
		return err
	}
	r.wg.Add(1)
	go r.recvLoop(conn)
	return nil
}

// pause closes the multicast socket but preserves request/approval state. In
// particular it must not cancel a confirmation when iOS opens the browser.
func (r *Receiver) pause() {
	if r.conn == nil {
		return
	}
	r.conn.Close()
	r.wg.Wait()
	r.conn, r.pc, r.joined = nil, nil, nil
	r.cfg.Logf("receiver paused")
}

// rejoinMulticast refreshes OS memberships after a network change (including
// Wi-Fi returning on the same interface). It keeps this socket and all pending
// requests, deletion tombstones and in-flight approvals intact. The extension
// serializes calls and waits for them before Stop.
func (r *Receiver) rejoinMulticast(ifs []net.Interface) error {
	group := &net.UDPAddr{IP: MulticastGroup}
	for _, iface := range r.joined {
		// The OS may already have removed membership when the interface went
		// away, so a failed LeaveGroup is harmless.
		_ = r.pc.LeaveGroup(&iface, group)
	}
	r.joined = nil
	var names []string
	for _, iface := range ifs {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 || !hasIPv4Address(iface) {
			continue
		}
		if err := r.pc.JoinGroup(&iface, group); err != nil {
			r.cfg.Logf("JoinGroup on %s: %v", iface.Name, err)
			continue
		}
		r.joined = append(r.joined, iface)
		names = append(names, iface.Name)
	}
	if len(r.joined) == 0 {
		return errors.New("loginbeacon: could not join multicast group on any interface")
	}
	r.cfg.Logf("receiver joined multicast on %v (port %d)", names, MulticastPort)
	return nil
}

// Stop cancels discovery and any outstanding URL retrievals and clears secrets.
func (r *Receiver) Stop() {
	r.cancel()
	r.pause()
	r.clearRequests()
}

func (pb *pendingBeacon) clear() {
	if pb.cancel != nil {
		pb.cancel()
	}
	if pb.key != nil {
		pb.key.zero()
		pb.key = nil
	}
	pb.authURL = ""
}

func (pb *pendingBeacon) expires() time.Time {
	expires := pb.lastSeen.Add(api.RequestLease)
	if limit := pb.firstSeen.Add(api.RequestRetention); limit.Before(expires) {
		return limit
	}
	return expires
}

func (r *Receiver) removeLocked(id requestID) {
	if pb := r.pending[id]; pb != nil {
		pb.clear()
		delete(r.pending, id)
		if r.cfg.OnRemoved != nil {
			r.cfg.OnRemoved([16]byte(id))
		}
	}
}

// Delete removes and suppresses a request until its original expiry. UI Ignore
// means "later" and must not call this method.
func (r *Receiver) Delete(rid [16]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.pruneExpiredLocked(now)
	id := requestID(rid)
	if pb := r.pending[id]; pb != nil {
		r.deleted[id] = pb.firstSeen.Add(api.RequestRetention)
		r.removeLocked(id)
	} else if _, exists := r.deleted[id]; !exists && len(r.pending)+len(r.deleted) < api.MaxTrackedRequests {
		r.deleted[id] = now.Add(api.RequestRetention)
	}
}

func (r *Receiver) pruneExpiredLocked(now time.Time) {
	for id, pb := range r.pending {
		if !now.Before(pb.expires()) {
			r.removeLocked(id)
		}
	}
	for id, expiry := range r.deleted {
		if !now.Before(expiry) {
			delete(r.deleted, id)
		}
	}
}

// Approve retrieves a validated URL for this request. It does not open a browser
// or remove the request: the caller deletes it after browser handoff succeeds.
// A successful retrieval is cached in memory to allow browser-handoff retries.
func (r *Receiver) Approve(ctx context.Context, rid [16]byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, approvalTimeout)
	defer cancel()
	stopShutdown := context.AfterFunc(r.ctx, cancel)
	defer stopShutdown()
	if err := ctx.Err(); err != nil {
		return "", err
	}

	r.mu.Lock()
	if ctx.Err() != nil || r.ctx.Err() != nil || r.disabled {
		r.mu.Unlock()
		return "", context.Canceled
	}
	r.pruneExpiredLocked(time.Now())
	pb := r.pending[requestID(rid)]
	if pb == nil {
		r.mu.Unlock()
		return "", errNoPendingBeacon
	}
	if pb.cancel != nil {
		r.mu.Unlock()
		return "", errApprovalInProgress
	}
	if pb.authURL != "" {
		url := pb.authURL
		r.mu.Unlock()
		return url, nil
	}
	if pb.key == nil {
		key, err := newEphemeralKey()
		if err != nil {
			r.mu.Unlock()
			return "", err
		}
		pb.key = &key
	}
	pb.cancel = cancel
	key, beacon, src := *pb.key, pb.beacon, *pb.src
	r.mu.Unlock()
	defer key.zero()
	defer func() {
		r.mu.Lock()
		pb.cancel = nil
		r.mu.Unlock()
	}()

	approverName, _ := os.Hostname()
	approval := marshalApproval(&approvalMsg{
		RequestID: requestID(rid), ApproverEphPub: key.pub,
		UnixSec: time.Now().Unix(), ApproverName: approverName,
	})
	uconn, err := net.DialUDP("udp4", nil, &src)
	if err != nil {
		return "", err
	}
	defer uconn.Close()
	stopClose := context.AfterFunc(ctx, func() { uconn.Close() })
	defer stopClose()
	buf := make([]byte, maxWireSize+1)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if _, err := uconn.Write(approval); err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", err
		}
		if err := uconn.SetReadDeadline(time.Now().Add(approvalRetryInterval)); err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", err
		}
		n, err := uconn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return "", err
		}
		if n > maxWireSize {
			return "", errBadLength
		}
		sealed, err := parseSealedURL(buf[:n])
		if err != nil {
			return "", err
		}
		if sealed.RequestID != requestID(rid) {
			return "", errors.New("loginbeacon: sealed URL request id mismatch")
		}
		url, err := openURL(key.priv, beacon.SenderEphPub, sealed)
		if err != nil {
			return "", fmt.Errorf("loginbeacon: opening sealed url: %w", err)
		}
		if !r.cfg.URLAllowed(url) {
			return "", errors.New("loginbeacon: url not in allowlist")
		}
		r.mu.Lock()
		// Deletion, expiry, request cancellation, and shutdown can win while
		// the network read completes. Do not deliver a stale result.
		valid := !r.disabled && ctx.Err() == nil && r.ctx.Err() == nil && r.pending[requestID(rid)] == pb && time.Now().Before(pb.expires())
		if valid {
			pb.authURL = url
			pb.key.zero()
			pb.key = nil
		}
		r.mu.Unlock()
		if !valid {
			return "", context.Canceled
		}
		return url, nil
	}
}

func (r *Receiver) recvLoop(conn *net.UDPConn) {
	defer r.wg.Done()
	buf := make([]byte, maxWireSize+1)
	for {
		r.mu.Lock()
		r.pruneExpiredLocked(time.Now())
		r.mu.Unlock()
		if err := conn.SetReadDeadline(time.Now().Add(beaconInterval)); err != nil {
			return
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if r.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			r.cfg.Logf("read: %v", err)
			continue
		}
		if n > maxWireSize {
			continue
		}
		r.handleBeacon(buf[:n], src)
	}
}

func (r *Receiver) handleBeacon(pkt []byte, src *net.UDPAddr) {
	t, _, err := parseHeader(pkt)
	if err != nil {
		return
	}
	if t == msgTypeCancel {
		r.handleCancel(pkt, src)
		return
	}
	if t != msgTypeBeacon {
		return
	}
	m, err := parseBeacon(pkt)
	if err != nil {
		return
	}
	if r.cfg.IgnoreDeviceIDHash != ([16]byte{}) && m.DeviceIDHash == r.cfg.IgnoreDeviceIDHash {
		return
	}
	if delta := time.Now().Unix() - m.UnixSec; delta > 60 || delta < -60 {
		r.cfg.Logf("dropping stale beacon from %s (delta=%ds)", src, delta)
		return
	}

	r.mu.Lock()
	if r.disabled {
		r.mu.Unlock()
		return
	}
	r.pruneExpiredLocked(time.Now())
	if _, deleted := r.deleted[m.RequestID]; deleted {
		r.mu.Unlock()
		return
	}
	pb := r.pending[m.RequestID]
	firstSighting := pb == nil
	if firstSighting {
		if len(r.pending)+len(r.deleted) >= api.MaxTrackedRequests {
			r.mu.Unlock()
			return
		}
		// A sender may retry with a new request ID, key and UDP port. Retire
		// older requests only when both its instance ID and LAN address match.
		// These are discovery hints, not authenticated peer identity.
		if m.DeviceIDHash != ([16]byte{}) {
			for oldID, old := range r.pending {
				if old.beacon.DeviceIDHash == m.DeviceIDHash && old.src != nil && old.src.IP.Equal(src.IP) {
					r.deleted[oldID] = old.firstSeen.Add(api.RequestRetention)
					r.removeLocked(oldID)
				}
			}
		}
		r.pending[m.RequestID] = &pendingBeacon{beacon: *m, src: src, firstSeen: time.Now()}
	} else if pb.beacon.SenderEphPub != m.SenderEphPub || !pb.src.IP.Equal(src.IP) || pb.src.Port != src.Port {
		// The request ID is bound to its first key/source for its lifetime.
		// Pinning prevents replacement; initial discovery is not authenticated.
		r.mu.Unlock()
		return
	}
	// Repeated announcements refresh visibility, not the pinned display identity.
	r.pending[m.RequestID].lastSeen = time.Now()
	cached := r.pending[m.RequestID].beacon
	r.cfg.OnBeacon(projectBeacon(cached, src))
	r.mu.Unlock()

	if firstSighting {
		r.cfg.Logf("new beacon from %s rid=%x hostname=%q kind=%q", src, m.RequestID[:4], m.Hostname, m.DeviceKind)
	}
}

func (r *Receiver) handleCancel(pkt []byte, src *net.UDPAddr) {
	id, err := parseCancel(pkt)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pb := r.pending[id]
	if pb == nil || !pb.src.IP.Equal(src.IP) || pb.src.Port != src.Port {
		return
	}
	// Retain a tombstone so delayed announcements cannot resurrect the request.
	r.deleted[id] = pb.firstSeen.Add(api.RequestRetention)
	r.removeLocked(id)
}

// clearRequests cancels retrievals immediately without touching socket ownership.
func (r *Receiver) clearRequests() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.disabled = true
	for id := range r.pending {
		r.removeLocked(id)
	}
	clear(r.pending)
	clear(r.deleted)
}

func (r *Receiver) enableRequests() {
	r.mu.Lock()
	r.disabled = false
	r.mu.Unlock()
}

func (r *Receiver) requests() []api.Pending {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneExpiredLocked(time.Now())
	requests := make([]api.Pending, 0, len(r.pending))
	if r.disabled {
		return requests
	}
	for _, pb := range r.pending {
		requests = append(requests, api.Pending{
			Request: projectBeacon(pb.beacon, pb.src).apiRequest(),
			Expires: pb.expires(),
		})
	}
	slices.SortFunc(requests, func(a, b api.Pending) int {
		return strings.Compare(a.RequestID, b.RequestID)
	})
	return requests
}

func projectBeacon(m beaconMsg, src *net.UDPAddr) Beacon {
	b := Beacon{RequestID: [16]byte(m.RequestID), Hostname: m.Hostname, DeviceKind: m.DeviceKind, DeviceIDHash: m.DeviceIDHash}
	if m.DeviceIDHash != ([16]byte{}) {
		// Scope the instance to its pinned source so copying a device ID from
		// another host cannot supersede that host's request in a client.
		id := hashDeviceID(src.IP.String() + "\x00" + string(m.DeviceIDHash[:]))
		b.RequesterID = hex.EncodeToString(id[:])
	}
	return b
}

func (b Beacon) apiRequest() api.Request {
	return api.Request{
		RequestID: hex.EncodeToString(b.RequestID[:]), Hostname: b.Hostname,
		DeviceKind: b.DeviceKind, DeviceIDHash: hex.EncodeToString(b.DeviceIDHash[:]),
		RequesterID: b.RequesterID,
	}
}
