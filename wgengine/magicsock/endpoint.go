// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/poly1305"
	"golang.org/x/exp/maps"
	"tailscale.com/disco"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/stun"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
	"tailscale.com/util/ringbuffer"
)

// endpoint is a wireguard/conn.Endpoint. In wireguard-go and kernel WireGuard
// there is only one endpoint for a peer, but in Tailscale we distribute a
// number of possible endpoints for a peer which would include the all the
// likely addresses at which a peer may be reachable. This endpoint type holds
// the information required that when WiregGuard-Go wants to send to a
// particular peer (essentally represented by this endpoint type), the send
// function can use the currnetly best known Tailscale endpoint to send packets
// to the peer.
type endpoint struct {
	// atomically accessed; declared first for alignment reasons
	lastRecv              mono.Time
	numStopAndResetAtomic int64
	debugUpdates          *ringbuffer.RingBuffer[EndpointChange]

	// These fields are initialized once and never modified.
	c            *Conn
	publicKey    key.NodePublic // peer public key (for WireGuard + DERP)
	publicKeyHex string         // cached output of publicKey.UntypedHexString
	fakeWGAddr   netip.AddrPort // the UDP address we tell wireguard-go we're using
	nodeAddr     netip.Addr     // the node's first tailscale address; used for logging & wireguard rate-limiting (Issue 6686)

	disco atomic.Pointer[endpointDisco] // if the peer supports disco, the key and short string

	// mu protects all following fields.
	mu sync.Mutex // Lock ordering: Conn.mu, then endpoint.mu

	heartBeatTimer *time.Timer    // nil when idle
	lastSend       mono.Time      // last time there was outgoing packets sent to this peer (from wireguard-go)
	lastFullPing   mono.Time      // last time we pinged all disco or wireguard only endpoints
	derpAddr       netip.AddrPort // fallback/bootstrap path, if non-zero (non-zero for well-behaved clients)

	bestAddr           addrLatency // best non-DERP path; zero if none
	bestAddrAt         mono.Time   // time best address re-confirmed
	trustBestAddrUntil mono.Time   // time when bestAddr expires
	sentPing           map[stun.TxID]sentPing
	endpointState      map[netip.AddrPort]*endpointState
	isCallMeMaybeEP    map[netip.AddrPort]bool

	pendingCLIPings []pendingCLIPing // any outstanding "tailscale ping" commands running

	// The following fields are related to the new "silent disco"
	// implementation that's a WIP as of 2022-10-20.
	// See #540 for background.
	heartbeatDisabled bool

	expired         bool // whether the node has expired
	isWireguardOnly bool // whether the endpoint is WireGuard only
}

type pendingCLIPing struct {
	res *ipnstate.PingResult
	cb  func(*ipnstate.PingResult)
}

// endpointDisco is the current disco key and short string for an endpoint. This
// structure is immutable.
type endpointDisco struct {
	key   key.DiscoPublic // for discovery messages.
	short string          // ShortString of discoKey.
}

type sentPing struct {
	to      netip.AddrPort
	at      mono.Time
	timer   *time.Timer // timeout timer
	purpose discoPingPurpose
}

// endpointState is some state and history for a specific endpoint of
// a endpoint. (The subject is the endpoint.endpointState
// map key)
type endpointState struct {
	// all fields guarded by endpoint.mu

	// lastPing is the last (outgoing) ping time.
	lastPing mono.Time

	// lastGotPing, if non-zero, means that this was an endpoint
	// that we learned about at runtime (from an incoming ping)
	// and that is not in the network map. If so, we keep the time
	// updated and use it to discard old candidates.
	lastGotPing time.Time

	// lastGotPingTxID contains the TxID for the last incoming ping. This is
	// used to de-dup incoming pings that we may see on both the raw disco
	// socket on Linux, and UDP socket. We cannot rely solely on the raw socket
	// disco handling due to https://github.com/tailscale/tailscale/issues/7078.
	lastGotPingTxID stun.TxID

	// callMeMaybeTime, if non-zero, is the time this endpoint
	// was advertised last via a call-me-maybe disco message.
	callMeMaybeTime time.Time

	recentPongs []pongReply // ring buffer up to pongHistoryCount entries
	recentPong  uint16      // index into recentPongs of most recent; older before, wrapped

	index int16 // index in nodecfg.Node.Endpoints; meaningless if lastGotPing non-zero
}

// clear removes all derived / probed state from an endpointState.
func (s *endpointState) clear() {
	*s = endpointState{
		index:       s.index,
		lastGotPing: s.lastGotPing,
	}
}

// pongHistoryCount is how many pongReply values we keep per endpointState
const pongHistoryCount = 64

type pongReply struct {
	latency time.Duration
	pongAt  mono.Time      // when we received the pong
	from    netip.AddrPort // the pong's src (usually same as endpoint map key)
	pongSrc netip.AddrPort // what they reported they heard
}

// EndpointChange is a structure containing information about changes made to a
// particular endpoint. This is not a stable interface and could change at any
// time.
type EndpointChange struct {
	When time.Time // when the change occurred
	What string    // what this change is
	From any       `json:",omitempty"` // information about the previous state
	To   any       `json:",omitempty"` // information about the new state
}

// shouldDeleteLocked reports whether we should delete this endpoint.
func (st *endpointState) shouldDeleteLocked() bool {
	switch {
	case !st.callMeMaybeTime.IsZero():
		return false
	case st.lastGotPing.IsZero():
		// This was an endpoint from the network map. Is it still in the network map?
		return st.index == indexSentinelDeleted
	default:
		// This was an endpoint discovered at runtime.
		return time.Since(st.lastGotPing) > sessionActiveTimeout
	}
}

// latencyLocked returns the most recent latency measurement, if any.
// endpoint.mu must be held.
func (st *endpointState) latencyLocked() (lat time.Duration, ok bool) {
	if len(st.recentPongs) == 0 {
		return 0, false
	}
	return st.recentPongs[st.recentPong].latency, true
}

// endpoint.mu must be held.
func (st *endpointState) addPongReplyLocked(r pongReply) {
	if n := len(st.recentPongs); n < pongHistoryCount {
		st.recentPong = uint16(n)
		st.recentPongs = append(st.recentPongs, r)
		return
	}
	i := st.recentPong + 1
	if i == pongHistoryCount {
		i = 0
	}
	st.recentPongs[i] = r
	st.recentPong = i
}

func (de *endpoint) deleteEndpointLocked(why string, ep netip.AddrPort) {
	de.debugUpdates.Add(EndpointChange{
		When: time.Now(),
		What: "deleteEndpointLocked-" + why,
		From: ep,
	})
	delete(de.endpointState, ep)
	if de.bestAddr.AddrPort == ep {
		de.debugUpdates.Add(EndpointChange{
			When: time.Now(),
			What: "deleteEndpointLocked-bestAddr-" + why,
			From: de.bestAddr,
		})
		de.bestAddr = addrLatency{}
	}
}

// initFakeUDPAddr populates fakeWGAddr with a globally unique fake UDPAddr.
// The current implementation just uses the pointer value of de jammed into an IPv6
// address, but it could also be, say, a counter.
func (de *endpoint) initFakeUDPAddr() {
	var addr [16]byte
	addr[0] = 0xfd
	addr[1] = 0x00
	binary.BigEndian.PutUint64(addr[2:], uint64(reflect.ValueOf(de).Pointer()))
	de.fakeWGAddr = netip.AddrPortFrom(netip.AddrFrom16(addr).Unmap(), 12345)
}

// noteRecvActivity records receive activity on de, and invokes
// Conn.noteRecvActivity no more than once every 10s.
func (de *endpoint) noteRecvActivity(ipp netip.AddrPort) {
	now := mono.Now()

	// TODO(raggi): this probably applies relatively equally well to disco
	// managed endpoints, but that would be a less conservative change.
	if de.isWireguardOnly {
		de.mu.Lock()
		de.bestAddr.AddrPort = ipp
		de.bestAddrAt = now
		de.trustBestAddrUntil = now.Add(5 * time.Second)
		de.mu.Unlock()
	}

	elapsed := now.Sub(de.lastRecv.LoadAtomic())
	if elapsed > 10*time.Second {
		de.lastRecv.StoreAtomic(now)

		if de.c.noteRecvActivity == nil {
			return
		}
		de.c.noteRecvActivity(de.publicKey)
	}
}

func (de *endpoint) discoShort() string {
	var short string
	if d := de.disco.Load(); d != nil {
		short = d.short
	}
	return short
}

// String exists purely so wireguard-go internals can log.Printf("%v")
// its internal conn.Endpoints and we don't end up with data races
// from fmt (via log) reading mutex fields and such.
func (de *endpoint) String() string {
	return fmt.Sprintf("magicsock.endpoint{%v, %v}", de.publicKey.ShortString(), de.discoShort())
}

func (de *endpoint) ClearSrc()           {}
func (de *endpoint) SrcToString() string { panic("unused") } // unused by wireguard-go
func (de *endpoint) SrcIP() netip.Addr   { panic("unused") } // unused by wireguard-go
func (de *endpoint) DstToString() string { return de.publicKeyHex }
func (de *endpoint) DstIP() netip.Addr   { return de.nodeAddr } // see tailscale/tailscale#6686
func (de *endpoint) DstToBytes() []byte  { return packIPPort(de.fakeWGAddr) }

// addrForSendLocked returns the address(es) that should be used for
// sending the next packet. Zero, one, or both of UDP address and DERP
// addr may be non-zero. If the endpoint is WireGuard only and does not have
// latency information, a bool is returned to indiciate that the
// WireGuard latency discovery pings should be sent.
//
// de.mu must be held.
func (de *endpoint) addrForSendLocked(now mono.Time) (udpAddr, derpAddr netip.AddrPort, sendWGPing bool) {
	udpAddr = de.bestAddr.AddrPort

	if udpAddr.IsValid() && !now.After(de.trustBestAddrUntil) {
		return udpAddr, netip.AddrPort{}, false
	}

	if de.isWireguardOnly {
		// If the endpoint is wireguard-only, we don't have a DERP
		// address to send to, so we have to send to the UDP address.
		udpAddr, shouldPing := de.addrForWireGuardSendLocked(now)
		return udpAddr, netip.AddrPort{}, shouldPing
	}

	// We had a bestAddr but it expired so send both to it
	// and DERP.
	return udpAddr, de.derpAddr, false
}

// addrForWireGuardSendLocked returns the address that should be used for
// sending the next packet. If a packet has never or not recently been sent to
// the endpoint, then a randomly selected address for the endpoint is returned,
// as well as a bool indiciating that WireGuard discovery pings should be started.
// If the addresses have latency information available, then the address with the
// best latency is used.
//
// de.mu must be held.
func (de *endpoint) addrForWireGuardSendLocked(now mono.Time) (udpAddr netip.AddrPort, shouldPing bool) {
	if len(de.endpointState) == 0 {
		de.c.logf("magicsock: addrForSendWireguardLocked: [unexpected] no candidates available for endpoint")
		return udpAddr, false
	}

	// lowestLatency is a high duration initially, so we
	// can be sure we're going to have a duration lower than this
	// for the first latency retrieved.
	lowestLatency := time.Hour
	var oldestPing mono.Time
	for ipp, state := range de.endpointState {
		if oldestPing.IsZero() {
			oldestPing = state.lastPing
		} else if state.lastPing.Before(oldestPing) {
			oldestPing = state.lastPing
		}

		if latency, ok := state.latencyLocked(); ok {
			if latency < lowestLatency || latency == lowestLatency && ipp.Addr().Is6() {
				// If we have the same latency,IPv6 is prioritized.
				// TODO(catzkorn): Consider a small increase in latency to use
				// IPv6 in comparison to IPv4, when possible.
				lowestLatency = latency
				udpAddr = ipp
			}
		}
	}
	needPing := len(de.endpointState) > 1 && now.Sub(oldestPing) > wireguardPingInterval

	if !udpAddr.IsValid() {
		candidates := maps.Keys(de.endpointState)

		// Randomly select an address to use until we retrieve latency information
		// and give it a short trustBestAddrUntil time so we avoid flapping between
		// addresses while waiting on latency information to be populated.
		udpAddr = candidates[rand.Intn(len(candidates))]
	}

	de.bestAddr.AddrPort = udpAddr
	// Only extend trustBestAddrUntil by one second to avoid packet
	// reordering and/or CPU usage from random selection during the first
	// second. We should receive a response due to a WireGuard handshake in
	// less than one second in good cases, in which case this will be then
	// extended to 15 seconds.
	de.trustBestAddrUntil = now.Add(time.Second)
	return udpAddr, needPing
}

// heartbeat is called every heartbeatInterval to keep the best UDP path alive,
// or kick off discovery of other paths.
func (de *endpoint) heartbeat() {
	de.mu.Lock()
	defer de.mu.Unlock()

	de.heartBeatTimer = nil

	if de.heartbeatDisabled {
		// If control override to disable heartBeatTimer set, return early.
		return
	}

	if de.lastSend.IsZero() {
		// Shouldn't happen.
		return
	}

	if mono.Since(de.lastSend) > sessionActiveTimeout {
		// Session's idle. Stop heartbeating.
		de.c.dlogf("[v1] magicsock: disco: ending heartbeats for idle session to %v (%v)", de.publicKey.ShortString(), de.discoShort())
		return
	}

	now := mono.Now()
	udpAddr, _, _ := de.addrForSendLocked(now)
	if udpAddr.IsValid() {
		// We have a preferred path. Ping that every 2 seconds.
		de.startDiscoPingLocked(udpAddr, now, pingHeartbeat, 0)
	}

	if de.wantFullPingLocked(now) {
		de.sendDiscoPingsLocked(now, true)
	}

	de.heartBeatTimer = time.AfterFunc(heartbeatInterval, de.heartbeat)
}

// wantFullPingLocked reports whether we should ping to all our peers looking for
// a better path.
//
// de.mu must be held.
func (de *endpoint) wantFullPingLocked(now mono.Time) bool {
	if runtime.GOOS == "js" {
		return false
	}
	if !de.bestAddr.IsValid() || de.lastFullPing.IsZero() {
		return true
	}
	if now.After(de.trustBestAddrUntil) {
		return true
	}
	if de.bestAddr.latency <= goodEnoughLatency {
		return false
	}
	if now.Sub(de.lastFullPing) >= upgradeInterval {
		return true
	}
	return false
}

func (de *endpoint) noteActiveLocked() {
	de.lastSend = mono.Now()
	if de.heartBeatTimer == nil && !de.heartbeatDisabled {
		de.heartBeatTimer = time.AfterFunc(heartbeatInterval, de.heartbeat)
	}
}

// cliPing starts a ping for the "tailscale ping" command. res is value to call cb with,
// already partially filled.
func (de *endpoint) cliPing(res *ipnstate.PingResult, size int, cb func(*ipnstate.PingResult)) {
	de.mu.Lock()
	defer de.mu.Unlock()

	if de.expired {
		res.Err = errExpired.Error()
		cb(res)
		return
	}

	de.pendingCLIPings = append(de.pendingCLIPings, pendingCLIPing{res, cb})

	now := mono.Now()
	udpAddr, derpAddr, _ := de.addrForSendLocked(now)
	if derpAddr.IsValid() {
		de.startDiscoPingLocked(derpAddr, now, pingCLI, size)
	}
	if udpAddr.IsValid() && now.Before(de.trustBestAddrUntil) {
		// Already have an active session, so just ping the address we're using.
		// Otherwise "tailscale ping" results to a node on the local network
		// can look like they're bouncing between, say 10.0.0.0/9 and the peer's
		// IPv6 address, both 1ms away, and it's random who replies first.
		de.startDiscoPingLocked(udpAddr, now, pingCLI, size)
	} else {
		for ep := range de.endpointState {
			de.startDiscoPingLocked(ep, now, pingCLI, size)
		}
	}
	de.noteActiveLocked()
}

var (
	errExpired     = errors.New("peer's node key has expired")
	errNoUDPOrDERP = errors.New("no UDP or DERP addr")
)

func (de *endpoint) send(buffs [][]byte) error {
	de.mu.Lock()
	if de.expired {
		de.mu.Unlock()
		return errExpired
	}

	now := mono.Now()
	udpAddr, derpAddr, startWGPing := de.addrForSendLocked(now)

	if de.isWireguardOnly {
		if startWGPing {
			de.sendWireGuardOnlyPingsLocked(now)
		}
	} else if !udpAddr.IsValid() || now.After(de.trustBestAddrUntil) {
		de.sendDiscoPingsLocked(now, true)
	}
	de.noteActiveLocked()
	de.mu.Unlock()

	if !udpAddr.IsValid() && !derpAddr.IsValid() {
		return errNoUDPOrDERP
	}
	var err error
	if udpAddr.IsValid() {
		_, err = de.c.sendUDPBatch(udpAddr, buffs)

		// If the error is known to indicate that the endpoint is no longer
		// usable, clear the endpoint statistics so that the next send will
		// re-evaluate the best endpoint.
		if err != nil && isBadEndpointErr(err) {
			de.noteBadEndpoint(udpAddr)
		}

		// TODO(raggi): needs updating for accuracy, as in error conditions we may have partial sends.
		if stats := de.c.stats.Load(); err == nil && stats != nil {
			var txBytes int
			for _, b := range buffs {
				txBytes += len(b)
			}
			stats.UpdateTxPhysical(de.nodeAddr, udpAddr, txBytes)
		}
	}
	if derpAddr.IsValid() {
		allOk := true
		for _, buff := range buffs {
			ok, _ := de.c.sendAddr(derpAddr, de.publicKey, buff)
			if stats := de.c.stats.Load(); stats != nil {
				stats.UpdateTxPhysical(de.nodeAddr, derpAddr, len(buff))
			}
			if !ok {
				allOk = false
			}
		}
		if allOk {
			return nil
		}
	}
	return err
}

func (de *endpoint) discoPingTimeout(txid stun.TxID) {
	de.mu.Lock()
	defer de.mu.Unlock()
	sp, ok := de.sentPing[txid]
	if !ok {
		return
	}
	if debugDisco() || !de.bestAddr.IsValid() || mono.Now().After(de.trustBestAddrUntil) {
		de.c.dlogf("[v1] magicsock: disco: timeout waiting for pong %x from %v (%v, %v)", txid[:6], sp.to, de.publicKey.ShortString(), de.discoShort())
	}
	de.removeSentDiscoPingLocked(txid, sp)
}

// forgetDiscoPing is called by a timer when a ping either fails to send or
// has taken too long to get a pong reply.
func (de *endpoint) forgetDiscoPing(txid stun.TxID) {
	de.mu.Lock()
	defer de.mu.Unlock()
	if sp, ok := de.sentPing[txid]; ok {
		de.removeSentDiscoPingLocked(txid, sp)
	}
}

func (de *endpoint) removeSentDiscoPingLocked(txid stun.TxID, sp sentPing) {
	// Stop the timer for the case where sendPing failed to write to UDP.
	// In the case of a timer already having fired, this is a no-op:
	sp.timer.Stop()
	delete(de.sentPing, txid)
}

// discoPingSize is the size of a complete disco ping packet, without any padding.
const discoPingSize = len(disco.Magic) + key.DiscoPublicRawLen + disco.NonceLen +
	poly1305.TagSize + disco.MessageHeaderLen + disco.PingLen

// sendDiscoPing sends a ping with the provided txid to ep using de's discoKey. size
// is the desired disco message size, including all disco headers but excluding IP/UDP
// headers.
//
// The caller (startPingLocked) should've already recorded the ping in
// sentPing and set up the timer.
//
// The caller should use de.discoKey as the discoKey argument.
// It is passed in so that sendDiscoPing doesn't need to lock de.mu.
func (de *endpoint) sendDiscoPing(ep netip.AddrPort, discoKey key.DiscoPublic, txid stun.TxID, size int, logLevel discoLogLevel) {
	padding := 0
	if size > int(tstun.DefaultMTU()) {
		size = int(tstun.DefaultMTU())
	}
	if size-discoPingSize > 0 {
		padding = size - discoPingSize
	}
	sent, _ := de.c.sendDiscoMessage(ep, de.publicKey, discoKey, &disco.Ping{
		TxID:    [12]byte(txid),
		NodeKey: de.c.publicKeyAtomic.Load(),
		Padding: padding,
	}, logLevel)
	if !sent {
		de.forgetDiscoPing(txid)
	}
}

// discoPingPurpose is the reason why a discovery ping message was sent.
type discoPingPurpose int

//go:generate go run tailscale.com/cmd/addlicense -file discopingpurpose_string.go go run golang.org/x/tools/cmd/stringer -type=discoPingPurpose -trimprefix=ping
const (
	// pingDiscovery means that purpose of a ping was to see if a
	// path was valid.
	pingDiscovery discoPingPurpose = iota

	// pingHeartbeat means that purpose of a ping was whether a
	// peer was still there.
	pingHeartbeat

	// pingCLI means that the user is running "tailscale ping"
	// from the CLI. These types of pings can go over DERP.
	pingCLI
)

// startDiscoPingLocked sends a disco ping to ep in a separate goroutine.
func (de *endpoint) startDiscoPingLocked(ep netip.AddrPort, now mono.Time, purpose discoPingPurpose, size int) {
	if runtime.GOOS == "js" {
		return
	}
	epDisco := de.disco.Load()
	if epDisco == nil {
		return
	}
	if purpose != pingCLI {
		st, ok := de.endpointState[ep]
		if !ok {
			// Shouldn't happen. But don't ping an endpoint that's
			// not active for us.
			de.c.logf("magicsock: disco: [unexpected] attempt to ping no longer live endpoint %v", ep)
			return
		}
		st.lastPing = now
	}

	txid := stun.NewTxID()
	de.sentPing[txid] = sentPing{
		to:      ep,
		at:      now,
		timer:   time.AfterFunc(pingTimeoutDuration, func() { de.discoPingTimeout(txid) }),
		purpose: purpose,
	}
	logLevel := discoLog
	if purpose == pingHeartbeat {
		logLevel = discoVerboseLog
	}
	go de.sendDiscoPing(ep, epDisco.key, txid, size, logLevel)
}

// sendDiscoPingsLocked starts pinging all of ep's endpoints.
func (de *endpoint) sendDiscoPingsLocked(now mono.Time, sendCallMeMaybe bool) {
	de.lastFullPing = now
	var sentAny bool
	for ep, st := range de.endpointState {
		if st.shouldDeleteLocked() {
			de.deleteEndpointLocked("sendPingsLocked", ep)
			continue
		}
		if runtime.GOOS == "js" {
			continue
		}
		if !st.lastPing.IsZero() && now.Sub(st.lastPing) < discoPingInterval {
			continue
		}

		firstPing := !sentAny
		sentAny = true

		if firstPing && sendCallMeMaybe {
			de.c.dlogf("[v1] magicsock: disco: send, starting discovery for %v (%v)", de.publicKey.ShortString(), de.discoShort())
		}

		de.startDiscoPingLocked(ep, now, pingDiscovery, 0)
	}
	derpAddr := de.derpAddr
	if sentAny && sendCallMeMaybe && derpAddr.IsValid() {
		// Have our magicsock.Conn figure out its STUN endpoint (if
		// it doesn't know already) and then send a CallMeMaybe
		// message to our peer via DERP informing them that we've
		// sent so our firewall ports are probably open and now
		// would be a good time for them to connect.
		go de.c.enqueueCallMeMaybe(derpAddr, de)
	}
}

// sendWireGuardOnlyPingsLocked evaluates all available addresses for
// a WireGuard only endpoint and initates an ICMP ping for useable
// addresses.
func (de *endpoint) sendWireGuardOnlyPingsLocked(now mono.Time) {
	if runtime.GOOS == "js" {
		return
	}

	// Normally the we only send pings at a low rate as the decision to start
	// sending a ping sets bestAddrAtUntil with a reasonable time to keep trying
	// that address, however, if that code changed we may want to be sure that
	// we don't ever send excessive pings to avoid impact to the client/user.
	if !now.After(de.lastFullPing.Add(10 * time.Second)) {
		return
	}
	de.lastFullPing = now

	for ipp := range de.endpointState {
		if ipp.Addr().Is4() && de.c.noV4.Load() {
			continue
		}
		if ipp.Addr().Is6() && de.c.noV6.Load() {
			continue
		}

		go de.sendWireGuardOnlyPing(ipp, now)
	}
}

// sendWireGuardOnlyPing sends a ICMP ping to a WireGuard only address to
// discover the latency.
func (de *endpoint) sendWireGuardOnlyPing(ipp netip.AddrPort, now mono.Time) {
	ctx, cancel := context.WithTimeout(de.c.connCtx, 5*time.Second)
	defer cancel()

	de.setLastPing(ipp, now)

	addr := &net.IPAddr{
		IP:   net.IP(ipp.Addr().AsSlice()),
		Zone: ipp.Addr().Zone(),
	}

	p := de.c.getPinger()
	if p == nil {
		de.c.logf("[v2] magicsock: sendWireGuardOnlyPingLocked: pinger is nil")
		return
	}

	latency, err := p.Send(ctx, addr, nil)
	if err != nil {
		de.c.logf("[v2] magicsock: sendWireGuardOnlyPingLocked: %s", err)
		return
	}

	de.mu.Lock()
	defer de.mu.Unlock()

	state, ok := de.endpointState[ipp]
	if !ok {
		return
	}
	state.addPongReplyLocked(pongReply{
		latency: latency,
		pongAt:  now,
		from:    ipp,
		pongSrc: netip.AddrPort{}, // We don't know this.
	})
}

// setLastPing sets lastPing on the endpointState to now.
func (de *endpoint) setLastPing(ipp netip.AddrPort, now mono.Time) {
	de.mu.Lock()
	defer de.mu.Unlock()
	state, ok := de.endpointState[ipp]
	if !ok {
		return
	}
	state.lastPing = now
}

// updateFromNode updates the endpoint based on a tailcfg.Node from a NetMap
// update.
func (de *endpoint) updateFromNode(n *tailcfg.Node, heartbeatDisabled bool) {
	if n == nil {
		panic("nil node when updating endpoint")
	}
	de.mu.Lock()
	defer de.mu.Unlock()

	de.heartbeatDisabled = heartbeatDisabled
	de.expired = n.Expired

	epDisco := de.disco.Load()
	var discoKey key.DiscoPublic
	if epDisco != nil {
		discoKey = epDisco.key
	}

	if discoKey != n.DiscoKey {
		de.c.logf("[v1] magicsock: disco: node %s changed from %s to %s", de.publicKey.ShortString(), discoKey, n.DiscoKey)
		de.disco.Store(&endpointDisco{
			key:   n.DiscoKey,
			short: n.DiscoKey.ShortString(),
		})
		de.debugUpdates.Add(EndpointChange{
			When: time.Now(),
			What: "updateFromNode-resetLocked",
		})
		de.resetLocked()
	}
	if n.DERP == "" {
		if de.derpAddr.IsValid() {
			de.debugUpdates.Add(EndpointChange{
				When: time.Now(),
				What: "updateFromNode-remove-DERP",
				From: de.derpAddr,
			})
		}
		de.derpAddr = netip.AddrPort{}
	} else {
		newDerp, _ := netip.ParseAddrPort(n.DERP)
		if de.derpAddr != newDerp {
			de.debugUpdates.Add(EndpointChange{
				When: time.Now(),
				What: "updateFromNode-DERP",
				From: de.derpAddr,
				To:   newDerp,
			})
		}
		de.derpAddr = newDerp
	}

	for _, st := range de.endpointState {
		st.index = indexSentinelDeleted // assume deleted until updated in next loop
	}

	var newIpps []netip.AddrPort
	for i, epStr := range n.Endpoints {
		if i > math.MaxInt16 {
			// Seems unlikely.
			continue
		}
		ipp, err := netip.ParseAddrPort(epStr)
		if err != nil {
			de.c.logf("magicsock: bogus netmap endpoint %q", epStr)
			continue
		}
		if st, ok := de.endpointState[ipp]; ok {
			st.index = int16(i)
		} else {
			de.endpointState[ipp] = &endpointState{index: int16(i)}
			newIpps = append(newIpps, ipp)
		}
	}
	if len(newIpps) > 0 {
		de.debugUpdates.Add(EndpointChange{
			When: time.Now(),
			What: "updateFromNode-new-Endpoints",
			To:   newIpps,
		})
	}

	// Now delete anything unless it's still in the network map or
	// was a recently discovered endpoint.
	for ep, st := range de.endpointState {
		if st.shouldDeleteLocked() {
			de.deleteEndpointLocked("updateFromNode", ep)
		}
	}
}

// addCandidateEndpoint adds ep as an endpoint to which we should send
// future pings. If there is an existing endpointState for ep, and forRxPingTxID
// matches the last received ping TxID, this function reports true, otherwise
// false.
//
// This is called once we've already verified that we got a valid
// discovery message from de via ep.
func (de *endpoint) addCandidateEndpoint(ep netip.AddrPort, forRxPingTxID stun.TxID) (duplicatePing bool) {
	de.mu.Lock()
	defer de.mu.Unlock()

	if st, ok := de.endpointState[ep]; ok {
		duplicatePing = forRxPingTxID == st.lastGotPingTxID
		if !duplicatePing {
			st.lastGotPingTxID = forRxPingTxID
		}
		if st.lastGotPing.IsZero() {
			// Already-known endpoint from the network map.
			return duplicatePing
		}
		st.lastGotPing = time.Now()
		return duplicatePing
	}

	// Newly discovered endpoint. Exciting!
	de.c.dlogf("[v1] magicsock: disco: adding %v as candidate endpoint for %v (%s)", ep, de.discoShort(), de.publicKey.ShortString())
	de.endpointState[ep] = &endpointState{
		lastGotPing:     time.Now(),
		lastGotPingTxID: forRxPingTxID,
	}

	// If for some reason this gets very large, do some cleanup.
	if size := len(de.endpointState); size > 100 {
		for ep, st := range de.endpointState {
			if st.shouldDeleteLocked() {
				de.deleteEndpointLocked("addCandidateEndpoint", ep)
			}
		}
		size2 := len(de.endpointState)
		de.c.dlogf("[v1] magicsock: disco: addCandidateEndpoint pruned %v candidate set from %v to %v entries", size, size2)
	}
	return false
}

// clearBestAddrLocked clears the bestAddr and related fields such that future
// packets will re-evaluate the best address to send to next.
//
// de.mu must be held.
func (de *endpoint) clearBestAddrLocked() {
	de.bestAddr = addrLatency{}
	de.bestAddrAt = 0
	de.trustBestAddrUntil = 0
}

// noteBadEndpoint marks ipp as a bad endpoint that would need to be
// re-evaluated before future use, this should be called for example if a send
// to ipp fails due to a host unreachable error or similar.
func (de *endpoint) noteBadEndpoint(ipp netip.AddrPort) {
	de.mu.Lock()
	defer de.mu.Unlock()

	de.clearBestAddrLocked()

	if st, ok := de.endpointState[ipp]; ok {
		st.clear()
	}
}

// noteConnectivityChange is called when connectivity changes enough
// that we should question our earlier assumptions about which paths
// work.
func (de *endpoint) noteConnectivityChange() {
	de.mu.Lock()
	defer de.mu.Unlock()

	de.clearBestAddrLocked()

	for k := range de.endpointState {
		de.endpointState[k].clear()
	}
}

// handlePongConnLocked handles a Pong message (a reply to an earlier ping).
// It should be called with the Conn.mu held.
//
// It reports whether m.TxID corresponds to a ping that this endpoint sent.
func (de *endpoint) handlePongConnLocked(m *disco.Pong, di *discoInfo, src netip.AddrPort) (knownTxID bool) {
	de.mu.Lock()
	defer de.mu.Unlock()

	isDerp := src.Addr() == tailcfg.DerpMagicIPAddr

	sp, ok := de.sentPing[m.TxID]
	if !ok {
		// This is not a pong for a ping we sent.
		return false
	}
	knownTxID = true // for naked returns below
	de.removeSentDiscoPingLocked(m.TxID, sp)

	now := mono.Now()
	latency := now.Sub(sp.at)

	if !isDerp {
		st, ok := de.endpointState[sp.to]
		if !ok {
			// This is no longer an endpoint we care about.
			return
		}

		de.c.peerMap.setNodeKeyForIPPort(src, de.publicKey)

		st.addPongReplyLocked(pongReply{
			latency: latency,
			pongAt:  now,
			from:    src,
			pongSrc: m.Src,
		})
	}

	if sp.purpose != pingHeartbeat {
		de.c.dlogf("[v1] magicsock: disco: %v<-%v (%v, %v)  got pong tx=%x latency=%v pong.src=%v%v", de.c.discoShort, de.discoShort(), de.publicKey.ShortString(), src, m.TxID[:6], latency.Round(time.Millisecond), m.Src, logger.ArgWriter(func(bw *bufio.Writer) {
			if sp.to != src {
				fmt.Fprintf(bw, " ping.to=%v", sp.to)
			}
		}))
	}

	for _, pp := range de.pendingCLIPings {
		de.c.populateCLIPingResponseLocked(pp.res, latency, sp.to)
		go pp.cb(pp.res)
	}
	de.pendingCLIPings = nil

	// Promote this pong response to our current best address if it's lower latency.
	// TODO(bradfitz): decide how latency vs. preference order affects decision
	if !isDerp {
		thisPong := addrLatency{sp.to, latency}
		if betterAddr(thisPong, de.bestAddr) {
			de.c.logf("magicsock: disco: node %v %v now using %v", de.publicKey.ShortString(), de.discoShort(), sp.to)
			de.debugUpdates.Add(EndpointChange{
				When: time.Now(),
				What: "handlePingLocked-bestAddr-update",
				From: de.bestAddr,
				To:   thisPong,
			})
			de.bestAddr = thisPong
		}
		if de.bestAddr.AddrPort == thisPong.AddrPort {
			de.debugUpdates.Add(EndpointChange{
				When: time.Now(),
				What: "handlePingLocked-bestAddr-latency",
				From: de.bestAddr,
				To:   thisPong,
			})
			de.bestAddr.latency = latency
			de.bestAddrAt = now
			de.trustBestAddrUntil = now.Add(trustUDPAddrDuration)
		}
	}
	return
}

// addrLatency is an IPPort with an associated latency.
type addrLatency struct {
	netip.AddrPort
	latency time.Duration
}

func (a addrLatency) String() string {
	return a.AddrPort.String() + "@" + a.latency.String()
}

// betterAddr reports whether a is a better addr to use than b.
func betterAddr(a, b addrLatency) bool {
	if a.AddrPort == b.AddrPort {
		return false
	}
	if !b.IsValid() {
		return true
	}
	if !a.IsValid() {
		return false
	}

	// Each address starts with a set of points (from 0 to 100) that
	// represents how much faster they are than the highest-latency
	// endpoint. For example, if a has latency 200ms and b has latency
	// 190ms, then a starts with 0 points and b starts with 5 points since
	// it's 5% faster.
	var aPoints, bPoints int
	if a.latency > b.latency && a.latency > 0 {
		bPoints = int(100 - ((b.latency * 100) / a.latency))
	} else if b.latency > 0 {
		aPoints = int(100 - ((a.latency * 100) / b.latency))
	}

	// Prefer private IPs over public IPs as long as the latencies are
	// roughly equivalent, since it's less likely that a user will have to
	// pay for the bandwidth in a cloud environment.
	//
	// Additionally, prefer any loopback address strongly over non-loopback
	// addresses.
	if a.Addr().IsLoopback() {
		aPoints += 50
	} else if a.Addr().IsPrivate() {
		aPoints += 20
	}
	if b.Addr().IsLoopback() {
		bPoints += 50
	} else if b.Addr().IsPrivate() {
		bPoints += 20
	}

	// Prefer IPv6 for being a bit more robust, as long as
	// the latencies are roughly equivalent.
	if a.Addr().Is6() {
		aPoints += 10
	}
	if b.Addr().Is6() {
		bPoints += 10
	}

	// Don't change anything if the latency improvement is less than 1%; we
	// want a bit of "stickiness" (a.k.a. hysteresis) to avoid flapping if
	// there's two roughly-equivalent endpoints.
	//
	// Points are essentially the percentage improvement of latency vs. the
	// slower endpoint; absent any boosts from private IPs, IPv6, etc., a
	// will be a better address than b by a fraction of 1% or less if
	// aPoints <= 1 and bPoints == 0.
	if aPoints <= 1 && bPoints == 0 {
		return false
	}

	return aPoints > bPoints
}

// handleCallMeMaybe handles a CallMeMaybe discovery message via
// DERP. The contract for use of this message is that the peer has
// already sent to us via UDP, so their stateful firewall should be
// open. Now we can Ping back and make it through.
func (de *endpoint) handleCallMeMaybe(m *disco.CallMeMaybe) {
	if runtime.GOOS == "js" {
		// Nothing to do on js/wasm if we can't send UDP packets anyway.
		return
	}
	de.mu.Lock()
	defer de.mu.Unlock()

	now := time.Now()
	for ep := range de.isCallMeMaybeEP {
		de.isCallMeMaybeEP[ep] = false // mark for deletion
	}
	var newEPs []netip.AddrPort
	for _, ep := range m.MyNumber {
		if ep.Addr().Is6() && ep.Addr().IsLinkLocalUnicast() {
			// We send these out, but ignore them for now.
			// TODO: teach the ping code to ping on all interfaces
			// for these.
			continue
		}
		mak.Set(&de.isCallMeMaybeEP, ep, true)
		if es, ok := de.endpointState[ep]; ok {
			es.callMeMaybeTime = now
		} else {
			de.endpointState[ep] = &endpointState{callMeMaybeTime: now}
			newEPs = append(newEPs, ep)
		}
	}
	if len(newEPs) > 0 {
		de.debugUpdates.Add(EndpointChange{
			When: time.Now(),
			What: "handleCallMeMaybe-new-endpoints",
			To:   newEPs,
		})

		de.c.dlogf("[v1] magicsock: disco: call-me-maybe from %v %v added new endpoints: %v",
			de.publicKey.ShortString(), de.discoShort(),
			logger.ArgWriter(func(w *bufio.Writer) {
				for i, ep := range newEPs {
					if i > 0 {
						w.WriteString(", ")
					}
					w.WriteString(ep.String())
				}
			}))
	}

	// Delete any prior CallMeMaybe endpoints that weren't included
	// in this message.
	for ep, want := range de.isCallMeMaybeEP {
		if !want {
			delete(de.isCallMeMaybeEP, ep)
			de.deleteEndpointLocked("handleCallMeMaybe", ep)
		}
	}

	// Zero out all the lastPing times to force sendPingsLocked to send new ones,
	// even if it's been less than 5 seconds ago.
	for _, st := range de.endpointState {
		st.lastPing = 0
	}
	de.sendDiscoPingsLocked(mono.Now(), false)
}

func (de *endpoint) populatePeerStatus(ps *ipnstate.PeerStatus) {
	de.mu.Lock()
	defer de.mu.Unlock()

	ps.Relay = de.c.derpRegionCodeOfIDLocked(int(de.derpAddr.Port()))

	if de.lastSend.IsZero() {
		return
	}

	now := mono.Now()
	ps.LastWrite = de.lastSend.WallTime()
	ps.Active = now.Sub(de.lastSend) < sessionActiveTimeout

	if udpAddr, derpAddr, _ := de.addrForSendLocked(now); udpAddr.IsValid() && !derpAddr.IsValid() {
		ps.CurAddr = udpAddr.String()
	}
}

// stopAndReset stops timers associated with de and resets its state back to zero.
// It's called when a discovery endpoint is no longer present in the
// NetworkMap, or when magicsock is transitioning from running to
// stopped state (via SetPrivateKey(zero))
func (de *endpoint) stopAndReset() {
	atomic.AddInt64(&de.numStopAndResetAtomic, 1)
	de.mu.Lock()
	defer de.mu.Unlock()

	if closing := de.c.closing.Load(); !closing {
		de.c.logf("[v1] magicsock: doing cleanup for discovery key %s", de.discoShort())
	}

	de.debugUpdates.Add(EndpointChange{
		When: time.Now(),
		What: "stopAndReset-resetLocked",
	})
	de.resetLocked()
	if de.heartBeatTimer != nil {
		de.heartBeatTimer.Stop()
		de.heartBeatTimer = nil
	}
	de.pendingCLIPings = nil
}

// resetLocked clears all the endpoint's p2p state, reverting it to a
// DERP-only endpoint. It does not stop the endpoint's heartbeat
// timer, if one is running.
func (de *endpoint) resetLocked() {
	de.lastSend = 0
	de.lastFullPing = 0
	de.clearBestAddrLocked()
	for _, es := range de.endpointState {
		es.lastPing = 0
	}
	for txid, sp := range de.sentPing {
		de.removeSentDiscoPingLocked(txid, sp)
	}
}

func (de *endpoint) numStopAndReset() int64 {
	return atomic.LoadInt64(&de.numStopAndResetAtomic)
}
