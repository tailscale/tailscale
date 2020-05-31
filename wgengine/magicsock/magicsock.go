// Copyright (c) 2019 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package magicsock implements a socket that can change its communication path while
// in use, actively searching for the best way to communicate.
package magicsock

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/time/rate"
	"inet.af/netaddr"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netns"
	"tailscale.com/net/stun"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/structs"
	"tailscale.com/version"
)

// A Conn routes UDP packets and actively manages a list of its endpoints.
// It implements wireguard/conn.Bind.
type Conn struct {
	pconnPort    uint16 // the preferred port from opts.Port; 0 means auto
	pconn4       *RebindingUDPConn
	pconn6       *RebindingUDPConn // non-nil if IPv6 available
	epFunc       func(endpoints []string)
	logf         logger.Logf
	sendLogLimit *rate.Limiter
	netChecker   *netcheck.Client

	// bufferedIPv4From and bufferedIPv4Packet are owned by
	// ReceiveIPv4, and used when both a DERP and IPv4 packet arrive
	// at the same time. It stores the IPv4 packet for use in the next call.
	bufferedIPv4From   *net.UDPAddr // if non-nil, then bufferedIPv4Packet is valid
	bufferedIPv4Packet []byte       // the received packet (reused, owned by ReceiveIPv4)

	connCtx       context.Context // closed on Conn.Close
	connCtxCancel func()          // closes connCtx

	// stunReceiveFunc holds the current STUN packet processing func.
	// Its Loaded value is always non-nil.
	stunReceiveFunc atomic.Value // of func(p []byte, fromAddr *net.UDPAddr)

	udpRecvCh  chan udpReadResult
	derpRecvCh chan derpReadResult

	mu sync.Mutex // guards all following fields

	started bool
	closed  bool

	endpointsUpdateWaiter *sync.Cond
	endpointsUpdateActive bool
	wantEndpointsUpdate   string // true if non-empty; string is reason
	lastEndpoints         []string
	peerSet               map[key.Public]struct{}

	// addrsByUDP is a map of every remote ip:port to a priority
	// list of endpoint addresses for a peer.
	// The priority list is provided by wgengine configuration.
	//
	// Given a wgcfg describing:
	//	machineA: 10.0.0.1:1, 10.0.0.2:2
	//	machineB: 10.0.0.3:3
	// the addrsByUDP map contains:
	//	10.0.0.1:1 -> [10.0.0.1:1, 10.0.0.2:2]
	//	10.0.0.2:2 -> [10.0.0.1:1, 10.0.0.2:2]
	//	10.0.0.3:3 -> [10.0.0.3:3]
	addrsByUDP map[netaddr.IPPort]*AddrSet

	// addrsByKey maps from public keys (as seen by incoming DERP
	// packets) to its AddrSet (the same values as in addrsByUDP).
	addrsByKey map[key.Public]*AddrSet

	netInfoFunc func(*tailcfg.NetInfo) // nil until set
	netInfoLast *tailcfg.NetInfo

	derpMap     *tailcfg.DERPMap // nil (or zero regions/nodes) means DERP is disabled
	privateKey  key.Private
	myDerp      int                // nearest DERP region ID; 0 means none/unknown
	derpStarted chan struct{}      // closed on first connection to DERP; for tests
	activeDerp  map[int]activeDerp // DERP regionID -> connection to a node in that region
	prevDerp    map[int]*syncs.WaitGroupChan

	// derpRoute contains optional alternate routes to use as an
	// optimization instead of contacting a peer via their home
	// DERP connection.  If they sent us a message on a different
	// DERP connection (which should really only be on our DERP
	// home connection, or what was once our home), then we
	// remember that route here to optimistically use instead of
	// creating a new DERP connection back to their home.
	derpRoute map[key.Public]derpRoute

	// peerLastDerp tracks which DERP node we last used to speak with a
	// peer. It's only used to quiet logging, so we only log on change.
	peerLastDerp map[key.Public]int

	// noV4 and noV6 are whether IPv4 and IPv6 are known to be
	// missing.  They're only used to suppress log spam. The name
	// is named negatively because in early start-up, we don't yet
	// necessarily have a netcheck.Report and don't want to skip
	// logging.
	noV4, noV6 syncs.AtomicBool
}

// derpRoute is a route entry for a public key, saying that a certain
// peer should be available at DERP node derpID, as long as the
// current connection for that derpID is dc. (but dc should not be
// used to write directly; it's owned by the read/write loops)
type derpRoute struct {
	derpID int
	dc     *derphttp.Client // don't use directly; see comment above
}

// removeDerpPeerRoute removes a DERP route entry previously added by addDerpPeerRoute.
func (c *Conn) removeDerpPeerRoute(peer key.Public, derpID int, dc *derphttp.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r2 := derpRoute{derpID, dc}
	if r, ok := c.derpRoute[peer]; ok && r == r2 {
		delete(c.derpRoute, peer)
	}
}

// addDerpPeerRoute adds a DERP route entry, noting that peer was seen
// on DERP node derpID, at least on the connection identified by dc.
// See issue 150 for details.
func (c *Conn) addDerpPeerRoute(peer key.Public, derpID int, dc *derphttp.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.derpRoute == nil {
		c.derpRoute = make(map[key.Public]derpRoute)
	}
	r := derpRoute{derpID, dc}
	c.derpRoute[peer] = r
}

// DerpMagicIP is a fake WireGuard endpoint IP address that means
// to use DERP. When used, the port number of the WireGuard endpoint
// is the DERP server number to use.
//
// Mnemonic: 3.3.40 are numbers above the keys D, E, R, P.
const DerpMagicIP = "127.3.3.40"

var derpMagicIP = net.ParseIP(DerpMagicIP).To4()
var derpMagicIPAddr = netaddr.IPv4(127, 3, 3, 40)

// activeDerp contains fields for an active DERP connection.
type activeDerp struct {
	c       *derphttp.Client
	cancel  context.CancelFunc
	writeCh chan<- derpWriteRequest
	// lastWrite is the time of the last request for its write
	// channel (currently even if there was no write).
	// It is always non-nil and initialized to a non-zero Time[
	lastWrite  *time.Time
	createTime time.Time
}

// DefaultPort is the default port to listen on.
// The current default (zero) means to auto-select a random free port.
const DefaultPort = 0

var DisableSTUNForTesting bool

// Options contains options for Listen.
type Options struct {
	// Logf optionally provides a log function to use.
	// Must not be nil.
	Logf logger.Logf

	// Port is the port to listen on.
	// Zero means to pick one automatically.
	Port uint16

	// EndpointsFunc optionally provides a func to be called when
	// endpoints change. The called func does not own the slice.
	EndpointsFunc func(endpoint []string)
}

func (o *Options) logf() logger.Logf {
	if o.Logf == nil {
		panic("must provide magicsock.Options.logf")
	}
	return o.Logf
}

func (o *Options) endpointsFunc() func([]string) {
	if o == nil || o.EndpointsFunc == nil {
		return func([]string) {}
	}
	return o.EndpointsFunc
}

// newConn is the error-free, network-listening-side-effect-free based
// of NewConn. Mostly for tests.
func newConn() *Conn {
	c := &Conn{
		sendLogLimit: rate.NewLimiter(rate.Every(1*time.Minute), 1),
		addrsByUDP:   make(map[netaddr.IPPort]*AddrSet),
		addrsByKey:   make(map[key.Public]*AddrSet),
		derpRecvCh:   make(chan derpReadResult),
		udpRecvCh:    make(chan udpReadResult),
		derpStarted:  make(chan struct{}),
		peerLastDerp: make(map[key.Public]int),
	}
	c.endpointsUpdateWaiter = sync.NewCond(&c.mu)
	return c
}

// NewConn creates a magic Conn listening on opts.Port.
// As the set of possible endpoints for a Conn changes, the
// callback opts.EndpointsFunc is called.
//
// It doesn't start doing anything until Start is called.
func NewConn(opts Options) (*Conn, error) {
	c := newConn()
	c.pconnPort = opts.Port
	c.logf = opts.logf()
	c.epFunc = opts.endpointsFunc()

	if err := c.initialBind(); err != nil {
		return nil, err
	}

	c.connCtx, c.connCtxCancel = context.WithCancel(context.Background())
	c.netChecker = &netcheck.Client{
		Logf:         logger.WithPrefix(c.logf, "netcheck: "),
		GetSTUNConn4: func() netcheck.STUNConn { return c.pconn4 },
	}
	if c.pconn6 != nil {
		c.netChecker.GetSTUNConn6 = func() netcheck.STUNConn { return c.pconn6 }
	}

	c.ignoreSTUNPackets()

	return c, nil
}

func (c *Conn) Start() {
	c.mu.Lock()
	if c.started {
		panic("duplicate Start call")
	}
	c.started = true
	c.mu.Unlock()

	c.ReSTUN("initial")

	// We assume that LinkChange notifications are plumbed through well
	// on our mobile clients, so don't do the timer thing to save radio/battery/CPU/etc.
	if !version.IsMobile() {
		go c.periodicReSTUN()
	}
	go c.periodicDerpCleanup()
}

func (c *Conn) donec() <-chan struct{} { return c.connCtx.Done() }

// ignoreSTUNPackets sets a STUN packet processing func that does nothing.
func (c *Conn) ignoreSTUNPackets() {
	c.stunReceiveFunc.Store(func([]byte, *net.UDPAddr) {})
}

// c.mu must NOT be held.
func (c *Conn) updateEndpoints(why string) {
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		why := c.wantEndpointsUpdate
		c.wantEndpointsUpdate = ""
		if why != "" && !c.closed {
			go c.updateEndpoints(why)
		} else {
			c.endpointsUpdateActive = false
			c.endpointsUpdateWaiter.Broadcast()
		}

	}()
	c.logf("magicsock: starting endpoint update (%s)", why)

	endpoints, reasons, err := c.determineEndpoints(c.connCtx)
	if err != nil {
		c.logf("magicsock: endpoint update (%s) failed: %v", why, err)
		// TODO(crawshaw): are there any conditions under which
		// we should trigger a retry based on the error here?
		return
	}

	if c.setEndpoints(endpoints) {
		c.logEndpointChange(endpoints, reasons)
		c.epFunc(endpoints)
	}
}

// setEndpoints records the new endpoints, reporting whether they're changed.
// It takes ownership of the slice.
func (c *Conn) setEndpoints(endpoints []string) (changed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if stringsEqual(endpoints, c.lastEndpoints) {
		return false
	}
	c.lastEndpoints = endpoints
	return true
}

func (c *Conn) updateNetInfo(ctx context.Context) (*netcheck.Report, error) {
	c.mu.Lock()
	dm := c.derpMap
	c.mu.Unlock()

	if DisableSTUNForTesting || dm == nil {
		return new(netcheck.Report), nil
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	c.stunReceiveFunc.Store(c.netChecker.ReceiveSTUNPacket)
	defer c.ignoreSTUNPackets()

	report, err := c.netChecker.GetReport(ctx, dm)
	if err != nil {
		return nil, err
	}

	c.noV4.Set(!report.IPv4)
	c.noV6.Set(!report.IPv6)

	ni := &tailcfg.NetInfo{
		DERPLatency:           map[string]float64{},
		MappingVariesByDestIP: report.MappingVariesByDestIP,
		HairPinning:           report.HairPinning,
	}
	for rid, d := range report.RegionV4Latency {
		ni.DERPLatency[fmt.Sprintf("%d-v4", rid)] = d.Seconds()
	}
	for rid, d := range report.RegionV6Latency {
		ni.DERPLatency[fmt.Sprintf("%d-v6", rid)] = d.Seconds()
	}
	ni.WorkingIPv6.Set(report.IPv6)
	ni.WorkingUDP.Set(report.UDP)
	ni.PreferredDERP = report.PreferredDERP

	if ni.PreferredDERP == 0 {
		// Perhaps UDP is blocked. Pick a deterministic but arbitrary
		// one.
		ni.PreferredDERP = c.pickDERPFallback()
	}
	if !c.setNearestDERP(ni.PreferredDERP) {
		ni.PreferredDERP = 0
	}

	// TODO: set link type

	c.callNetInfoCallback(ni)
	return report, nil
}

var processStartUnixNano = time.Now().UnixNano()

// pickDERPFallback returns a non-zero but deterministic DERP node to
// connect to.  This is only used if netcheck couldn't find the
// nearest one (for instance, if UDP is blocked and thus STUN latency
// checks aren't working).
//
// c.mu must NOT be held.
func (c *Conn) pickDERPFallback() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.wantDerpLocked() {
		return 0
	}
	ids := c.derpMap.RegionIDs()
	if len(ids) == 0 {
		// No DERP regions in non-nil map.
		return 0
	}

	// See where our peers are.
	var (
		peersOnDerp = map[int]int{}
		best        int
		bestCount   int
	)
	for _, as := range c.addrsByKey {
		if id := as.derpID(); id != 0 {
			peersOnDerp[id]++
			if v := peersOnDerp[id]; v > bestCount {
				bestCount = v
				best = id
			}
		}
	}

	// If we already had selected something in the past and it has
	// any peers, stay on it. If there are no peers, though, also
	// stay where we are.
	if c.myDerp != 0 && (best == 0 || peersOnDerp[c.myDerp] != 0) {
		return c.myDerp
	}

	// Otherwise pick wherever the most peers are.
	if best != 0 {
		return best
	}

	// Otherwise just pick something randomly.
	h := fnv.New64()
	h.Write([]byte(fmt.Sprintf("%p/%d", c, processStartUnixNano))) // arbitrary
	return ids[rand.New(rand.NewSource(int64(h.Sum64()))).Intn(len(ids))]
}

// callNetInfoCallback calls the NetInfo callback (if previously
// registered with SetNetInfoCallback) if ni has substantially changed
// since the last state.
//
// callNetInfoCallback takes ownership of ni.
//
// c.mu must NOT be held.
func (c *Conn) callNetInfoCallback(ni *tailcfg.NetInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ni.BasicallyEqual(c.netInfoLast) {
		return
	}
	c.netInfoLast = ni
	if c.netInfoFunc != nil {
		c.logf("magicsock: netInfo update: %+v", ni)
		go c.netInfoFunc(ni)
	}
}

func (c *Conn) SetNetInfoCallback(fn func(*tailcfg.NetInfo)) {
	if fn == nil {
		panic("nil NetInfoCallback")
	}
	c.mu.Lock()
	last := c.netInfoLast
	c.netInfoFunc = fn
	c.mu.Unlock()

	if last != nil {
		fn(last)
	}
}

// c.mu must NOT be held.
func (c *Conn) setNearestDERP(derpNum int) (wantDERP bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.wantDerpLocked() {
		c.myDerp = 0
		return false
	}
	if derpNum == c.myDerp {
		// No change.
		return true
	}
	c.myDerp = derpNum

	if c.privateKey.IsZero() {
		// No private key yet, so DERP connections won't come up anyway.
		// Return early rather than ultimately log a couple lines of noise.
		return true
	}

	// On change, notify all currently connected DERP servers and
	// start connecting to our home DERP if we are not already.
	dr := c.derpMap.Regions[derpNum]
	if dr == nil {
		c.logf("[unexpected] magicsock: derpMap.Regions[%v] is nil", derpNum)
	} else {
		c.logf("magicsock: home is now derp-%v (%v)", derpNum, c.derpMap.Regions[derpNum].RegionCode)
	}
	for i, ad := range c.activeDerp {
		go ad.c.NotePreferred(i == c.myDerp)
	}
	c.goDerpConnect(derpNum)
	return true
}

// goDerpConnect starts a goroutine to start connecting to the given
// DERP node.
//
// c.mu may be held, but does not need to be.
func (c *Conn) goDerpConnect(node int) {
	if node == 0 {
		return
	}
	go c.derpWriteChanOfAddr(&net.UDPAddr{IP: derpMagicIP, Port: node}, key.Public{})
}

// determineEndpoints returns the machine's endpoint addresses. It
// does a STUN lookup (via netcheck) to determine its public address.
//
// c.mu must NOT be held.
func (c *Conn) determineEndpoints(ctx context.Context) (ipPorts []string, reasons map[string]string, err error) {
	nr, err := c.updateNetInfo(ctx)
	if err != nil {
		c.logf("magicsock.Conn.determineEndpoints: updateNetInfo: %v", err)
		return nil, nil, err
	}

	already := make(map[string]string) // endpoint -> how it was found
	var eps []string                   // unique endpoints

	addAddr := func(s, reason string) {
		if _, ok := already[s]; !ok {
			already[s] = reason
			eps = append(eps, s)
		}
	}

	if nr.GlobalV4 != "" {
		addAddr(nr.GlobalV4, "stun")
	}
	if nr.GlobalV6 != "" {
		addAddr(nr.GlobalV6, "stun")
	}

	c.ignoreSTUNPackets()

	if localAddr := c.pconn4.LocalAddr(); localAddr.IP.IsUnspecified() {
		ips, loopback, err := interfaces.LocalAddresses()
		if err != nil {
			return nil, nil, err
		}
		reason := "localAddresses"
		if len(ips) == 0 && len(eps) == 0 {
			// Only include loopback addresses if we have no
			// interfaces at all to use as endpoints and don't
			// have a public IPv4 or IPv6 address. This allows
			// for localhost testing when you're on a plane and
			// offline, for example.
			ips = loopback
			reason = "loopback"
		}
		for _, ipStr := range ips {
			addAddr(net.JoinHostPort(ipStr, fmt.Sprint(localAddr.Port)), reason)
		}
	} else {
		// Our local endpoint is bound to a particular address.
		// Do not offer addresses on other local interfaces.
		addAddr(localAddr.String(), "socket")
	}

	// Note: the endpoints are intentionally returned in priority order,
	// from "farthest but most reliable" to "closest but least
	// reliable." Addresses returned from STUN should be globally
	// addressable, but might go farther on the network than necessary.
	// Local interface addresses might have lower latency, but not be
	// globally addressable.
	//
	// The STUN address(es) are always first so that legacy wireguard
	// can use eps[0] as its only known endpoint address (although that's
	// obviously non-ideal).
	return eps, already, nil
}

func stringsEqual(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func (c *Conn) LocalPort() uint16 {
	laddr := c.pconn4.LocalAddr()
	return uint16(laddr.Port)
}

func shouldSprayPacket(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	msgType := binary.LittleEndian.Uint32(b[:4])
	switch msgType {
	case device.MessageInitiationType,
		device.MessageResponseType,
		device.MessageCookieReplyType: // TODO: necessary?
		return true
	}
	return false
}

var logPacketDests, _ = strconv.ParseBool(os.Getenv("DEBUG_LOG_PACKET_DESTS"))

const sprayPeriod = 3 * time.Second

// appendDests appends to dsts the destinations that b should be
// written to in order to reach as. Some of the returned UDPAddrs may
// be fake addrs representing DERP servers.
//
// It also returns as's current roamAddr, if any.
func (as *AddrSet) appendDests(dsts []*net.UDPAddr, b []byte) (_ []*net.UDPAddr, roamAddr *net.UDPAddr) {
	spray := shouldSprayPacket(b) // true for handshakes
	now := as.timeNow()

	as.mu.Lock()
	defer as.mu.Unlock()

	// Spray logic.
	//
	// After exchanging a handshake with a peer, we send some outbound
	// packets to every endpoint of that peer. These packets are spaced out
	// over several seconds to make sure that our peer has an opportunity to
	// send its own spray packet to us before we are done spraying.
	//
	// Multiple packets are necessary because we have to both establish the
	// NAT mappings between two peers *and use* the mappings to switch away
	// from DERP to a higher-priority UDP endpoint.
	const sprayFreq = 250 * time.Millisecond
	if spray {
		as.lastSpray = now
		as.stopSpray = now.Add(sprayPeriod)

		// Reset our favorite route on new handshakes so we
		// can downgrade to a worse path if our better path
		// goes away. (https://github.com/tailscale/tailscale/issues/92)
		as.curAddr = -1
	} else if now.Before(as.stopSpray) {
		// We are in the spray window. If it has been sprayFreq since we
		// last sprayed a packet, spray this packet.
		if now.Sub(as.lastSpray) >= sprayFreq {
			spray = true
			as.lastSpray = now
		}
	}

	// Pick our destination address(es).
	switch {
	case spray:
		// This packet is being sprayed to all addresses.
		for i := range as.addrs {
			dsts = append(dsts, &as.addrs[i])
		}
		if as.roamAddr != nil {
			dsts = append(dsts, as.roamAddr)
		}
	case as.roamAddr != nil:
		// We have a roaming address, prefer it over other addrs.
		// TODO(danderson): this is not correct, there's no reason
		// roamAddr should be special like this.
		dsts = append(dsts, as.roamAddr)
	case as.curAddr != -1:
		if as.curAddr >= len(as.addrs) {
			as.Logf("[unexpected] magicsock bug: as.curAddr >= len(as.addrs): %d >= %d", as.curAddr, len(as.addrs))
			break
		}
		// No roaming addr, but we've seen packets from a known peer
		// addr, so keep using that one.
		dsts = append(dsts, &as.addrs[as.curAddr])
	default:
		// We know nothing about how to reach this peer, and we're not
		// spraying. Use the first address in the array, which will
		// usually be a DERP address that guarantees connectivity.
		if len(as.addrs) > 0 {
			dsts = append(dsts, &as.addrs[0])
		}
	}

	if logPacketDests {
		as.Logf("spray=%v; roam=%v; dests=%v", spray, as.roamAddr, dsts)
	}
	return dsts, as.roamAddr
}

var errNoDestinations = errors.New("magicsock: no destinations")

func (c *Conn) Send(b []byte, ep conn.Endpoint) error {
	var as *AddrSet
	switch v := ep.(type) {
	default:
		panic(fmt.Sprintf("[unexpected] Endpoint type %T", v))
	case *singleEndpoint:
		addr := (*net.UDPAddr)(v)
		if addr.IP.Equal(derpMagicIP) {
			c.logf("magicsock: [unexpected] DERP BUG: attempting to send packet to DERP address %v", addr)
			return nil
		}
		return c.sendUDP(addr, b)
	case *AddrSet:
		as = v
	}

	var addrBuf [8]*net.UDPAddr
	dsts, roamAddr := as.appendDests(addrBuf[:0], b)

	if len(dsts) == 0 {
		return errNoDestinations
	}

	var success bool
	var ret error
	for _, addr := range dsts {
		err := c.sendAddr(addr, as.publicKey, b)
		if err == nil {
			success = true
		} else if ret == nil {
			ret = err
		}
		if err != nil && addr != roamAddr && c.sendLogLimit.Allow() {
			if c.connCtx.Err() == nil { // don't log if we're closed
				c.logf("magicsock: Conn.Send(%v): %v", addr, err)
			}
		}
	}
	if success {
		return nil
	}
	return ret
}

var errConnClosed = errors.New("Conn closed")

var errDropDerpPacket = errors.New("too many DERP packets queued; dropping")

// sendUDP sends UDP packet b to addr.
func (c *Conn) sendUDP(addr *net.UDPAddr, b []byte) error {
	if addr.IP.To4() != nil {
		_, err := c.pconn4.WriteTo(b, addr)
		if err != nil && c.noV4.Get() {
			return nil
		}
		return err
	}
	if c.pconn6 != nil {
		_, err := c.pconn6.WriteTo(b, addr)
		if err != nil && c.noV6.Get() {
			return nil
		}
		return err
	}
	return nil // ignore IPv6 dest if we don't have an IPv6 address.
}

// sendAddr sends packet b to addr, which is either a real UDP address
// or a fake UDP address representing a DERP server (see derpmap.go).
// The provided public key identifies the recipient.
func (c *Conn) sendAddr(addr *net.UDPAddr, pubKey key.Public, b []byte) error {
	if !addr.IP.Equal(derpMagicIP) {
		return c.sendUDP(addr, b)
	}

	ch := c.derpWriteChanOfAddr(addr, pubKey)
	if ch == nil {
		return nil
	}

	// TODO(bradfitz): this makes garbage for now; we could use a
	// buffer pool later.  Previously we passed ownership of this
	// to derpWriteRequest and waited for derphttp.Client.Send to
	// complete, but that's too slow while holding wireguard-go
	// internal locks.
	pkt := make([]byte, len(b))
	copy(pkt, b)

	select {
	case <-c.donec():
		return errConnClosed
	case ch <- derpWriteRequest{addr, pubKey, pkt}:
		return nil
	default:
		// Too many writes queued. Drop packet.
		return errDropDerpPacket
	}
}

// bufferedDerpWritesBeforeDrop is how many packets writes can be
// queued up the DERP client to write on the wire before we start
// dropping.
//
// TODO: this is currently arbitrary. Figure out something better?
const bufferedDerpWritesBeforeDrop = 32

// debugUseDerpRoute temporarily (2020-03-22) controls whether DERP
// reverse routing is enabled (Issue 150). It will become always true
// later.
var debugUseDerpRoute, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_ENABLE_DERP_ROUTE"))

// derpWriteChanOfAddr returns a DERP client for fake UDP addresses that
// represent DERP servers, creating them as necessary. For real UDP
// addresses, it returns nil.
//
// If peer is non-zero, it can be used to find an active reverse
// path, without using addr.
func (c *Conn) derpWriteChanOfAddr(addr *net.UDPAddr, peer key.Public) chan<- derpWriteRequest {
	if !addr.IP.Equal(derpMagicIP) {
		return nil
	}
	regionID := addr.Port

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.wantDerpLocked() || c.closed {
		return nil
	}
	if c.privateKey.IsZero() {
		c.logf("magicsock: DERP lookup of %v with no private key; ignoring", addr)
		return nil
	}

	// See if we have a connection open to that DERP node ID
	// first. If so, might as well use it. (It's a little
	// arbitrary whether we use this one vs. the reverse route
	// below when we have both.)
	ad, ok := c.activeDerp[regionID]
	if ok {
		*ad.lastWrite = time.Now()
		c.setPeerLastDerpLocked(peer, regionID, regionID)
		return ad.writeCh
	}

	// If we don't have an open connection to the peer's home DERP
	// node, see if we have an open connection to a DERP node
	// where we'd heard from that peer already. For instance,
	// perhaps peer's home is Frankfurt, but they dialed our home DERP
	// node in SF to reach us, so we can reply to them using our
	// SF connection rather than dialing Frankfurt. (Issue 150)
	if !peer.IsZero() && debugUseDerpRoute {
		if r, ok := c.derpRoute[peer]; ok {
			if ad, ok := c.activeDerp[r.derpID]; ok && ad.c == r.dc {
				c.setPeerLastDerpLocked(peer, r.derpID, regionID)
				*ad.lastWrite = time.Now()
				return ad.writeCh
			}
		}
	}

	why := "home-keep-alive"
	if !peer.IsZero() {
		why = peerShort(peer)
	}
	c.logf("magicsock: adding connection to derp-%v for %v", regionID, why)

	firstDerp := false
	if c.activeDerp == nil {
		firstDerp = true
		c.activeDerp = make(map[int]activeDerp)
		c.prevDerp = make(map[int]*syncs.WaitGroupChan)
	}
	if c.derpMap == nil || c.derpMap.Regions[regionID] == nil {
		return nil
	}

	// Note that derphttp.NewClient does not dial the server
	// so it is safe to do under the mu lock.
	dc := derphttp.NewRegionClient(c.privateKey, c.logf, func() *tailcfg.DERPRegion {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.derpMap == nil {
			return nil
		}
		return c.derpMap.Regions[regionID]
	})

	dc.NotePreferred(c.myDerp == regionID)
	dc.DNSCache = dnscache.Get()

	ctx, cancel := context.WithCancel(c.connCtx)
	ch := make(chan derpWriteRequest, bufferedDerpWritesBeforeDrop)

	ad.c = dc
	ad.writeCh = ch
	ad.cancel = cancel
	ad.lastWrite = new(time.Time)
	*ad.lastWrite = time.Now()
	ad.createTime = time.Now()
	c.activeDerp[regionID] = ad
	c.logActiveDerpLocked()
	c.setPeerLastDerpLocked(peer, regionID, regionID)

	// Build a startGate for the derp reader+writer
	// goroutines, so they don't start running until any
	// previous generation is closed.
	startGate := syncs.ClosedChan()
	if prev := c.prevDerp[regionID]; prev != nil {
		startGate = prev.DoneChan()
	}
	// And register a WaitGroup(Chan) for this generation.
	wg := syncs.NewWaitGroupChan()
	wg.Add(2)
	c.prevDerp[regionID] = wg

	if firstDerp {
		startGate = c.derpStarted
		go func() {
			dc.Connect(ctx)
			close(c.derpStarted)
		}()
	}

	go c.runDerpReader(ctx, addr, dc, wg, startGate)
	go c.runDerpWriter(ctx, addr, dc, ch, wg, startGate)

	return ad.writeCh
}

// setPeerLastDerpLocked notes that peer is now being written to via
// the provided DERP regionID, and that the peer advertises a DERP
// home region ID of homeID.
//
// If there's any change, it logs.
//
// c.mu must be held.
func (c *Conn) setPeerLastDerpLocked(peer key.Public, regionID, homeID int) {
	if peer.IsZero() {
		return
	}
	old := c.peerLastDerp[peer]
	if old == regionID {
		return
	}
	c.peerLastDerp[peer] = regionID

	var newDesc string
	switch {
	case regionID == homeID && regionID == c.myDerp:
		newDesc = "shared home"
	case regionID == homeID:
		newDesc = "their home"
	case regionID == c.myDerp:
		newDesc = "our home"
	case regionID != homeID:
		newDesc = "alt"
	}
	if old == 0 {
		c.logf("magicsock: derp route for %s set to derp-%d (%s)", peerShort(peer), regionID, newDesc)
	} else {
		c.logf("magicsock: derp route for %s changed from derp-%d => derp-%d (%s)", peerShort(peer), old, regionID, newDesc)
	}
}

// derpReadResult is the type sent by runDerpClient to ReceiveIPv4
// when a DERP packet is available.
//
// Notably, it doesn't include the derp.ReceivedPacket because we
// don't want to give the receiver access to the aliased []byte.  To
// get at the packet contents they need to call copyBuf to copy it
// out, which also releases the buffer.
type derpReadResult struct {
	derpAddr *net.UDPAddr
	n        int        // length of data received
	src      key.Public // may be zero until server deployment if v2+
	// copyBuf is called to copy the data to dst.  It returns how
	// much data was copied, which will be n if dst is large
	// enough. copyBuf can only be called once.
	copyBuf func(dst []byte) int
}

var logDerpVerbose, _ = strconv.ParseBool(os.Getenv("DEBUG_DERP_VERBOSE"))

// runDerpReader runs in a goroutine for the life of a DERP
// connection, handling received packets.
func (c *Conn) runDerpReader(ctx context.Context, derpFakeAddr *net.UDPAddr, dc *derphttp.Client, wg *syncs.WaitGroupChan, startGate <-chan struct{}) {
	defer wg.Decr()
	defer dc.Close()

	select {
	case <-startGate:
	case <-ctx.Done():
		return
	}

	didCopy := make(chan struct{}, 1)
	var buf [derp.MaxPacketSize]byte

	res := derpReadResult{derpAddr: derpFakeAddr}
	var pkt derp.ReceivedPacket
	res.copyBuf = func(dst []byte) int {
		n := copy(dst, pkt.Data)
		didCopy <- struct{}{}
		return n
	}

	// peerPresent is the set of senders we know are present on this
	// connection, based on messages we've received from the server.
	peerPresent := map[key.Public]bool{}

	for {
		msg, err := dc.Recv(buf[:])
		if err == derphttp.ErrClientClosed {
			return
		}
		if err != nil {
			// Forget that all these peers have routes.
			for peer := range peerPresent {
				delete(peerPresent, peer)
				c.removeDerpPeerRoute(peer, derpFakeAddr.Port, dc)
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			c.ReSTUN("derp-close")
			c.logf("magicsock: [%p] derp.Recv(derp-%d): %v", dc, derpFakeAddr.Port, err)
			time.Sleep(250 * time.Millisecond)
			continue
		}
		switch m := msg.(type) {
		case derp.ReceivedPacket:
			pkt = m
			res.n = len(m.Data)
			res.src = m.Source
			if logDerpVerbose {
				c.logf("magicsock: got derp-%v packet: %q", derpFakeAddr, m.Data)
			}
			// If this is a new sender we hadn't seen before, remember it and
			// register a route for this peer.
			if _, ok := peerPresent[m.Source]; !ok {
				peerPresent[m.Source] = true
				c.addDerpPeerRoute(m.Source, derpFakeAddr.Port, dc)
			}
		default:
			// Ignore.
			// TODO: handle endpoint notification messages.
			continue
		}
		select {
		case <-ctx.Done():
			return
		case c.derpRecvCh <- res:
			<-didCopy
		}
	}
}

type derpWriteRequest struct {
	addr   *net.UDPAddr
	pubKey key.Public
	b      []byte // copied; ownership passed to receiver
}

// runDerpWriter runs in a goroutine for the life of a DERP
// connection, handling received packets.
func (c *Conn) runDerpWriter(ctx context.Context, derpFakeAddr *net.UDPAddr, dc *derphttp.Client, ch <-chan derpWriteRequest, wg *syncs.WaitGroupChan, startGate <-chan struct{}) {
	defer wg.Decr()
	select {
	case <-startGate:
	case <-ctx.Done():
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case wr := <-ch:
			err := dc.Send(wr.pubKey, wr.b)
			if err != nil {
				c.logf("magicsock: derp.Send(%v): %v", wr.addr, err)
			}
		}
	}
}

// findEndpoint maps from a UDP address to a WireGuard endpoint, for
// ReceiveIPv4/ReceiveIPv6.
func (c *Conn) findEndpoint(addr *net.UDPAddr) conn.Endpoint {
	if as := c.findAddrSet(addr); as != nil {
		return as
	}
	// The peer that sent this packet has roamed beyond the
	// knowledge provided by the control server.
	// If the packet is valid wireguard will call UpdateDst
	// on the original endpoint using this addr.
	return (*singleEndpoint)(addr)
}

func (c *Conn) findAddrSet(addr *net.UDPAddr) *AddrSet {
	ip, ok := netaddr.FromStdIP(addr.IP)
	if !ok {
		return nil
	}
	ipp := netaddr.IPPort{ip, uint16(addr.Port)}

	c.mu.Lock()
	defer c.mu.Unlock()

	return c.addrsByUDP[ipp]
}

type udpReadResult struct {
	_    structs.Incomparable
	n    int
	err  error
	addr *net.UDPAddr
}

// aLongTimeAgo is a non-zero time, far in the past, used for
// immediate cancellation of network operations.
var aLongTimeAgo = time.Unix(233431200, 0)

// awaitUDP4 reads a single IPv4 UDP packet (or an error) and sends it
// to c.udpRecvCh, skipping over (but handling) any STUN replies.
func (c *Conn) awaitUDP4(b []byte) {
	for {
		n, pAddr, err := c.pconn4.ReadFrom(b)
		if err != nil {
			select {
			case c.udpRecvCh <- udpReadResult{err: err}:
			case <-c.donec():
			}
			return
		}
		addr := pAddr.(*net.UDPAddr)
		if stun.Is(b[:n]) {
			c.stunReceiveFunc.Load().(func([]byte, *net.UDPAddr))(b[:n], addr)
			continue
		}

		addr.IP = addr.IP.To4()
		select {
		case c.udpRecvCh <- udpReadResult{n: n, addr: addr}:
		case <-c.donec():
		}
		return
	}

}

func (c *Conn) ReceiveIPv4(b []byte) (n int, ep conn.Endpoint, addr *net.UDPAddr, err error) {
	// First, process any buffered packet from earlier.
	if addr := c.bufferedIPv4From; addr != nil {
		c.bufferedIPv4From = nil
		return copy(b, c.bufferedIPv4Packet), c.findEndpoint(addr), addr, nil
	}

	go c.awaitUDP4(b)

	// Once the above goroutine has started, it owns b until it writes
	// to udpRecvCh. The code below must not access b until it's
	// completed a successful receive on udpRecvCh.

	var addrSet *AddrSet

	select {
	case dm := <-c.derpRecvCh:
		// Cancel the pconn read goroutine
		c.pconn4.SetReadDeadline(aLongTimeAgo)
		// Wait for the UDP-reading goroutine to be done, since it's currently
		// the owner of the b []byte buffer:
		select {
		case um := <-c.udpRecvCh:
			if um.err != nil {
				// The normal case. The SetReadDeadline interrupted
				// the read and we get an error which we now ignore.
			} else {
				// The pconn.ReadFrom succeeded and was about to send,
				// but DERP sent first. So now we have both ready.
				// Save the UDP packet away for use by the next
				// ReceiveIPv4 call.
				c.bufferedIPv4From = um.addr
				c.bufferedIPv4Packet = append(c.bufferedIPv4Packet[:0], b[:um.n]...)
			}
			c.pconn4.SetReadDeadline(time.Time{})
		case <-c.donec():
			return 0, nil, nil, errors.New("Conn closed")
		}
		n, addr = dm.n, dm.derpAddr
		ncopy := dm.copyBuf(b)
		if ncopy != n {
			err = fmt.Errorf("received DERP packet of length %d that's too big for WireGuard ReceiveIPv4 buf size %d", n, ncopy)
			c.logf("magicsock: %v", err)
			return 0, nil, nil, err
		}

		c.mu.Lock()
		addrSet = c.addrsByKey[dm.src]
		c.mu.Unlock()

		if addrSet == nil {
			key := wgcfg.Key(dm.src)
			c.logf("magicsock: DERP packet from unknown key: %s", key.ShortString())
		}

	case um := <-c.udpRecvCh:
		if um.err != nil {
			return 0, nil, nil, err
		}
		n, addr = um.n, um.addr

	case <-c.donec():
		// Socket has been shut down. All the producers of packets
		// respond to the context cancellation and go away, so we have
		// to also unblock and return an error, to inform wireguard-go
		// that this socket has gone away.
		//
		// Specifically, wireguard-go depends on its bind.Conn having
		// the standard socket behavior, which is that a Close()
		// unblocks any concurrent Read()s. wireguard-go itself calls
		// Clos() on magicsock, and expects ReceiveIPv4 to unblock
		// with an error so it can clean up.
		return 0, nil, nil, errors.New("socket closed")
	}

	if addrSet != nil {
		ep = addrSet
	} else {
		ep = c.findEndpoint(addr)
	}
	return n, ep, addr, nil
}

func (c *Conn) ReceiveIPv6(b []byte) (int, conn.Endpoint, *net.UDPAddr, error) {
	if c.pconn6 == nil {
		return 0, nil, nil, syscall.EAFNOSUPPORT
	}
	for {
		n, pAddr, err := c.pconn6.ReadFrom(b)
		if err != nil {
			return 0, nil, nil, err
		}
		addr := pAddr.(*net.UDPAddr)
		if stun.Is(b[:n]) {
			c.stunReceiveFunc.Load().(func([]byte, *net.UDPAddr))(b[:n], addr)
			continue
		}
		ep := c.findEndpoint(addr)
		return n, ep, addr, nil
	}
}

// SetPrivateKey sets the connection's private key.
//
// This is only used to be able prove our identity when connecting to
// DERP servers.
//
// If the private key changes, any DERP connections are torn down &
// recreated when needed.
func (c *Conn) SetPrivateKey(privateKey wgcfg.PrivateKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldKey, newKey := c.privateKey, key.Private(privateKey)
	if newKey == oldKey {
		return nil
	}
	c.privateKey = newKey

	if oldKey.IsZero() {
		c.logf("magicsock: SetPrivateKey called (init)")
		go c.ReSTUN("set-private-key")
	} else {
		c.logf("magicsock: SetPrivateKey called (changed")
	}
	c.closeAllDerpLocked("new-private-key")

	// Key changed. Close existing DERP connections and reconnect to home.
	if c.myDerp != 0 {
		c.logf("magicsock: private key changed, reconnecting to home derp-%d", c.myDerp)
		c.goDerpConnect(c.myDerp)
	}

	return nil
}

// UpdatePeers is called when the set of WireGuard peers changes. It
// then removes any state for old peers.
//
// The caller passes ownership of newPeers map to UpdatePeers.
func (c *Conn) UpdatePeers(newPeers map[key.Public]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldPeers := c.peerSet
	c.peerSet = newPeers

	// Clean up any key.Public-keyed maps for peers that no longer
	// exist.
	for peer := range oldPeers {
		if _, ok := newPeers[peer]; !ok {
			delete(c.addrsByKey, peer)
			delete(c.derpRoute, peer)
			delete(c.peerLastDerp, peer)
		}
	}

	if len(oldPeers) == 0 && len(newPeers) > 0 {
		go c.ReSTUN("non-zero-peers")
	}
}

// SetDERPMap controls which (if any) DERP servers are used.
// A nil value means to disable DERP; it's disabled by default.
func (c *Conn) SetDERPMap(dm *tailcfg.DERPMap) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if reflect.DeepEqual(dm, c.derpMap) {
		return
	}

	c.derpMap = dm
	if dm == nil {
		c.closeAllDerpLocked("derp-disabled")
		return
	}

	go c.ReSTUN("derp-map-update")
}

func (c *Conn) wantDerpLocked() bool { return c.derpMap != nil }

// c.mu must be held.
func (c *Conn) closeAllDerpLocked(why string) {
	if len(c.activeDerp) == 0 {
		return // without the useless log statement
	}
	for i := range c.activeDerp {
		c.closeDerpLocked(i, why)
	}
	c.logActiveDerpLocked()
}

// c.mu must be held.
// It is the responsibility of the caller to call logActiveDerpLocked after any set of closes.
func (c *Conn) closeDerpLocked(node int, why string) {
	if ad, ok := c.activeDerp[node]; ok {
		c.logf("magicsock: closing connection to derp-%v (%v), age %v", node, why, time.Since(ad.createTime).Round(time.Second))
		go ad.c.Close()
		ad.cancel()
		delete(c.activeDerp, node)
	}
}

// c.mu must be held.
func (c *Conn) logActiveDerpLocked() {
	now := time.Now()
	c.logf("magicsock: %v active derp conns%s", len(c.activeDerp), logger.ArgWriter(func(buf *bufio.Writer) {
		if len(c.activeDerp) == 0 {
			return
		}
		buf.WriteString(":")
		c.foreachActiveDerpSortedLocked(func(node int, ad activeDerp) {
			fmt.Fprintf(buf, " derp-%d=cr%v,wr%v", node, simpleDur(now.Sub(ad.createTime)), simpleDur(now.Sub(*ad.lastWrite)))
		})
	}))
}

func (c *Conn) logEndpointChange(endpoints []string, reasons map[string]string) {
	c.logf("magicsock: endpoints changed: %s", logger.ArgWriter(func(buf *bufio.Writer) {
		for i, ep := range endpoints {
			if i > 0 {
				buf.WriteString(", ")
			}
			fmt.Fprintf(buf, "%s (%s)", ep, reasons[ep])
		}
	}))
}

// c.mu must be held.
func (c *Conn) foreachActiveDerpSortedLocked(fn func(regionID int, ad activeDerp)) {
	if len(c.activeDerp) < 2 {
		for id, ad := range c.activeDerp {
			fn(id, ad)
		}
		return
	}
	ids := make([]int, 0, len(c.activeDerp))
	for id := range c.activeDerp {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		fn(id, c.activeDerp[id])
	}
}

func (c *Conn) cleanStaleDerp() {
	c.mu.Lock()
	defer c.mu.Unlock()
	const inactivityTime = 60 * time.Second
	tooOld := time.Now().Add(-inactivityTime)
	dirty := false
	for i, ad := range c.activeDerp {
		if i == c.myDerp {
			continue
		}
		if ad.lastWrite.Before(tooOld) {
			c.closeDerpLocked(i, "idle")
			dirty = true
		}
	}
	if dirty {
		c.logActiveDerpLocked()
	}
}

// DERPs reports the number of active DERP connections.
func (c *Conn) DERPs() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.activeDerp)
}

func (c *Conn) SetMark(value uint32) error { return nil }
func (c *Conn) LastMark() uint32           { return 0 }

// Close closes the connection.
//
// Only the first close does anything. Any later closes return nil.
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	defer c.mu.Unlock()

	c.closed = true
	c.connCtxCancel()
	c.closeAllDerpLocked("conn-close")
	if c.pconn6 != nil {
		c.pconn6.Close()
	}
	err := c.pconn4.Close()
	// Wait on endpoints updating right at the end, once everything is
	// already closed. We want everything else in the Conn to be
	// consistently in the closed state before we release mu to wait
	// on the endpoint updater.
	for c.endpointsUpdateActive {
		c.endpointsUpdateWaiter.Wait()
	}
	return err
}

func (c *Conn) haveAnyPeers() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.peerSet) > 0
}

func (c *Conn) periodicReSTUN() {
	prand := rand.New(rand.NewSource(time.Now().UnixNano()))
	dur := func() time.Duration {
		// Just under 30s, a common UDP NAT timeout (Linux at least)
		return time.Duration(20+prand.Intn(7)) * time.Second
	}
	timer := time.NewTimer(dur())
	defer timer.Stop()
	for {
		select {
		case <-c.donec():
			return
		case <-timer.C:
			if c.haveAnyPeers() {
				c.ReSTUN("periodic")
			}
			timer.Reset(dur())
		}
	}
}

func (c *Conn) periodicDerpCleanup() {
	ticker := time.NewTicker(15 * time.Second) // arbitrary
	defer ticker.Stop()
	for {
		select {
		case <-c.donec():
			return
		case <-ticker.C:
			c.cleanStaleDerp()
		}
	}
}

// ReSTUN triggers an address discovery.
// The provided why string is for debug logging only.
func (c *Conn) ReSTUN(why string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		panic("call to ReSTUN before Start")
	}
	if c.closed {
		// raced with a shutdown.
		return
	}

	if c.endpointsUpdateActive {
		if c.wantEndpointsUpdate != why {
			c.logf("magicsock: ReSTUN: endpoint update active, need another later (%q)", why)
			c.wantEndpointsUpdate = why
		}
	} else {
		c.endpointsUpdateActive = true
		go c.updateEndpoints(why)
	}
}

func (c *Conn) initialBind() error {
	if err := c.bind1(&c.pconn4, "udp4"); err != nil {
		return err
	}
	if err := c.bind1(&c.pconn6, "udp6"); err != nil {
		c.logf("magicsock: ignoring IPv6 bind failure: %v", err)
	}
	return nil
}

func (c *Conn) bind1(ruc **RebindingUDPConn, which string) error {
	host := ""
	if v, _ := strconv.ParseBool(os.Getenv("IN_TS_TEST")); v {
		host = "127.0.0.1"
	}
	var pc net.PacketConn
	var err error
	listenCtx := context.Background() // unused without DNS name to resolve
	if c.pconnPort == 0 && DefaultPort != 0 {
		pc, err = netns.Listener().ListenPacket(listenCtx, which, fmt.Sprintf("%s:%d", host, DefaultPort))
		if err != nil {
			c.logf("magicsock: bind: default port %s/%v unavailable; picking random", which, DefaultPort)
		}
	}
	if pc == nil {
		pc, err = netns.Listener().ListenPacket(listenCtx, which, fmt.Sprintf("%s:%d", host, c.pconnPort))
	}
	if err != nil {
		c.logf("magicsock: bind(%s/%v): %v", which, c.pconnPort, err)
		return fmt.Errorf("magicsock: bind: %s/%d: %v", which, c.pconnPort, err)
	}
	if *ruc == nil {
		*ruc = new(RebindingUDPConn)
	}
	(*ruc).Reset(pc.(*net.UDPConn))
	return nil
}

// Rebind closes and re-binds the UDP sockets.
// It should be followed by a call to ReSTUN.
func (c *Conn) Rebind() {
	host := ""
	if v, _ := strconv.ParseBool(os.Getenv("IN_TS_TEST")); v {
		host = "127.0.0.1"
	}
	listenCtx := context.Background() // unused without DNS name to resolve
	if c.pconnPort != 0 {
		c.pconn4.mu.Lock()
		if err := c.pconn4.pconn.Close(); err != nil {
			c.logf("magicsock: link change close failed: %v", err)
		}
		packetConn, err := netns.Listener().ListenPacket(listenCtx, "udp4", fmt.Sprintf("%s:%d", host, c.pconnPort))
		if err == nil {
			c.logf("magicsock: link change rebound port: %d", c.pconnPort)
			c.pconn4.pconn = packetConn.(*net.UDPConn)
			c.pconn4.mu.Unlock()
			return
		}
		c.logf("magicsock: link change unable to bind fixed port %d: %v, falling back to random port", c.pconnPort, err)
		c.pconn4.mu.Unlock()
	}
	c.logf("magicsock: link change, binding new port")
	packetConn, err := netns.Listener().ListenPacket(listenCtx, "udp4", host+":0")
	if err != nil {
		c.logf("magicsock: link change failed to bind new port: %v", err)
		return
	}
	c.pconn4.Reset(packetConn.(*net.UDPConn))

	c.mu.Lock()
	c.closeAllDerpLocked("rebind")
	c.mu.Unlock()
	c.goDerpConnect(c.myDerp)
	c.resetAddrSetStates()
}

// resetAddrSetStates resets the preferred address for all peers and
// re-enables spraying.
// This is called when connectivity changes enough that we no longer
// trust the old routes.
func (c *Conn) resetAddrSetStates() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, as := range c.addrsByKey {
		as.curAddr = -1
		as.stopSpray = as.timeNow().Add(sprayPeriod)
	}
}

// AddrSet is a set of UDP addresses that implements wireguard/conn.Endpoint.
type AddrSet struct {
	publicKey key.Public // peer public key used for DERP communication

	// addrs is an ordered priority list provided by wgengine,
	// sorted from expensive+slow+reliable at the begnining to
	// fast+cheap at the end. More concretely, it's typically:
	//
	//     [DERP fakeip:node, Global IP:port, LAN ip:port]
	//
	// But there could be multiple or none of each.
	addrs   []net.UDPAddr
	ipPorts []netaddr.IPPort // same as addrs, in different form

	// clock, if non-nil, is used in tests instead of time.Now.
	clock func() time.Time
	Logf  logger.Logf // must not be nil

	mu sync.Mutex // guards following fields

	// roamAddr is non-nil if/when we receive a correctly signed
	// WireGuard packet from an unexpected address. If so, we
	// remember it and send responses there in the future, but
	// this should hopefully never be used (or at least used
	// rarely) in the case that all the components of Tailscale
	// are correctly learning/sharing the network map details.
	roamAddr *net.UDPAddr

	// curAddr is an index into addrs of the highest-priority
	// address a valid packet has been received from so far.
	// If no valid packet from addrs has been received, curAddr is -1.
	curAddr int

	// stopSpray is the time after which we stop spraying packets.
	stopSpray time.Time

	// lastSpray is the last time we sprayed a packet.
	lastSpray time.Time
}

// derpID returns this AddrSet's home DERP node, or 0 if none is found.
func (as *AddrSet) derpID() int {
	for _, ua := range as.addrs {
		if ua.IP.Equal(derpMagicIP) {
			return ua.Port
		}
	}
	return 0
}

func (as *AddrSet) timeNow() time.Time {
	if as.clock != nil {
		return as.clock()
	}
	return time.Now()
}

var noAddr = &net.UDPAddr{
	IP:   net.ParseIP("127.127.127.127"),
	Port: 127,
}

func (a *AddrSet) dst() *net.UDPAddr {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddr != nil {
		return a.roamAddr
	}
	if len(a.addrs) == 0 {
		return noAddr
	}
	i := a.curAddr
	if i == -1 {
		i = 0
	}
	return &a.addrs[i]
}

// packUDPAddr packs a UDPAddr in the form wanted by WireGuard.
func packUDPAddr(ua *net.UDPAddr) []byte {
	ip := ua.IP.To4()
	if ip == nil {
		ip = ua.IP
	}
	b := make([]byte, 0, len(ip)+2)
	b = append(b, ip...)
	b = append(b, byte(ua.Port))
	b = append(b, byte(ua.Port>>8))
	return b
}

func (a *AddrSet) DstToBytes() []byte {
	return packUDPAddr(a.dst())
}
func (a *AddrSet) DstToString() string {
	dst := a.dst()
	return dst.String()
}
func (a *AddrSet) DstIP() net.IP {
	return a.dst().IP
}
func (a *AddrSet) SrcIP() net.IP       { return nil }
func (a *AddrSet) SrcToString() string { return "" }
func (a *AddrSet) ClearSrc()           {}

func (a *AddrSet) UpdateDst(new *net.UDPAddr) error {
	if new.IP.Equal(derpMagicIP) {
		// Never consider DERP addresses as a viable candidate for
		// either curAddr or roamAddr. It's only ever a last resort
		// choice, never a preferred choice.
		// This is a hot path for established connections.
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddr != nil && equalUDPAddr(new, a.roamAddr) {
		// Packet from the current roaming address, no logging.
		// This is a hot path for established connections.
		return nil
	}
	if a.roamAddr == nil && a.curAddr >= 0 && equalUDPAddr(new, &a.addrs[a.curAddr]) {
		// Packet from current-priority address, no logging.
		// This is a hot path for established connections.
		return nil
	}

	index := -1
	for i := range a.addrs {
		if equalUDPAddr(new, &a.addrs[i]) {
			index = i
			break
		}
	}

	publicKey := wgcfg.Key(a.publicKey)
	pk := publicKey.ShortString()
	old := "<none>"
	if a.curAddr >= 0 {
		old = a.addrs[a.curAddr].String()
	}

	switch {
	case index == -1:
		if a.roamAddr == nil {
			a.Logf("magicsock: rx %s from roaming address %s, set as new priority", pk, new)
		} else {
			a.Logf("magicsock: rx %s from roaming address %s, replaces roaming address %s", pk, new, a.roamAddr)
		}
		a.roamAddr = new

	case a.roamAddr != nil:
		a.Logf("magicsock: rx %s from known %s (%d), replaces roaming address %s", pk, new, index, a.roamAddr)
		a.roamAddr = nil
		a.curAddr = index

	case a.curAddr == -1:
		a.Logf("magicsock: rx %s from %s (%d/%d), set as new priority", pk, new, index, len(a.addrs))
		a.curAddr = index

	case index < a.curAddr:
		a.Logf("magicsock: rx %s from low-pri %s (%d), keeping current %s (%d)", pk, new, index, old, a.curAddr)

	default: // index > a.curAddr
		a.Logf("magicsock: rx %s from %s (%d/%d), replaces old priority %s", pk, new, index, len(a.addrs), old)
		a.curAddr = index
	}

	return nil
}

func equalUDPAddr(x, y *net.UDPAddr) bool {
	return x.Port == y.Port && x.IP.Equal(y.IP)
}

func (a *AddrSet) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	buf := new(strings.Builder)
	buf.WriteByte('[')
	if a.roamAddr != nil {
		buf.WriteString("roam:")
		sbPrintAddr(buf, *a.roamAddr)
	}
	for i, addr := range a.addrs {
		if i > 0 || a.roamAddr != nil {
			buf.WriteString(", ")
		}
		sbPrintAddr(buf, addr)
		if a.curAddr == i {
			buf.WriteByte('*')
		}
	}
	buf.WriteByte(']')

	return buf.String()
}

func (a *AddrSet) Addrs() []wgcfg.Endpoint {
	var eps []wgcfg.Endpoint
	for _, addr := range a.addrs {
		eps = append(eps, wgcfg.Endpoint{
			Host: addr.IP.String(),
			Port: uint16(addr.Port),
		})
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.roamAddr != nil {
		eps = append(eps, wgcfg.Endpoint{
			Host: a.roamAddr.IP.String(),
			Port: uint16(a.roamAddr.Port),
		})
	}
	return eps
}

// CreateBind is called by WireGuard to create a UDP binding.
func (c *Conn) CreateBind(uint16) (conn.Bind, uint16, error) {
	return c, c.LocalPort(), nil
}

// CreateEndpoint is called by WireGuard to connect to an endpoint.
// The key is the public key of the peer and addrs is a
// comma-separated list of UDP ip:ports.
func (c *Conn) CreateEndpoint(pubKey [32]byte, addrs string) (conn.Endpoint, error) {
	pk := key.Public(pubKey)
	c.logf("magicsock: CreateEndpoint: key=%s: %s", pk.ShortString(), strings.ReplaceAll(addrs, "127.3.3.40:", "derp-"))
	a := &AddrSet{
		Logf:      c.logf,
		publicKey: pk,
		curAddr:   -1,
	}

	if addrs != "" {
		for _, ep := range strings.Split(addrs, ",") {
			ua, err := net.ResolveUDPAddr("udp", ep)
			if err != nil {
				return nil, err
			}
			ipp, ok := netaddr.FromStdAddr(ua.IP, ua.Port, ua.Zone)
			if !ok {
				return nil, fmt.Errorf("bogus address %q", ep)
			}
			ua.IP = ipp.IP.IPAddr().IP // makes IPv4 addresses 4 bytes long
			a.ipPorts = append(a.ipPorts, ipp)
			a.addrs = append(a.addrs, *ua)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// If this endpoint is being updated, remember its old set of
	// endpoints so we can remove any (from c.addrsByUDP) that are
	// not in the new set.
	var oldIPP []netaddr.IPPort
	if preva, ok := c.addrsByKey[pk]; ok {
		oldIPP = preva.ipPorts
	}
	c.addrsByKey[pk] = a

	// Add entries to c.addrsByUDP.
	for _, ipp := range a.ipPorts {
		if ipp.IP == derpMagicIPAddr {
			continue
		}
		c.addrsByUDP[ipp] = a
	}

	// Remove previous c.addrsByUDP entries that are no longer in the new set.
	for _, ipp := range oldIPP {
		if ipp.IP != derpMagicIPAddr && c.addrsByUDP[ipp] != a {
			delete(c.addrsByUDP, ipp)
		}
	}

	return a, nil
}

type singleEndpoint net.UDPAddr

func (e *singleEndpoint) ClearSrc()           {}
func (e *singleEndpoint) DstIP() net.IP       { return (*net.UDPAddr)(e).IP }
func (e *singleEndpoint) SrcIP() net.IP       { return nil }
func (e *singleEndpoint) SrcToString() string { return "" }
func (e *singleEndpoint) DstToString() string { return (*net.UDPAddr)(e).String() }
func (e *singleEndpoint) DstToBytes() []byte  { return packUDPAddr((*net.UDPAddr)(e)) }
func (e *singleEndpoint) UpdateDst(dst *net.UDPAddr) error {
	return fmt.Errorf("magicsock.singleEndpoint(%s).UpdateDst(%s): should never be called", (*net.UDPAddr)(e), dst)
}
func (e *singleEndpoint) Addrs() []wgcfg.Endpoint {
	return []wgcfg.Endpoint{{
		Host: e.IP.String(),
		Port: uint16(e.Port),
	}}
}

// RebindingUDPConn is a UDP socket that can be re-bound.
// Unix has no notion of re-binding a socket, so we swap it out for a new one.
type RebindingUDPConn struct {
	mu    sync.Mutex
	pconn *net.UDPConn
}

func (c *RebindingUDPConn) Reset(pconn *net.UDPConn) {
	c.mu.Lock()
	old := c.pconn
	c.pconn = pconn
	c.mu.Unlock()

	if old != nil {
		old.Close()
	}
}

func (c *RebindingUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		pconn := c.pconn
		c.mu.Unlock()

		n, addr, err := pconn.ReadFrom(b)
		if err != nil {
			c.mu.Lock()
			pconn2 := c.pconn
			c.mu.Unlock()

			if pconn != pconn2 {
				continue
			}
		}
		return n, addr, err
	}
}

func (c *RebindingUDPConn) LocalAddr() *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pconn.LocalAddr().(*net.UDPAddr)
}

func (c *RebindingUDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pconn.Close()
}

func (c *RebindingUDPConn) SetReadDeadline(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pconn.SetReadDeadline(t)
}

func (c *RebindingUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	for {
		c.mu.Lock()
		pconn := c.pconn
		c.mu.Unlock()

		n, err := pconn.WriteToUDP(b, addr)
		if err != nil {
			c.mu.Lock()
			pconn2 := c.pconn
			c.mu.Unlock()

			if pconn != pconn2 {
				continue
			}
		}
		return n, err
	}
}

func (c *RebindingUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	for {
		c.mu.Lock()
		pconn := c.pconn
		c.mu.Unlock()

		n, err := pconn.WriteTo(b, addr)
		if err != nil {
			c.mu.Lock()
			pconn2 := c.pconn
			c.mu.Unlock()

			if pconn != pconn2 {
				continue
			}
		}
		return n, err
	}
}

// simpleDur rounds d such that it stringifies to something short.
func simpleDur(d time.Duration) time.Duration {
	if d < time.Second {
		return d.Round(time.Millisecond)
	}
	if d < time.Minute {
		return d.Round(time.Second)
	}
	return d.Round(time.Minute)
}

func peerShort(k key.Public) string {
	k2 := wgcfg.Key(k)
	return k2.ShortString()
}

func sbPrintAddr(sb *strings.Builder, a net.UDPAddr) {
	is6 := a.IP.To4() == nil
	if is6 {
		sb.WriteByte('[')
	}
	fmt.Fprintf(sb, "%s", a.IP)
	if is6 {
		sb.WriteByte(']')
	}
	fmt.Fprintf(sb, ":%d", a.Port)
}

func (c *Conn) UpdateStatus(sb *ipnstate.StatusBuilder) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, as := range c.addrsByKey {
		ps := &ipnstate.PeerStatus{
			InMagicSock: true,
		}
		for i, ua := range as.addrs {
			uaStr := udpAddrDebugString(ua)
			ps.Addrs = append(ps.Addrs, uaStr)
			if as.curAddr == i {
				ps.CurAddr = uaStr
			}
		}
		if as.roamAddr != nil {
			ps.CurAddr = udpAddrDebugString(*as.roamAddr)
		}
		sb.AddPeer(k, ps)
	}

	c.foreachActiveDerpSortedLocked(func(node int, ad activeDerp) {
		// TODO(bradfitz): add to ipnstate.StatusBuilder
		//f("<li><b>derp-%v</b>: cr%v,wr%v</li>", node, simpleDur(now.Sub(ad.createTime)), simpleDur(now.Sub(*ad.lastWrite)))
	})
}

func udpAddrDebugString(ua net.UDPAddr) string {
	if ua.IP.Equal(derpMagicIP) {
		return fmt.Sprintf("derp-%d", ua.Port)
	}
	return ua.String()
}
