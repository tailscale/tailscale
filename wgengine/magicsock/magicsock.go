// Copyright (c) 2019 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package magicsock implements a socket that can change its communication path while
// in use, actively searching for the best way to communicate.
package magicsock

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
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

	"github.com/golang/groupcache/lru"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/wgcfg"
	"go4.org/mem"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/time/rate"
	"inet.af/netaddr"
	"tailscale.com/control/controlclient"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/disco"
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
	"tailscale.com/types/nettype"
	"tailscale.com/types/opt"
	"tailscale.com/types/structs"
	"tailscale.com/version"
)

// Various debugging and experimental tweakables, set by environment
// variable.
var (
	// logPacketDests prints the known addresses for a peer every time
	// they change, in the legacy (non-discovery) endpoint code only.
	logPacketDests, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_LOG_PACKET_DESTS"))
	// debugDisco prints verbose logs of active discovery events as
	// they happen.
	debugDisco, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_DISCO"))
	// debugOmitLocalAddresses removes all local interface addresses
	// from magicsock's discovered local endpoints. Used in some tests.
	debugOmitLocalAddresses, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_OMIT_LOCAL_ADDRS"))
	// debugUseDerpRoute temporarily (2020-03-22) controls whether DERP
	// reverse routing is enabled (Issue 150). It will become always true
	// later.
	debugUseDerpRoute, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_ENABLE_DERP_ROUTE"))
	// logDerpVerbose logs all received DERP packets, including their
	// full payload.
	logDerpVerbose, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_DERP"))
	// debugReSTUNStopOnIdle unconditionally enables the "shut down
	// STUN if magicsock is idle" behavior that normally only triggers
	// on mobile devices, lowers the shutdown interval, and logs more
	// verbosely about idle measurements.
	debugReSTUNStopOnIdle, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_RESTUN_STOP_ON_IDLE"))
)

// inTest reports whether the running program is a test that set the
// IN_TS_TEST environment variable.
//
// Unlike the other debug tweakables above, this one needs to be
// checked every time at runtime, because tests set this after program
// startup.
func inTest() bool {
	inTest, _ := strconv.ParseBool(os.Getenv("IN_TS_TEST"))
	return inTest
}

// A Conn routes UDP packets and actively manages a list of its endpoints.
// It implements wireguard/conn.Bind.
type Conn struct {
	pconnPort        uint16 // the preferred port from opts.Port; 0 means auto
	pconn4           *RebindingUDPConn
	pconn6           *RebindingUDPConn // non-nil if IPv6 available
	epFunc           func(endpoints []string)
	logf             logger.Logf
	sendLogLimit     *rate.Limiter
	netChecker       *netcheck.Client
	idleFunc         func() time.Duration   // nil means unknown
	noteRecvActivity func(tailcfg.DiscoKey) // or nil, see Options.NoteRecvActivity

	// bufferedIPv4From and bufferedIPv4Packet are owned by
	// ReceiveIPv4, and used when both a DERP and IPv4 packet arrive
	// at the same time. It stores the IPv4 packet for use in the next call.
	bufferedIPv4From   netaddr.IPPort // if non-zero, then bufferedIPv4Packet is valid
	bufferedIPv4Packet []byte         // the received packet (reused, owned by ReceiveIPv4)

	connCtx       context.Context // closed on Conn.Close
	connCtxCancel func()          // closes connCtx

	// stunReceiveFunc holds the current STUN packet processing func.
	// Its Loaded value is always non-nil.
	stunReceiveFunc atomic.Value // of func(p []byte, fromAddr *net.UDPAddr)

	udpRecvCh  chan udpReadResult
	derpRecvCh chan derpReadResult

	// packetListener optionally specifies a test hook to open a PacketConn.
	packetListener nettype.PacketListener

	// ============================================================
	mu     sync.Mutex // guards all following fields; see userspaceEngine lock ordering rules
	muCond *sync.Cond

	started bool // Start was called
	closed  bool // Close was called

	endpointsUpdateActive bool
	wantEndpointsUpdate   string // true if non-empty; string is reason
	lastEndpoints         []string
	peerSet               map[key.Public]struct{}

	discoPrivate    key.Private
	discoPublic     tailcfg.DiscoKey // public of discoPrivate
	discoShort      string           // ShortString of discoPublic (to save logging work later)
	nodeOfDisco     map[tailcfg.DiscoKey]*tailcfg.Node
	discoOfNode     map[tailcfg.NodeKey]tailcfg.DiscoKey
	discoOfAddr     map[netaddr.IPPort]tailcfg.DiscoKey // validated non-DERP paths only
	endpointOfDisco map[tailcfg.DiscoKey]*discoEndpoint // those with activity only
	sharedDiscoKey  map[tailcfg.DiscoKey]*[32]byte      // nacl/box precomputed key

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
	netMap      *controlclient.NetworkMap
	privateKey  key.Private
	everHadKey  bool               // whether we ever had a non-zero private key
	myDerp      int                // nearest DERP region ID; 0 means none/unknown
	derpStarted chan struct{}      // closed on first connection to DERP; for tests & cleaner Close
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

	// IdleFunc optionally provides a func to return how long
	// it's been since a TUN packet was sent or received.
	IdleFunc func() time.Duration

	// PacketListener optionally specifies how to create PacketConns.
	// It's meant for testing.
	PacketListener nettype.PacketListener

	// NoteRecvActivity, if provided, is a func for magicsock to
	// call whenever it receives a packet from a a
	// discovery-capable peer if it's been more than ~10 seconds
	// since the last one. (10 seconds is somewhat arbitrary; the
	// sole user just doesn't need or want it called on every
	// packet, just every minute or two for Wireguard timeouts,
	// and 10 seconds seems like a good trade-off between often
	// enough and not too often.) The provided func is called while
	// holding userspaceEngine.wgLock and likely calls
	// Conn.CreateEndpoint, which acquires Conn.mu. As such, you should
	// not hold
	NoteRecvActivity func(tailcfg.DiscoKey)
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
		sendLogLimit:    rate.NewLimiter(rate.Every(1*time.Minute), 1),
		addrsByUDP:      make(map[netaddr.IPPort]*AddrSet),
		addrsByKey:      make(map[key.Public]*AddrSet),
		derpRecvCh:      make(chan derpReadResult),
		udpRecvCh:       make(chan udpReadResult),
		derpStarted:     make(chan struct{}),
		peerLastDerp:    make(map[key.Public]int),
		endpointOfDisco: make(map[tailcfg.DiscoKey]*discoEndpoint),
		sharedDiscoKey:  make(map[tailcfg.DiscoKey]*[32]byte),
		discoOfAddr:     make(map[netaddr.IPPort]tailcfg.DiscoKey),
	}
	c.muCond = sync.NewCond(&c.mu)
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
	c.idleFunc = opts.IdleFunc
	c.packetListener = opts.PacketListener
	c.noteRecvActivity = opts.NoteRecvActivity

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
	c.stunReceiveFunc.Store(func([]byte, netaddr.IPPort) {})
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
			c.muCond.Broadcast()
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

	if dm == nil {
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
		UPnP:                  report.UPnP,
		PMP:                   report.PMP,
		PCP:                   report.PCP,
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

// peerForIP returns the Node in nm that's responsible for
// handling the given IP address.
func peerForIP(nm *controlclient.NetworkMap, ip netaddr.IP) (n *tailcfg.Node, ok bool) {
	if nm == nil {
		return nil, false
	}
	wgIP := wgcfg.IP{Addr: ip.As16()}
	// Check for exact matches before looking for subnet matches.
	for _, p := range nm.Peers {
		for _, a := range p.Addresses {
			if a.IP == wgIP {
				return p, true
			}
		}
	}
	for _, p := range nm.Peers {
		for _, cidr := range p.AllowedIPs {
			if cidr.Contains(wgIP) {
				return p, true
			}
		}
	}
	return nil, false
}

// Ping handles a "tailscale ping" CLI query.
func (c *Conn) Ping(ip netaddr.IP, cb func(*ipnstate.PingResult)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	res := &ipnstate.PingResult{IP: ip.String()}
	if c.privateKey.IsZero() {
		res.Err = "local tailscaled stopped"
		cb(res)
		return
	}
	peer, ok := peerForIP(c.netMap, ip)
	if !ok {
		res.Err = "no matching peer"
		cb(res)
		return
	}
	if len(peer.Addresses) > 0 {
		res.NodeIP = peer.Addresses[0].IP.String()
	}
	res.NodeName = peer.Name // prefer DNS name
	if res.NodeName == "" {
		res.NodeName = peer.Hostinfo.Hostname // else hostname
	} else {
		if i := strings.Index(res.NodeName, "."); i != -1 {
			res.NodeName = res.NodeName[:i]
		}
	}

	dk, ok := c.discoOfNode[peer.Key]
	if !ok {
		res.Err = "no discovery key for peer (pre 0.100?)"
		cb(res)
		return
	}
	de, ok := c.endpointOfDisco[dk]
	if !ok {
		c.mu.Unlock() // temporarily release
		if c.noteRecvActivity != nil {
			c.noteRecvActivity(dk)
		}
		c.mu.Lock() // re-acquire

		// re-check at least basic invariant:
		if c.privateKey.IsZero() {
			res.Err = "local tailscaled stopped"
			cb(res)
			return
		}

		de, ok = c.endpointOfDisco[dk]
		if !ok {
			res.Err = "internal error: failed to create endpoint for discokey"
			cb(res)
			return
		}
		c.logf("magicsock: started peer %v for ping to %v", dk.ShortString(), peer.Key.ShortString())
	}
	de.cliPing(res, cb)
}

// c.mu must be held
func (c *Conn) populateCLIPingResponseLocked(res *ipnstate.PingResult, latency time.Duration, ep netaddr.IPPort) {
	res.LatencySeconds = latency.Seconds()
	if ep.IP != derpMagicIPAddr {
		res.Endpoint = ep.String()
		return
	}
	regionID := int(ep.Port)
	res.DERPRegionID = regionID
	if c.derpMap != nil {
		if dr, ok := c.derpMap.Regions[regionID]; ok {
			res.DERPRegionCode = dr.RegionCode
		}
	}
}

// DiscoPublicKey returns the discovery public key.
func (c *Conn) DiscoPublicKey() tailcfg.DiscoKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.discoPrivate.IsZero() {
		priv := key.NewPrivate()
		c.discoPrivate = priv
		c.discoPublic = tailcfg.DiscoKey(priv.Public())
		c.discoShort = c.discoPublic.ShortString()
		c.logf("magicsock: disco key = %v", c.discoShort)
	}
	return c.discoPublic
}

// PeerHasDiscoKey reports whether peer k supports discovery keys (client version 0.100.0+).
func (c *Conn) PeerHasDiscoKey(k tailcfg.NodeKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.discoOfNode[k]
	return ok
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
	go c.derpWriteChanOfAddr(netaddr.IPPort{IP: derpMagicIPAddr, Port: uint16(node)}, key.Public{})
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
		if debugOmitLocalAddresses && (reason == "localAddresses" || reason == "socket") {
			return
		}
		if _, ok := already[s]; !ok {
			already[s] = reason
			eps = append(eps, s)
		}
	}

	if nr.GlobalV4 != "" {
		addAddr(nr.GlobalV4, "stun")

		// If they're behind a hard NAT and are using a fixed
		// port locally, assume they might've added a static
		// port mapping on their router to the same explicit
		// port that tailscaled is running with. Worst case
		// it's an invalid candidate mapping.
		if nr.MappingVariesByDestIP.EqualBool(true) && c.pconnPort != 0 {
			if ip, _, err := net.SplitHostPort(nr.GlobalV4); err == nil {
				addAddr(net.JoinHostPort(ip, strconv.Itoa(int(c.pconnPort))), "port_in")
			}
		}
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

const sprayPeriod = 3 * time.Second

// appendDests appends to dsts the destinations that b should be
// written to in order to reach as. Some of the returned IPPorts may
// be fake addrs representing DERP servers.
//
// It also returns as's current roamAddr, if any.
func (as *AddrSet) appendDests(dsts []netaddr.IPPort, b []byte) (_ []netaddr.IPPort, roamAddr netaddr.IPPort) {
	spray := shouldSprayPacket(b) // true for handshakes
	now := as.timeNow()

	as.mu.Lock()
	defer as.mu.Unlock()

	as.lastSend = now

	// Some internal invariant checks.
	if len(as.addrs) != len(as.ipPorts) {
		panic(fmt.Sprintf("lena %d != leni %d", len(as.addrs), len(as.ipPorts)))
	}
	if n1, n2 := as.roamAddr != nil, as.roamAddrStd != nil; n1 != n2 {
		panic(fmt.Sprintf("roamnil %v != roamstdnil %v", n1, n2))
	}

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
		for i := range as.ipPorts {
			dsts = append(dsts, as.ipPorts[i])
		}
		if as.roamAddr != nil {
			dsts = append(dsts, *as.roamAddr)
		}
	case as.roamAddr != nil:
		// We have a roaming address, prefer it over other addrs.
		// TODO(danderson): this is not correct, there's no reason
		// roamAddr should be special like this.
		dsts = append(dsts, *as.roamAddr)
	case as.curAddr != -1:
		if as.curAddr >= len(as.addrs) {
			as.Logf("[unexpected] magicsock bug: as.curAddr >= len(as.addrs): %d >= %d", as.curAddr, len(as.addrs))
			break
		}
		// No roaming addr, but we've seen packets from a known peer
		// addr, so keep using that one.
		dsts = append(dsts, as.ipPorts[as.curAddr])
	default:
		// We know nothing about how to reach this peer, and we're not
		// spraying. Use the first address in the array, which will
		// usually be a DERP address that guarantees connectivity.
		if len(as.ipPorts) > 0 {
			dsts = append(dsts, as.ipPorts[0])
		}
	}

	if logPacketDests {
		as.Logf("spray=%v; roam=%v; dests=%v", spray, as.roamAddr, dsts)
	}
	if as.roamAddr != nil {
		roamAddr = *as.roamAddr
	}
	return dsts, roamAddr
}

var errNoDestinations = errors.New("magicsock: no destinations")

func (c *Conn) Send(b []byte, ep conn.Endpoint) error {
	var as *AddrSet
	switch v := ep.(type) {
	default:
		panic(fmt.Sprintf("[unexpected] Endpoint type %T", v))
	case *discoEndpoint:
		return v.send(b)
	case *singleEndpoint:
		addr := (*net.UDPAddr)(v)
		if addr.IP.Equal(derpMagicIP) {
			c.logf("magicsock: [unexpected] DERP BUG: attempting to send packet to DERP address %v", addr)
			return nil
		}
		_, err := c.sendUDPStd(addr, b)
		return err
	case *AddrSet:
		as = v
	}

	var addrBuf [8]netaddr.IPPort
	dsts, roamAddr := as.appendDests(addrBuf[:0], b)

	if len(dsts) == 0 {
		return errNoDestinations
	}

	var success bool
	var ret error
	for _, addr := range dsts {
		sent, err := c.sendAddr(addr, as.publicKey, b)
		if sent {
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

// sendUDP sends UDP packet b to ipp.
// See sendAddr's docs on the return value meanings.
func (c *Conn) sendUDP(ipp netaddr.IPPort, b []byte) (sent bool, err error) {
	ua := ipp.UDPAddr()
	defer netaddr.PutUDPAddr(ua)
	return c.sendUDPStd(ua, b)
}

// sendUDP sends UDP packet b to addr.
// See sendAddr's docs on the return value meanings.
func (c *Conn) sendUDPStd(addr *net.UDPAddr, b []byte) (sent bool, err error) {
	switch {
	case addr.IP.To4() != nil:
		_, err = c.pconn4.WriteTo(b, addr)
		if err != nil && c.noV4.Get() {
			return false, nil
		}
	case len(addr.IP) == net.IPv6len:
		if c.pconn6 == nil {
			// ignore IPv6 dest if we don't have an IPv6 address.
			return false, nil
		}
		_, err = c.pconn6.WriteTo(b, addr)
		if err != nil && c.noV6.Get() {
			return false, nil
		}
	default:
		panic("bogus sendUDPStd addr type")
	}
	return err == nil, err
}

// sendAddr sends packet b to addr, which is either a real UDP address
// or a fake UDP address representing a DERP server (see derpmap.go).
// The provided public key identifies the recipient.
//
// The returned err is whether there was an error writing when it
// should've worked.
// The returned sent is whether a packet went out at all.
// An example of when they might be different: sending to an
// IPv6 address when the local machine doesn't have IPv6 support
// returns (false, nil); it's not an error, but nothing was sent.
func (c *Conn) sendAddr(addr netaddr.IPPort, pubKey key.Public, b []byte) (sent bool, err error) {
	if addr.IP != derpMagicIPAddr {
		return c.sendUDP(addr, b)
	}

	ch := c.derpWriteChanOfAddr(addr, pubKey)
	if ch == nil {
		return false, nil
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
		return false, errConnClosed
	case ch <- derpWriteRequest{addr, pubKey, pkt}:
		return true, nil
	default:
		// Too many writes queued. Drop packet.
		return false, errDropDerpPacket
	}
}

// bufferedDerpWritesBeforeDrop is how many packets writes can be
// queued up the DERP client to write on the wire before we start
// dropping.
//
// TODO: this is currently arbitrary. Figure out something better?
const bufferedDerpWritesBeforeDrop = 32

// derpWriteChanOfAddr returns a DERP client for fake UDP addresses that
// represent DERP servers, creating them as necessary. For real UDP
// addresses, it returns nil.
//
// If peer is non-zero, it can be used to find an active reverse
// path, without using addr.
func (c *Conn) derpWriteChanOfAddr(addr netaddr.IPPort, peer key.Public) chan<- derpWriteRequest {
	if addr.IP != derpMagicIPAddr {
		return nil
	}
	regionID := int(addr.Port)

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
		if c.connCtx.Err() != nil {
			// If we're closing, don't try to acquire the lock.
			// We might already be in Conn.Close and the Lock would deadlock.
			return nil
		}
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
			c.muCond.Broadcast()
		}()
	}

	go c.runDerpReader(ctx, addr, dc, wg, startGate)
	go c.runDerpWriter(ctx, dc, ch, wg, startGate)

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
	regionID int
	n        int        // length of data received
	src      key.Public // may be zero until server deployment if v2+
	// copyBuf is called to copy the data to dst.  It returns how
	// much data was copied, which will be n if dst is large
	// enough. copyBuf can only be called once.
	copyBuf func(dst []byte) int
}

// runDerpReader runs in a goroutine for the life of a DERP
// connection, handling received packets.
func (c *Conn) runDerpReader(ctx context.Context, derpFakeAddr netaddr.IPPort, dc *derphttp.Client, wg *syncs.WaitGroupChan, startGate <-chan struct{}) {
	defer wg.Decr()
	defer dc.Close()

	select {
	case <-startGate:
	case <-ctx.Done():
		return
	}

	didCopy := make(chan struct{}, 1)
	regionID := int(derpFakeAddr.Port)
	res := derpReadResult{regionID: regionID}
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
		msg, err := dc.Recv()
		if err == derphttp.ErrClientClosed {
			return
		}
		if err != nil {
			// Forget that all these peers have routes.
			for peer := range peerPresent {
				delete(peerPresent, peer)
				c.removeDerpPeerRoute(peer, regionID, dc)
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			c.ReSTUN("derp-close")
			c.logf("magicsock: [%p] derp.Recv(derp-%d): %v", dc, regionID, err)

			// Avoid excessive spinning.
			// TODO: use a backoff timer, perhaps between 10ms and 500ms?
			// Don't want to sleep too long. For now 250ms seems fine.
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
			continue
		}
		switch m := msg.(type) {
		case derp.ReceivedPacket:
			pkt = m
			res.n = len(m.Data)
			res.src = m.Source
			if logDerpVerbose {
				c.logf("magicsock: got derp-%v packet: %q", regionID, m.Data)
			}
			// If this is a new sender we hadn't seen before, remember it and
			// register a route for this peer.
			if _, ok := peerPresent[m.Source]; !ok {
				peerPresent[m.Source] = true
				c.addDerpPeerRoute(m.Source, regionID, dc)
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
			select {
			case <-ctx.Done():
				return
			case <-didCopy:
				continue
			}
		}
	}
}

type derpWriteRequest struct {
	addr   netaddr.IPPort
	pubKey key.Public
	b      []byte // copied; ownership passed to receiver
}

// runDerpWriter runs in a goroutine for the life of a DERP
// connection, handling received packets.
func (c *Conn) runDerpWriter(ctx context.Context, dc *derphttp.Client, ch <-chan derpWriteRequest, wg *syncs.WaitGroupChan, startGate <-chan struct{}) {
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
// The provided addr and ipp must match.
//
// TODO(bradfitz): add a fast path that returns nil here for normal
// wireguard-go transport packets; wireguard-go only uses this
// Endpoint for the relatively rare non-data packets; but we need the
// Endpoint to find the UDPAddr to return to wireguard anyway, so no
// benefit unless we can, say, always return the same fake UDPAddr for
// all packets.
func (c *Conn) findEndpoint(ipp netaddr.IPPort, addr *net.UDPAddr) conn.Endpoint {
	c.mu.Lock()
	defer c.mu.Unlock()

	// See if they have a discoEndpoint, for a set of peers
	// both supporting active discovery.
	if dk, ok := c.discoOfAddr[ipp]; ok {
		if ep, ok := c.endpointOfDisco[dk]; ok {
			return ep
		}
	}

	// Pre-disco: look up their AddrSet.
	if as, ok := c.addrsByUDP[ipp]; ok {
		return as
	}

	// Pre-disco: the peer that sent this packet has roamed beyond
	// the knowledge provided by the control server.  If the
	// packet is valid wireguard will call UpdateDst on the
	// original endpoint using this addr.
	return (*singleEndpoint)(addr)
}

type udpReadResult struct {
	_    structs.Incomparable
	n    int
	err  error
	addr *net.UDPAddr
	ipp  netaddr.IPPort
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
		ipp, ok := c.pconn4.ippCache.IPPort(addr)
		if !ok {
			continue
		}
		if stun.Is(b[:n]) {
			c.stunReceiveFunc.Load().(func([]byte, netaddr.IPPort))(b[:n], ipp)
			continue
		}
		if c.handleDiscoMessage(b[:n], ipp) {
			continue
		}

		select {
		case c.udpRecvCh <- udpReadResult{n: n, addr: addr, ipp: ipp}:
		case <-c.donec():
		}
		return
	}
}

// wgRecvAddr returns the net.UDPAddr we tell wireguard-go the address
// from which we received a packet for an endpoint.
//
// ipp is required. addr can be optionally provided.
func wgRecvAddr(e conn.Endpoint, ipp netaddr.IPPort, addr *net.UDPAddr) *net.UDPAddr {
	if ipp == (netaddr.IPPort{}) {
		panic("zero ipp")
	}
	if de, ok := e.(*discoEndpoint); ok {
		return de.fakeWGAddrStd
	}
	if addr != nil {
		return addr
	}
	return ipp.UDPAddr()
}

// noteRecvActivityFromEndpoint calls the c.noteRecvActivity hook if
// e is a discovery-capable peer and this is the first receive activity
// it's got in awhile (in last 10 seconds).
//
// This should be called whenever a packet arrives from e.
func (c *Conn) noteRecvActivityFromEndpoint(e conn.Endpoint) {
	de, ok := e.(*discoEndpoint)
	if ok && c.noteRecvActivity != nil && de.isFirstRecvActivityInAwhile() {
		c.noteRecvActivity(de.discoKey)
	}
}

func (c *Conn) ReceiveIPv4(b []byte) (n int, ep conn.Endpoint, addr *net.UDPAddr, err error) {
Top:
	// First, process any buffered packet from earlier.
	if from := c.bufferedIPv4From; from != (netaddr.IPPort{}) {
		c.bufferedIPv4From = netaddr.IPPort{}
		addr = from.UDPAddr()
		ep := c.findEndpoint(from, addr)
		c.noteRecvActivityFromEndpoint(ep)
		return copy(b, c.bufferedIPv4Packet), ep, wgRecvAddr(ep, from, addr), nil
	}

	go c.awaitUDP4(b)

	// Once the above goroutine has started, it owns b until it writes
	// to udpRecvCh. The code below must not access b until it's
	// completed a successful receive on udpRecvCh.

	var addrSet *AddrSet
	var discoEp *discoEndpoint
	var ipp netaddr.IPPort
	var didNoteRecvActivity bool

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
				c.bufferedIPv4From = um.ipp
				c.bufferedIPv4Packet = append(c.bufferedIPv4Packet[:0], b[:um.n]...)
			}
			c.pconn4.SetReadDeadline(time.Time{})
		case <-c.donec():
			return 0, nil, nil, errors.New("Conn closed")
		}
		var regionID int
		n, regionID = dm.n, dm.regionID
		ncopy := dm.copyBuf(b)
		if ncopy != n {
			err = fmt.Errorf("received DERP packet of length %d that's too big for WireGuard ReceiveIPv4 buf size %d", n, ncopy)
			c.logf("magicsock: %v", err)
			return 0, nil, nil, err
		}

		ipp = netaddr.IPPort{IP: derpMagicIPAddr, Port: uint16(regionID)}
		if c.handleDiscoMessage(b[:n], ipp) {
			goto Top
		}

		c.mu.Lock()
		if dk, ok := c.discoOfNode[tailcfg.NodeKey(dm.src)]; ok {
			discoEp = c.endpointOfDisco[dk]
			// If we know about the node (it's in discoOfNode) but don't know about the
			// endpoint, that's because it's an idle peer that doesn't yet exist in the
			// wireguard config. So run the receive hook, if defined, which should
			// create the wireguard peer.
			if discoEp == nil && c.noteRecvActivity != nil {
				didNoteRecvActivity = true
				c.mu.Unlock()          // release lock before calling noteRecvActivity
				c.noteRecvActivity(dk) // (calls back into CreateEndpoint)
				// Now require the lock. No invariants need to be rechecked; just
				// 1-2 map lookups follow that are harmless if, say, the peer has
				// been deleted during this time.  In that case we'll treate it as a
				// legacy pre-disco UDP receive and hand it to wireguard which'll
				// likely just drop it.
				c.mu.Lock()

				discoEp = c.endpointOfDisco[dk]
				c.logf("magicsock: DERP packet received from idle peer %v; created=%v", dm.src.ShortString(), discoEp != nil)
			}
		}
		if discoEp == nil {
			addrSet = c.addrsByKey[dm.src]
		}
		c.mu.Unlock()

		if addrSet == nil && discoEp == nil {
			key := wgcfg.Key(dm.src)
			c.logf("magicsock: DERP packet from unknown key: %s", key.ShortString())
		}

	case um := <-c.udpRecvCh:
		if um.err != nil {
			return 0, nil, nil, err
		}
		n, addr, ipp = um.n, um.addr, um.ipp

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
	} else if discoEp != nil {
		ep = discoEp
	} else {
		ep = c.findEndpoint(ipp, addr)
	}
	if !didNoteRecvActivity {
		c.noteRecvActivityFromEndpoint(ep)
	}
	return n, ep, wgRecvAddr(ep, ipp, addr), nil
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
		ipp, ok := c.pconn6.ippCache.IPPort(addr)
		if !ok {
			continue
		}
		if stun.Is(b[:n]) {
			c.stunReceiveFunc.Load().(func([]byte, netaddr.IPPort))(b[:n], ipp)
			continue
		}
		if c.handleDiscoMessage(b[:n], ipp) {
			continue
		}

		ep := c.findEndpoint(ipp, addr)
		c.noteRecvActivityFromEndpoint(ep)
		return n, ep, wgRecvAddr(ep, ipp, addr), nil
	}
}

// discoLogLevel controls the verbosity of discovery log messages.
type discoLogLevel int

const (
	// discoLog means that a message should be logged.
	discoLog discoLogLevel = iota

	// discoVerboseLog means that a message should only be logged
	// in TS_DEBUG_DISCO mode.
	discoVerboseLog
)

func (c *Conn) sendDiscoMessage(dst netaddr.IPPort, dstKey tailcfg.NodeKey, dstDisco tailcfg.DiscoKey, m disco.Message, logLevel discoLogLevel) (sent bool, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false, errConnClosed
	}
	var nonce [disco.NonceLen]byte
	if _, err := crand.Read(nonce[:]); err != nil {
		panic(err) // worth dying for
	}
	pkt := make([]byte, 0, 512) // TODO: size it correctly? pool? if it matters.
	pkt = append(pkt, disco.Magic...)
	pkt = append(pkt, c.discoPublic[:]...)
	pkt = append(pkt, nonce[:]...)
	sharedKey := c.sharedDiscoKeyLocked(dstDisco)
	c.mu.Unlock()

	pkt = box.SealAfterPrecomputation(pkt, m.AppendMarshal(nil), &nonce, sharedKey)
	sent, err = c.sendAddr(dst, key.Public(dstKey), pkt)
	if sent {
		if logLevel == discoLog || (logLevel == discoVerboseLog && debugDisco) {
			c.logf("magicsock: disco: %v->%v (%v, %v) sent %v", c.discoShort, dstDisco.ShortString(), dstKey.ShortString(), derpStr(dst.String()), disco.MessageSummary(m))
		}
	} else if err == nil {
		// Can't send. (e.g. no IPv6 locally)
	} else {
		c.logf("magicsock: disco: failed to send %T to %v: %v", m, dst, err)
	}
	return sent, err
}

// handleDiscoMessage reports whether msg was a Tailscale inter-node discovery message
// that was handled.
//
// A discovery message has the form:
//
//  * magic             [6]byte
//  * senderDiscoPubKey [32]byte
//  * nonce             [24]byte
//  * naclbox of payload (see tailscale.com/disco package for inner payload format)
//
// For messages received over DERP, the addr will be derpMagicIP (with
// port being the region)
func (c *Conn) handleDiscoMessage(msg []byte, src netaddr.IPPort) bool {
	const headerLen = len(disco.Magic) + len(tailcfg.DiscoKey{}) + disco.NonceLen
	if len(msg) < headerLen || string(msg[:len(disco.Magic)]) != disco.Magic {
		return false
	}
	var sender tailcfg.DiscoKey
	copy(sender[:], msg[len(disco.Magic):])

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return true
	}
	if debugDisco {
		c.logf("magicsock: disco: got disco-looking frame from %v", sender.ShortString())
	}
	if c.privateKey.IsZero() {
		// Ignore disco messages when we're stopped.
		return false
	}
	if c.discoPrivate.IsZero() {
		if debugDisco {
			c.logf("magicsock: disco: ignoring disco-looking frame, no local key")
		}
		return false
	}

	peerNode, ok := c.nodeOfDisco[sender]
	if !ok {
		if debugDisco {
			c.logf("magicsock: disco: ignoring disco-looking frame, don't know node for %v", sender.ShortString())
		}
		// Returning false keeps passing it down, to WireGuard.
		// WireGuard will almost surely reject it, but give it a chance.
		return false
	}

	needsRecvActivityCall := false
	de, endpointFound0 := c.endpointOfDisco[sender]
	if !endpointFound0 {
		// We don't have an active endpoint for this sender but we knew about the node, so
		// it's an idle endpoint that doesn't yet exist in the wireguard config. We now have
		// to notify the userspace engine (via noteRecvActivity) so wireguard-go can create
		// an Endpoint (ultimately calling our CreateEndpoint).
		if debugDisco {
			c.logf("magicsock: disco: got message from inactive peer %v", sender.ShortString())
		}
		if c.noteRecvActivity == nil {
			c.logf("magicsock: [unexpected] have node without endpoint, without c.noteRecvActivity hook")
			return false
		}
		needsRecvActivityCall = true
	} else {
		needsRecvActivityCall = de.isFirstRecvActivityInAwhile()
	}
	if needsRecvActivityCall && c.noteRecvActivity != nil {
		// We can't hold Conn.mu while calling noteRecvActivity.
		// noteRecvActivity acquires userspaceEngine.wgLock (and per our
		// lock ordering rules: wgLock must come first), and also calls
		// back into our Conn.CreateEndpoint, which would double-acquire
		// Conn.mu.
		c.mu.Unlock()
		c.noteRecvActivity(sender)
		c.mu.Lock() // re-acquire

		// Now, recheck invariants that might've changed while we'd
		// released the lock, which isn't much:
		if c.closed || c.privateKey.IsZero() {
			return true
		}
		de, ok = c.endpointOfDisco[sender]
		if !ok {
			if _, ok := c.nodeOfDisco[sender]; !ok {
				// They just disappeared while we'd released the lock.
				return false
			}
			c.logf("magicsock: [unexpected] lazy endpoint not created for %v, %v", peerNode.Key.ShortString(), sender.ShortString())
			return false
		}
		if !endpointFound0 {
			c.logf("magicsock: lazy endpoint created via disco message for %v, %v", peerNode.Key.ShortString(), sender.ShortString())
		}
	}

	// First, do we even know (and thus care) about this sender? If not,
	// don't bother decrypting it.

	var nonce [disco.NonceLen]byte
	copy(nonce[:], msg[len(disco.Magic)+len(key.Public{}):])
	sealedBox := msg[headerLen:]
	payload, ok := box.OpenAfterPrecomputation(nil, sealedBox, &nonce, c.sharedDiscoKeyLocked(sender))
	if !ok {
		// This might be have been intended for a previous
		// disco key.  When we restart we get a new disco key
		// and old packets might've still been in flight (or
		// scheduled). This is particularly the case for LANs
		// or non-NATed endpoints.
		// Don't log in normal case. Pass on to wireguard, in case
		// it's actually a a wireguard packet (super unlikely,
		// but).
		if debugDisco {
			c.logf("magicsock: disco: failed to open naclbox from %v (wrong rcpt?)", sender)
		}
		// TODO(bradfitz): add some counter for this that logs rarely
		return false
	}

	dm, err := disco.Parse(payload)
	if debugDisco {
		c.logf("magicsock: disco: disco.Parse = %T, %v", dm, err)
	}
	if err != nil {
		// Couldn't parse it, but it was inside a correctly
		// signed box, so just ignore it, assuming it's from a
		// newer version of Tailscale that we don't
		// understand. Not even worth logging about, lest it
		// be too spammy for old clients.
		// TODO(bradfitz): add some counter for this that logs rarely
		return true
	}

	switch dm := dm.(type) {
	case *disco.Ping:
		c.handlePingLocked(dm, de, src, sender, peerNode)
	case *disco.Pong:
		if de == nil {
			return true
		}
		de.handlePongConnLocked(dm, src)
	case disco.CallMeMaybe:
		if src.IP != derpMagicIPAddr {
			// CallMeMaybe messages should only come via DERP.
			c.logf("[unexpected] CallMeMaybe packets should only come via DERP")
			return true
		}
		if de != nil {
			c.logf("magicsock: disco: %v<-%v (%v, %v)  got call-me-maybe", c.discoShort, de.discoShort, de.publicKey.ShortString(), derpStr(src.String()))
			go de.handleCallMeMaybe()
		}
	}

	return true
}

// de may be nil
func (c *Conn) handlePingLocked(dm *disco.Ping, de *discoEndpoint, src netaddr.IPPort, sender tailcfg.DiscoKey, peerNode *tailcfg.Node) {
	if peerNode == nil {
		c.logf("magicsock: disco: [unexpected] ignoring ping from unknown peer Node")
		return
	}
	likelyHeartBeat := de != nil && src == de.lastPingFrom && time.Since(de.lastPingTime) < 5*time.Second
	var discoShort string
	if de != nil {
		discoShort = de.discoShort
		de.lastPingFrom = src
		de.lastPingTime = time.Now()
	} else {
		discoShort = sender.ShortString()
	}
	if !likelyHeartBeat || debugDisco {
		c.logf("magicsock: disco: %v<-%v (%v, %v)  got ping tx=%x", c.discoShort, discoShort, peerNode.Key.ShortString(), src, dm.TxID[:6])
	}

	// Remember this route if not present.
	c.setAddrToDiscoLocked(src, sender, nil)

	ipDst := src
	discoDest := sender
	go c.sendDiscoMessage(ipDst, peerNode.Key, discoDest, &disco.Pong{
		TxID: dm.TxID,
		Src:  src,
	}, discoVerboseLog)
}

// setAddrToDiscoLocked records that newk is at src.
//
// c.mu must be held.
//
// If the caller already has a discoEndpoint mutex held as well, it
// can be passed in as alreadyLocked so it won't be re-acquired during
// any lazy cleanup of the mapping.
func (c *Conn) setAddrToDiscoLocked(src netaddr.IPPort, newk tailcfg.DiscoKey, alreadyLocked *discoEndpoint) {
	oldk, ok := c.discoOfAddr[src]
	if ok && oldk == newk {
		return
	}
	if ok {
		c.logf("magicsock: disco: changing mapping of %v from %x=>%x", src, oldk.ShortString(), newk.ShortString())
	} else {
		c.logf("magicsock: disco: adding mapping of %v to %v", src, newk.ShortString())
	}
	c.discoOfAddr[src] = newk
	if !ok {
		c.cleanDiscoOfAddrLocked(alreadyLocked)
	}
}

// cleanDiscoOfAddrLocked lazily checks a few entries in c.discoOfAddr
// and deletes them if they're stale. It has no pointers in it so we
// don't go through the effort of keeping it aggressively
// pruned. Instead, we lazily clean it whenever it grows.
//
// c.mu must be held.
//
// If the caller already has a discoEndpoint mutex held as well, it
// can be passed in as alreadyLocked so it won't be re-acquired.
func (c *Conn) cleanDiscoOfAddrLocked(alreadyLocked *discoEndpoint) {
	// If it's small enough, don't worry about it.
	if len(c.discoOfAddr) < 16 {
		return
	}

	const checkEntries = 5 // per one unit of growth

	// Take advantage of Go's random map iteration to check & clean
	// a few entries.
	n := 0
	for ipp, dk := range c.discoOfAddr {
		n++
		if n > checkEntries {
			return
		}
		de, ok := c.endpointOfDisco[dk]
		if !ok {
			// This discokey isn't even known anymore. Clean.
			delete(c.discoOfAddr, ipp)
			continue
		}
		if de != alreadyLocked {
			de.mu.Lock()
		}
		if _, ok := de.endpointState[ipp]; !ok {
			// The discoEndpoint no longer knows about that endpoint.
			// It must've changed. Clean.
			delete(c.discoOfAddr, ipp)
		}
		if de != alreadyLocked {
			de.mu.Unlock()
		}
	}
}

func (c *Conn) sharedDiscoKeyLocked(k tailcfg.DiscoKey) *[32]byte {
	if v, ok := c.sharedDiscoKey[k]; ok {
		return v
	}
	shared := new([32]byte)
	box.Precompute(shared, key.Public(k).B32(), c.discoPrivate.B32())
	c.sharedDiscoKey[k] = shared
	return shared
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
		c.everHadKey = true
		c.logf("magicsock: SetPrivateKey called (init)")
		if c.started {
			go c.ReSTUN("set-private-key")
		}
	} else if newKey.IsZero() {
		c.logf("magicsock: SetPrivateKey called (zeroed)")
		c.closeAllDerpLocked("zero-private-key")
	} else {
		c.logf("magicsock: SetPrivateKey called (changed)")
		c.closeAllDerpLocked("new-private-key")
	}

	// Key changed. Close existing DERP connections and reconnect to home.
	if c.myDerp != 0 && !newKey.IsZero() {
		c.logf("magicsock: private key changed, reconnecting to home derp-%d", c.myDerp)
		c.goDerpConnect(c.myDerp)
	}

	if newKey.IsZero() {
		for _, de := range c.endpointOfDisco {
			de.stopAndReset()
		}
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

	if c.started {
		go c.ReSTUN("derp-map-update")
	}
}

func nodesEqual(x, y []*tailcfg.Node) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if !x[i].Equal(y[i]) {
			return false
		}
	}
	return true
}

// SetNetworkMap is called when the control client gets a new network
// map from the control server. It must always be non-nil.
//
// It should not use the DERPMap field of NetworkMap; that's
// conditionally sent to SetDERPMap instead.
func (c *Conn) SetNetworkMap(nm *controlclient.NetworkMap) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.netMap != nil && nodesEqual(c.netMap.Peers, nm.Peers) {
		return
	}

	numDisco := 0
	for _, n := range nm.Peers {
		if n.DiscoKey.IsZero() {
			continue
		}
		numDisco++
		if ep, ok := c.endpointOfDisco[n.DiscoKey]; ok {
			ep.updateFromNode(n)
		}
	}

	c.logf("magicsock: got updated network map; %d peers (%d with discokey)", len(nm.Peers), numDisco)
	c.netMap = nm

	// Build and/or update node<->disco maps, only reallocating if
	// the set of discokeys changed.
	for pass := 1; pass <= 2; pass++ {
		if c.nodeOfDisco == nil || pass == 2 {
			c.nodeOfDisco = map[tailcfg.DiscoKey]*tailcfg.Node{}
			c.discoOfNode = map[tailcfg.NodeKey]tailcfg.DiscoKey{}
		}
		for _, n := range nm.Peers {
			if !n.DiscoKey.IsZero() {
				c.nodeOfDisco[n.DiscoKey] = n
				if old, ok := c.discoOfNode[n.Key]; ok && old != n.DiscoKey {
					c.logf("magicsock: node %s changed discovery key from %x to %x", n.Key.ShortString(), old[:8], n.DiscoKey[:8])
				}
				c.discoOfNode[n.Key] = n.DiscoKey
			}
		}
		if len(c.nodeOfDisco) == numDisco && len(c.discoOfNode) == numDisco {
			break
		}
	}

	// Clean c.endpointOfDisco for discovery keys that are no longer present.
	for dk, de := range c.endpointOfDisco {
		if _, ok := c.nodeOfDisco[dk]; !ok {
			de.stopAndReset()
			delete(c.endpointOfDisco, dk)
			delete(c.sharedDiscoKey, dk)
		}
	}

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

	for _, ep := range c.endpointOfDisco {
		ep.stopAndReset()
	}

	c.closed = true
	c.connCtxCancel()
	c.closeAllDerpLocked("conn-close")
	if c.pconn6 != nil {
		c.pconn6.Close()
	}
	err := c.pconn4.Close()

	// Wait on goroutines updating right at the end, once everything is
	// already closed. We want everything else in the Conn to be
	// consistently in the closed state before we release mu to wait
	// on the endpoint updater & derphttp.Connect.
	for c.goroutinesRunningLocked() {
		c.muCond.Wait()
	}
	return err
}

func (c *Conn) goroutinesRunningLocked() bool {
	if c.endpointsUpdateActive {
		return true
	}
	// The goroutine running dc.Connect in derpWriteChanOfAddr may linger
	// and appear to leak, as observed in https://github.com/tailscale/tailscale/issues/554.
	// This is despite the underlying context being cancelled by connCtxCancel above.
	// To avoid this condition, we must wait on derpStarted here
	// to ensure that this goroutine has exited by the time Close returns.
	// We only do this if derpWriteChanOfAddr has executed at least once:
	// on the first run, it sets firstDerp := true and spawns the aforementioned goroutine.
	// To detect this, we check activeDerp, which is initialized to non-nil on the first run.
	if c.activeDerp != nil {
		select {
		case <-c.derpStarted:
			break
		default:
			return true
		}
	}
	return false
}

func maxIdleBeforeSTUNShutdown() time.Duration {
	if debugReSTUNStopOnIdle {
		return time.Minute
	}
	return 5 * time.Minute
}

func (c *Conn) shouldDoPeriodicReSTUN() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.peerSet) == 0 {
		// No peers, so not worth doing.
		return false
	}
	// If it turns out this optimization was a mistake, we can
	// override it from the control server without waiting for a
	// new software rollout:
	if c.netMap != nil && c.netMap.Debug != nil && c.netMap.Debug.ForceBackgroundSTUN && !debugReSTUNStopOnIdle {
		return true
	}
	if f := c.idleFunc; f != nil {
		idleFor := f()
		if debugReSTUNStopOnIdle {
			c.logf("magicsock: periodicReSTUN: idle for %v", idleFor.Round(time.Second))
		}
		if idleFor > maxIdleBeforeSTUNShutdown() {
			if debugReSTUNStopOnIdle || version.IsMobile() { // TODO: make this unconditional later
				return false
			}
		}
	}
	return true
}

func (c *Conn) periodicReSTUN() {
	prand := rand.New(rand.NewSource(time.Now().UnixNano()))
	dur := func() time.Duration {
		// Just under 30s, a common UDP NAT timeout (Linux at least)
		return time.Duration(20+prand.Intn(7)) * time.Second
	}
	timer := time.NewTimer(dur())
	defer timer.Stop()
	var lastIdleState opt.Bool
	for {
		select {
		case <-c.donec():
			return
		case <-timer.C:
			doReSTUN := c.shouldDoPeriodicReSTUN()
			if !lastIdleState.EqualBool(doReSTUN) {
				if doReSTUN {
					c.logf("magicsock: periodicReSTUN enabled")
				} else {
					c.logf("magicsock: periodicReSTUN disabled due to inactivity")
				}
				lastIdleState.Set(doReSTUN)
			}
			if doReSTUN {
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

	// If the user stopped the app, stop doing work. (When the
	// user stops Tailscale via the GUI apps, ipn/local.go
	// reconfigures the engine with a zero private key.)
	//
	// This used to just check c.privateKey.IsZero, but that broke
	// some end-to-end tests tests that didn't ever set a private
	// key somehow. So for now, only stop doing work if we ever
	// had a key, which helps real users, but appeases tests for
	// now. TODO: rewrite those tests to be less brittle or more
	// realistic.
	if c.privateKey.IsZero() && c.everHadKey {
		c.logf("magicsock: ReSTUN(%q) ignored; stopped, no private key", why)
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

func (c *Conn) listenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	if c.packetListener != nil {
		return c.packetListener.ListenPacket(ctx, network, addr)
	}
	return netns.Listener().ListenPacket(ctx, network, addr)
}

func (c *Conn) bind1(ruc **RebindingUDPConn, which string) error {
	host := ""
	if inTest() {
		host = "127.0.0.1"
	}
	var pc net.PacketConn
	var err error
	listenCtx := context.Background() // unused without DNS name to resolve
	if c.pconnPort == 0 && DefaultPort != 0 {
		pc, err = c.listenPacket(listenCtx, which, fmt.Sprintf("%s:%d", host, DefaultPort))
		if err != nil {
			c.logf("magicsock: bind: default port %s/%v unavailable; picking random", which, DefaultPort)
		}
	}
	if pc == nil {
		pc, err = c.listenPacket(listenCtx, which, fmt.Sprintf("%s:%d", host, c.pconnPort))
	}
	if err != nil {
		c.logf("magicsock: bind(%s/%v): %v", which, c.pconnPort, err)
		return fmt.Errorf("magicsock: bind: %s/%d: %v", which, c.pconnPort, err)
	}
	if *ruc == nil {
		*ruc = new(RebindingUDPConn)
	}
	(*ruc).Reset(pc)
	return nil
}

// Rebind closes and re-binds the UDP sockets.
// It should be followed by a call to ReSTUN.
func (c *Conn) Rebind() {
	host := ""
	if inTest() {
		host = "127.0.0.1"
	}
	listenCtx := context.Background() // unused without DNS name to resolve
	if c.pconnPort != 0 {
		c.pconn4.mu.Lock()
		if err := c.pconn4.pconn.Close(); err != nil {
			c.logf("magicsock: link change close failed: %v", err)
		}
		packetConn, err := c.listenPacket(listenCtx, "udp4", fmt.Sprintf("%s:%d", host, c.pconnPort))
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
	packetConn, err := c.listenPacket(listenCtx, "udp4", host+":0")
	if err != nil {
		c.logf("magicsock: link change failed to bind new port: %v", err)
		return
	}
	c.pconn4.Reset(packetConn.(*net.UDPConn))

	c.mu.Lock()
	c.closeAllDerpLocked("rebind")
	haveKey := !c.privateKey.IsZero()
	c.mu.Unlock()

	if haveKey {
		c.goDerpConnect(c.myDerp)
	}
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
	for _, de := range c.endpointOfDisco {
		de.noteConnectivityChange()
	}
}

// AddrSet is a set of UDP addresses that implements wireguard/conn.Endpoint.
//
// This is the legacy endpoint for peers that don't support discovery;
// it predates discoEndpoint.
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

	lastSend time.Time

	// roamAddr is non-nil if/when we receive a correctly signed
	// WireGuard packet from an unexpected address. If so, we
	// remember it and send responses there in the future, but
	// this should hopefully never be used (or at least used
	// rarely) in the case that all the components of Tailscale
	// are correctly learning/sharing the network map details.
	roamAddr    *netaddr.IPPort
	roamAddrStd *net.UDPAddr

	// curAddr is an index into addrs of the highest-priority
	// address a valid packet has been received from so far.
	// If no valid packet from addrs has been received, curAddr is -1.
	curAddr int

	// stopSpray is the time after which we stop spraying packets.
	stopSpray time.Time

	// lastSpray is the last time we sprayed a packet.
	lastSpray time.Time

	// loggedLogPriMask is a bit field of that tracks whether
	// we've already logged about receiving a packet from a low
	// priority ("low-pri") address when we already have curAddr
	// set to a better one. This is only to suppress some
	// redundant logs.
	loggedLogPriMask uint32
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

var noAddr, _ = netaddr.FromStdAddr(net.ParseIP("127.127.127.127"), 127, "")

func (a *AddrSet) dst() netaddr.IPPort {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddr != nil {
		return *a.roamAddr
	}
	if len(a.addrs) == 0 {
		return noAddr
	}
	i := a.curAddr
	if i == -1 {
		i = 0
	}
	return a.ipPorts[i]
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

// packIPPort packs an IPPort into the form wanted by WireGuard.
func packIPPort(ua netaddr.IPPort) []byte {
	ip := ua.IP.Unmap()
	a := ip.As16()
	ipb := a[:]
	if ip.Is4() {
		ipb = ipb[12:]
	}
	b := make([]byte, 0, len(ipb)+2)
	b = append(b, ipb...)
	b = append(b, byte(ua.Port))
	b = append(b, byte(ua.Port>>8))
	return b
}

func (a *AddrSet) DstToBytes() []byte {
	return packIPPort(a.dst())
}
func (a *AddrSet) DstToString() string {
	dst := a.dst()
	return dst.String()
}
func (a *AddrSet) DstIP() net.IP {
	return a.dst().IP.IPAddr().IP // TODO: add netaddr accessor to cut an alloc here?
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

	if a.roamAddrStd != nil && equalUDPAddr(new, a.roamAddrStd) {
		// Packet from the current roaming address, no logging.
		// This is a hot path for established connections.
		return nil
	}
	if a.roamAddr == nil && a.curAddr >= 0 && equalUDPAddr(new, &a.addrs[a.curAddr]) {
		// Packet from current-priority address, no logging.
		// This is a hot path for established connections.
		return nil
	}

	newa, ok := netaddr.FromStdAddr(new.IP, new.Port, new.Zone)
	if !ok {
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
		a.roamAddr = &newa
		a.roamAddrStd = new

	case a.roamAddr != nil:
		a.Logf("magicsock: rx %s from known %s (%d), replaces roaming address %s", pk, new, index, a.roamAddr)
		a.roamAddr = nil
		a.roamAddrStd = nil
		a.curAddr = index
		a.loggedLogPriMask = 0

	case a.curAddr == -1:
		a.Logf("magicsock: rx %s from %s (%d/%d), set as new priority", pk, new, index, len(a.addrs))
		a.curAddr = index
		a.loggedLogPriMask = 0

	case index < a.curAddr:
		if 1 <= index && index <= 32 && (a.loggedLogPriMask&1<<(index-1)) == 0 {
			a.Logf("magicsock: rx %s from low-pri %s (%d), keeping current %s (%d)", pk, new, index, old, a.curAddr)
			a.loggedLogPriMask |= 1 << (index - 1)
		}

	default: // index > a.curAddr
		a.Logf("magicsock: rx %s from %s (%d/%d), replaces old priority %s", pk, new, index, len(a.addrs), old)
		a.curAddr = index
		a.loggedLogPriMask = 0
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
		sbPrintAddr(buf, *a.roamAddrStd)
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

func (as *AddrSet) populatePeerStatus(ps *ipnstate.PeerStatus) {
	as.mu.Lock()
	defer as.mu.Unlock()

	ps.LastWrite = as.lastSend
	for i, ua := range as.addrs {
		if ua.IP.Equal(derpMagicIP) {
			continue
		}
		uaStr := ua.String()
		ps.Addrs = append(ps.Addrs, uaStr)
		if as.curAddr == i {
			ps.CurAddr = uaStr
		}
	}
	if as.roamAddr != nil {
		ps.CurAddr = udpAddrDebugString(*as.roamAddrStd)
	}
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
//
// The key is the public key of the peer and addrs is either:
//
//  1) a comma-separated list of UDP ip:ports (the the peer doesn't have a discovery key)
//  2) "<hex-discovery-key>.disco.tailscale:12345", a magic value that means the peer
//     is running code that supports active discovery, so CreateEndpoint returns
//     a discoEndpoint.
//

func (c *Conn) CreateEndpoint(pubKey [32]byte, addrs string) (conn.Endpoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	pk := key.Public(pubKey)
	c.logf("magicsock: CreateEndpoint: key=%s: %s", pk.ShortString(), derpStr(addrs))

	if strings.HasSuffix(addrs, controlclient.EndpointDiscoSuffix) {
		discoHex := strings.TrimSuffix(addrs, controlclient.EndpointDiscoSuffix)
		discoKey, err := key.NewPublicFromHexMem(mem.S(discoHex))
		if err != nil {
			return nil, fmt.Errorf("magicsock: invalid discokey endpoint %q for %v: %w", addrs, pk.ShortString(), err)
		}
		de := &discoEndpoint{
			c:                  c,
			publicKey:          tailcfg.NodeKey(pk),        // peer public key (for WireGuard + DERP)
			discoKey:           tailcfg.DiscoKey(discoKey), // for discovery mesages
			discoShort:         tailcfg.DiscoKey(discoKey).ShortString(),
			wgEndpointHostPort: addrs,
			sentPing:           map[stun.TxID]sentPing{},
			endpointState:      map[netaddr.IPPort]*endpointState{},
		}
		de.initFakeUDPAddr()
		de.updateFromNode(c.nodeOfDisco[de.discoKey])
		c.endpointOfDisco[de.discoKey] = de
		return de, nil
	}

	a := &AddrSet{
		Logf:      c.logf,
		publicKey: pk,
		curAddr:   -1,
	}

	if addrs != "" {
		for _, ep := range strings.Split(addrs, ",") {
			ipp, err := netaddr.ParseIPPort(ep)
			if err != nil {
				return nil, fmt.Errorf("bogus address %q", ep)
			}
			a.ipPorts = append(a.ipPorts, ipp)
			a.addrs = append(a.addrs, *ipp.UDPAddr())
		}
	}

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

// singleEndpoint is a wireguard-go/conn.Endpoint used for "roaming
// addressed" in releases of Tailscale that predate discovery
// messages. New peers use discoEndpoint.
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
	// ippCache is a cache from UDPAddr => netaddr.IPPort. It's not safe for concurrent use.
	// This is used by ReceiveIPv6 and awaitUDP4 (called from ReceiveIPv4).
	ippCache ippCache

	mu    sync.Mutex
	pconn net.PacketConn
}

func (c *RebindingUDPConn) Reset(pconn net.PacketConn) {
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

func (c *Conn) derpRegionCodeOfAddrLocked(ipPort string) string {
	_, portStr, err := net.SplitHostPort(ipPort)
	if err != nil {
		return ""
	}
	regionID, err := strconv.Atoi(portStr)
	if err != nil {
		return ""
	}
	return c.derpRegionCodeOfIDLocked(regionID)
}

func (c *Conn) derpRegionCodeOfIDLocked(regionID int) string {
	if c.derpMap == nil {
		return ""
	}
	if r, ok := c.derpMap.Regions[regionID]; ok {
		return r.RegionCode
	}
	return ""
}

func (c *Conn) UpdateStatus(sb *ipnstate.StatusBuilder) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.netMap != nil {
		for _, addr := range c.netMap.Addresses {
			if (addr.IP.Is4() && addr.Mask != 32) || (addr.IP.Is6() && addr.Mask != 128) {
				continue
			}
			if ip, ok := netaddr.FromStdIP(addr.IP.IP()); ok {
				sb.AddTailscaleIP(ip)
			}
		}
	}

	for dk, n := range c.nodeOfDisco {
		ps := &ipnstate.PeerStatus{InMagicSock: true}
		ps.Addrs = append(ps.Addrs, n.Endpoints...)
		ps.Relay = c.derpRegionCodeOfAddrLocked(n.DERP)
		if de, ok := c.endpointOfDisco[dk]; ok {
			de.populatePeerStatus(ps)
		}
		sb.AddPeer(key.Public(n.Key), ps)
	}
	// Old-style (pre-disco) peers:
	for k, as := range c.addrsByKey {
		ps := &ipnstate.PeerStatus{
			InMagicSock: true,
			Relay:       c.derpRegionCodeOfIDLocked(as.derpID()),
		}
		as.populatePeerStatus(ps)
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

// discoEndpoint is a wireguard/conn.Endpoint for new-style peers that
// advertise a DiscoKey and participate in active discovery.
type discoEndpoint struct {
	// atomically accessed; declared first for alignment reasons
	lastRecvUnixAtomic int64

	// These fields are initialized once and never modified.
	c                  *Conn
	publicKey          tailcfg.NodeKey  // peer public key (for WireGuard + DERP)
	discoKey           tailcfg.DiscoKey // for discovery mesages
	discoShort         string           // ShortString of discoKey
	fakeWGAddr         netaddr.IPPort   // the UDP address we tell wireguard-go we're using
	fakeWGAddrStd      *net.UDPAddr     // the *net.UDPAddr form of fakeWGAddr
	wgEndpointHostPort string           // string from CreateEndpoint: "<hex-discovery-key>.disco.tailscale:12345"

	// Owned by Conn.mu:
	lastPingFrom netaddr.IPPort
	lastPingTime time.Time

	// mu protects all following fields.
	mu sync.Mutex // Lock ordering: Conn.mu, then discoEndpoint.mu

	heartBeatTimer *time.Timer    // nil when idle
	lastSend       time.Time      // last time there was outgoing packets sent to this peer (from wireguard-go)
	lastFullPing   time.Time      // last time we pinged all endpoints
	derpAddr       netaddr.IPPort // fallback/bootstrap path, if non-zero (non-zero for well-behaved clients)

	bestAddr           netaddr.IPPort // best non-DERP path; zero if none
	bestAddrLatency    time.Duration
	bestAddrAt         time.Time // time best address re-confirmed
	trustBestAddrUntil time.Time // time when bestAddr expires
	sentPing           map[stun.TxID]sentPing
	endpointState      map[netaddr.IPPort]*endpointState

	pendingCLIPings []pendingCLIPing // any outstanding "tailscale ping" commands running
}

type pendingCLIPing struct {
	res *ipnstate.PingResult
	cb  func(*ipnstate.PingResult)
}

const (
	// sessionActiveTimeout is how long since the last activity we
	// try to keep an established discoEndpoint peering alive.
	sessionActiveTimeout = 2 * time.Minute

	// upgradeInterval is how often we try to upgrade to a better path
	// even if we have some non-DERP route that works.
	upgradeInterval = 1 * time.Minute

	// heartbeatInterval is how often pings to the best UDP address
	// are sent.
	heartbeatInterval = 2 * time.Second

	// discoPingInterval is the minimum time between pings
	// to an endpoint. (Except in the case of CallMeMaybe frames
	// resetting the counter, as the first pings likely didn't through
	// the firewall)
	discoPingInterval = 5 * time.Second

	// pingTimeoutDuration is how long we wait for a pong reply before
	// assuming it's never coming.
	pingTimeoutDuration = 5 * time.Second

	// trustUDPAddrDuration is how long we trust a UDP address as the exclusive
	// path (without using DERP) without having heard a Pong reply.
	trustUDPAddrDuration = 5 * time.Second

	// goodEnoughLatency is the latency at or under which we don't
	// try to upgrade to a better path.
	goodEnoughLatency = 5 * time.Millisecond
)

// endpointState is some state and history for a specific endpoint of
// a discoEndpoint. (The subject is the discoEndpoint.endpointState
// map key)
type endpointState struct {
	// all fields guarded by discoEndpoint.mu:
	lastPing    time.Time
	recentPongs []pongReply // ring buffer up to pongHistoryCount entries
	recentPong  uint16      // index into recentPongs of most recent; older before, wrapped
	index       int16       // index in nodecfg.Node.Endpoints
}

// pongHistoryCount is how many pongReply values we keep per endpointState
const pongHistoryCount = 64

type pongReply struct {
	latency time.Duration
	pongAt  time.Time      // when we received the pong
	from    netaddr.IPPort // the pong's src (usually same as endpoint map key)
	pongSrc netaddr.IPPort // what they reported they heard
}

type sentPing struct {
	to      netaddr.IPPort
	at      time.Time
	timer   *time.Timer // timeout timer
	purpose discoPingPurpose
}

// initFakeUDPAddr populates fakeWGAddr with a globally unique fake UDPAddr.
// The current implementation just uses the pointer value of de jammed into an IPv6
// address, but it could also be, say, a counter.
func (de *discoEndpoint) initFakeUDPAddr() {
	var addr [16]byte
	addr[0] = 0xfd
	addr[1] = 0x00
	binary.BigEndian.PutUint64(addr[2:], uint64(reflect.ValueOf(de).Pointer()))
	de.fakeWGAddr = netaddr.IPPort{
		IP:   netaddr.IPFrom16(addr),
		Port: 12345,
	}
	de.fakeWGAddrStd = de.fakeWGAddr.UDPAddr()
}

// isFirstRecvActivityInAwhile notes that receive activity has occured for this
// endpoint and reports whether it's been at least 10 seconds since the last
// receive activity (including having never received from this peer before).
func (de *discoEndpoint) isFirstRecvActivityInAwhile() bool {
	now := time.Now().Unix()
	old := atomic.LoadInt64(&de.lastRecvUnixAtomic)
	if old <= now-10 {
		atomic.StoreInt64(&de.lastRecvUnixAtomic, now)
		return true
	}
	return false
}

// String exists purely so wireguard-go internals can log.Printf("%v")
// its internal conn.Endpoints and we don't end up with data races
// from fmt (via log) reading mutex fields and such.
func (de *discoEndpoint) String() string {
	return fmt.Sprintf("magicsock.discoEndpoint{%v, %v}", de.publicKey.ShortString(), de.discoShort)
}

func (de *discoEndpoint) Addrs() []wgcfg.Endpoint {
	// This has to be the same string that was passed to
	// CreateEndpoint, otherwise Reconfig will end up recreating
	// Endpoints and losing state over time.
	host, portStr, err := net.SplitHostPort(de.wgEndpointHostPort)
	if err != nil {
		panic(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		panic(err)
	}
	return []wgcfg.Endpoint{{Host: host, Port: uint16(port)}}
}

func (de *discoEndpoint) ClearSrc()           {}
func (de *discoEndpoint) SrcToString() string { panic("unused") } // unused by wireguard-go
func (de *discoEndpoint) SrcIP() net.IP       { panic("unused") } // unused by wireguard-go
func (de *discoEndpoint) DstToString() string { return de.wgEndpointHostPort }
func (de *discoEndpoint) DstIP() net.IP       { panic("unused") }
func (de *discoEndpoint) DstToBytes() []byte  { return packIPPort(de.fakeWGAddr) }
func (de *discoEndpoint) UpdateDst(addr *net.UDPAddr) error {
	// This is called ~per packet (and requiring a mutex acquisition inside wireguard-go).
	// TODO(bradfitz): make that cheaper and/or remove it. We don't need it.
	return nil
}

// addrForSendLocked returns the address(es) that should be used for
// sending the next packet. Zero, one, or both of UDP address and DERP
// addr may be non-zero.
//
// de.mu must be held.
func (de *discoEndpoint) addrForSendLocked(now time.Time) (udpAddr, derpAddr netaddr.IPPort) {
	udpAddr = de.bestAddr
	if udpAddr.IsZero() || now.After(de.trustBestAddrUntil) {
		// We had a bestAddr but it expired so send both to it
		// and DERP.
		derpAddr = de.derpAddr
	}
	return
}

// heartbeat is called every heartbeatInterval to keep the best UDP path alive,
// or kick off discovery of other paths.
func (de *discoEndpoint) heartbeat() {
	de.mu.Lock()
	defer de.mu.Unlock()

	de.heartBeatTimer = nil

	if de.lastSend.IsZero() {
		// Shouldn't happen.
		return
	}

	if time.Since(de.lastSend) > sessionActiveTimeout {
		// Session's idle. Stop heartbeating.
		de.c.logf("magicsock: disco: ending heartbeats for idle session to %v (%v)", de.publicKey.ShortString(), de.discoShort)
		return
	}

	now := time.Now()
	udpAddr, _ := de.addrForSendLocked(now)
	if !udpAddr.IsZero() {
		// We have a preferred path. Ping that every 2 seconds.
		de.startPingLocked(udpAddr, now, pingHeartbeat)
	}

	if de.wantFullPingLocked(now) {
		de.sendPingsLocked(now, true)
	}

	de.heartBeatTimer = time.AfterFunc(heartbeatInterval, de.heartbeat)
}

// wantFullPingLocked reports whether we should ping to all our peers looking for
// a better path.
//
// de.mu must be held.
func (de *discoEndpoint) wantFullPingLocked(now time.Time) bool {
	if de.bestAddr.IsZero() || de.lastFullPing.IsZero() {
		return true
	}
	if now.After(de.trustBestAddrUntil) {
		return true
	}
	if de.bestAddrLatency <= goodEnoughLatency {
		return false
	}
	if now.Sub(de.lastFullPing) >= upgradeInterval {
		return true
	}
	return false
}

func (de *discoEndpoint) noteActiveLocked() {
	de.lastSend = time.Now()
	if de.heartBeatTimer == nil {
		de.heartBeatTimer = time.AfterFunc(heartbeatInterval, de.heartbeat)
	}
}

// cliPing starts a ping for the "tailscale ping" command. res is value to call cb with,
// already partially filled.
func (de *discoEndpoint) cliPing(res *ipnstate.PingResult, cb func(*ipnstate.PingResult)) {
	de.mu.Lock()
	defer de.mu.Unlock()

	de.pendingCLIPings = append(de.pendingCLIPings, pendingCLIPing{res, cb})

	now := time.Now()
	udpAddr, derpAddr := de.addrForSendLocked(now)
	if !derpAddr.IsZero() {
		de.startPingLocked(derpAddr, now, pingCLI)
	}
	if !udpAddr.IsZero() && now.Before(de.trustBestAddrUntil) {
		// Already have an active session, so just ping the address we're using.
		// Otherwise "tailscale ping" results to a node on the local network
		// can look like they're bouncing between, say 10.0.0.0/9 and the peer's
		// IPv6 address, both 1ms away, and it's random who replies first.
		de.startPingLocked(udpAddr, now, pingCLI)
	} else {
		for ep := range de.endpointState {
			de.startPingLocked(ep, now, pingCLI)
		}
	}
	de.noteActiveLocked()
}

func (de *discoEndpoint) send(b []byte) error {
	now := time.Now()

	de.mu.Lock()
	udpAddr, derpAddr := de.addrForSendLocked(now)
	if udpAddr.IsZero() || now.After(de.trustBestAddrUntil) {
		de.sendPingsLocked(now, true)
	}
	de.noteActiveLocked()
	de.mu.Unlock()

	if udpAddr.IsZero() && derpAddr.IsZero() {
		return errors.New("no UDP or DERP addr")
	}
	var err error
	if !udpAddr.IsZero() {
		_, err = de.c.sendAddr(udpAddr, key.Public(de.publicKey), b)
	}
	if !derpAddr.IsZero() {
		if ok, _ := de.c.sendAddr(derpAddr, key.Public(de.publicKey), b); ok && err != nil {
			// UDP failed but DERP worked, so good enough:
			return nil
		}
	}
	return err
}

func (de *discoEndpoint) pingTimeout(txid stun.TxID) {
	de.mu.Lock()
	defer de.mu.Unlock()
	sp, ok := de.sentPing[txid]
	if !ok {
		return
	}
	if debugDisco || de.bestAddr.IsZero() || time.Now().After(de.trustBestAddrUntil) {
		de.c.logf("magicsock: disco: timeout waiting for pong %x from %v (%v, %v)", txid[:6], sp.to, de.publicKey.ShortString(), de.discoShort)
	}
	de.removeSentPingLocked(txid, sp)
}

// forgetPing is called by a timer when a ping either fails to send or
// has taken too long to get a pong reply.
func (de *discoEndpoint) forgetPing(txid stun.TxID) {
	de.mu.Lock()
	defer de.mu.Unlock()
	if sp, ok := de.sentPing[txid]; ok {
		de.removeSentPingLocked(txid, sp)
	}
}

func (de *discoEndpoint) removeSentPingLocked(txid stun.TxID, sp sentPing) {
	// Stop the timer for the case where sendPing failed to write to UDP.
	// In the case of a timer already having fired, this is a no-op:
	sp.timer.Stop()
	delete(de.sentPing, txid)
}

// sendDiscoPing sends a ping with the provided txid to ep.
//
// The caller (startPingLocked) should've already been recorded the ping in
// sentPing and set up the timer.
func (de *discoEndpoint) sendDiscoPing(ep netaddr.IPPort, txid stun.TxID, logLevel discoLogLevel) {
	sent, _ := de.sendDiscoMessage(ep, &disco.Ping{TxID: [12]byte(txid)}, logLevel)
	if !sent {
		de.forgetPing(txid)
	}
}

// discoPingPurpose is the reason why a discovery ping message was sent.
type discoPingPurpose int

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

func (de *discoEndpoint) startPingLocked(ep netaddr.IPPort, now time.Time, purpose discoPingPurpose) {
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
		timer:   time.AfterFunc(pingTimeoutDuration, func() { de.pingTimeout(txid) }),
		purpose: purpose,
	}
	logLevel := discoLog
	if purpose == pingHeartbeat {
		logLevel = discoVerboseLog
	}
	go de.sendDiscoPing(ep, txid, logLevel)
}

func (de *discoEndpoint) sendPingsLocked(now time.Time, sendCallMeMaybe bool) {
	de.lastFullPing = now
	var sentAny bool
	for ep, st := range de.endpointState {
		ep := ep
		if !st.lastPing.IsZero() && now.Sub(st.lastPing) < discoPingInterval {
			continue
		}

		firstPing := !sentAny
		sentAny = true

		if firstPing && sendCallMeMaybe {
			de.c.logf("magicsock: disco: send, starting discovery for %v (%v)", de.publicKey.ShortString(), de.discoShort)
		}

		de.startPingLocked(ep, now, pingDiscovery)
	}
	derpAddr := de.derpAddr
	if sentAny && sendCallMeMaybe && !derpAddr.IsZero() {
		// In just a bit of a time (for goroutines above to schedule and run),
		// send a message to peer via DERP informing them that we've sent
		// so our firewall ports are probably open and now would be a good time
		// for them to connect.
		time.AfterFunc(5*time.Millisecond, func() {
			de.sendDiscoMessage(derpAddr, disco.CallMeMaybe{}, discoLog)
		})
	}
}

func (de *discoEndpoint) sendDiscoMessage(dst netaddr.IPPort, dm disco.Message, logLevel discoLogLevel) (sent bool, err error) {
	return de.c.sendDiscoMessage(dst, de.publicKey, de.discoKey, dm, logLevel)
}

func (de *discoEndpoint) updateFromNode(n *tailcfg.Node) {
	if n == nil {
		// TODO: log, error, count? if this even happens.
		return
	}
	de.mu.Lock()
	defer de.mu.Unlock()

	if n.DERP == "" {
		de.derpAddr = netaddr.IPPort{}
	} else {
		de.derpAddr, _ = netaddr.ParseIPPort(n.DERP)
	}

	for _, st := range de.endpointState {
		st.index = -1 // assume deleted until updated in next loop
	}
	for i, epStr := range n.Endpoints {
		if i > math.MaxInt16 {
			// Seems unlikely.
			continue
		}
		ipp, err := netaddr.ParseIPPort(epStr)
		if err != nil {
			de.c.logf("magicsock: bogus netmap endpoint %q", epStr)
			continue
		}
		if st, ok := de.endpointState[ipp]; ok {
			st.index = int16(i)
		} else {
			de.endpointState[ipp] = &endpointState{index: int16(i)}
		}
	}
	// Now delete anything that wasn't updated.
	for ipp, st := range de.endpointState {
		if st.index == -1 {
			delete(de.endpointState, ipp)
			if de.bestAddr == ipp {
				de.bestAddr = netaddr.IPPort{}
			}
		}
	}
}

// noteConnectivityChange is called when connectivity changes enough
// that we should question our earlier assumptions about which paths
// work.
func (de *discoEndpoint) noteConnectivityChange() {
	de.mu.Lock()
	defer de.mu.Unlock()

	de.trustBestAddrUntil = time.Time{}
}

// handlePongConnLocked handles a Pong message (a reply to an earlier ping).
// It should be called with the Conn.mu held.
func (de *discoEndpoint) handlePongConnLocked(m *disco.Pong, src netaddr.IPPort) {
	de.mu.Lock()
	defer de.mu.Unlock()

	isDerp := src.IP == derpMagicIPAddr

	sp, ok := de.sentPing[m.TxID]
	if !ok {
		// This is not a pong for a ping we sent. Ignore.
		return
	}
	de.removeSentPingLocked(m.TxID, sp)

	now := time.Now()
	latency := now.Sub(sp.at)

	if !isDerp {
		st, ok := de.endpointState[sp.to]
		if !ok {
			// This is no longer an endpoint we care about.
			return
		}

		de.c.setAddrToDiscoLocked(src, de.discoKey, de)

		st.addPongReplyLocked(pongReply{
			latency: latency,
			pongAt:  now,
			from:    src,
			pongSrc: m.Src,
		})
	}

	if sp.purpose != pingHeartbeat {
		de.c.logf("magicsock: disco: %v<-%v (%v, %v)  got pong tx=%x latency=%v pong.src=%v%v", de.c.discoShort, de.discoShort, de.publicKey.ShortString(), src, m.TxID[:6], latency.Round(time.Millisecond), m.Src, logger.ArgWriter(func(bw *bufio.Writer) {
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
		if de.bestAddr.IsZero() || latency < de.bestAddrLatency {
			if de.bestAddr != sp.to {
				de.c.logf("magicsock: disco: node %v %v now using %v", de.publicKey.ShortString(), de.discoShort, sp.to)
				de.bestAddr = sp.to
			}
		}
		if de.bestAddr == sp.to {
			de.bestAddrLatency = latency
			de.bestAddrAt = now
			de.trustBestAddrUntil = now.Add(trustUDPAddrDuration)
		}
	}
}

// discoEndpoint.mu must be held.
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

// handleCallMeMaybe handles a CallMeMaybe discovery message via
// DERP. The contract for use of this message is that the peer has
// already sent to us via UDP, so their stateful firewall should be
// open. Now we can Ping back and make it through.
func (de *discoEndpoint) handleCallMeMaybe() {
	de.mu.Lock()
	defer de.mu.Unlock()

	// Zero out all the lastPing times to force sendPingsLocked to send new ones,
	// even if it's been less than 5 seconds ago.
	for _, st := range de.endpointState {
		st.lastPing = time.Time{}
	}
	de.sendPingsLocked(time.Now(), false)
}

func (de *discoEndpoint) populatePeerStatus(ps *ipnstate.PeerStatus) {
	de.mu.Lock()
	defer de.mu.Unlock()

	if de.lastSend.IsZero() {
		return
	}

	ps.LastWrite = de.lastSend

	now := time.Now()
	if udpAddr, derpAddr := de.addrForSendLocked(now); !udpAddr.IsZero() && derpAddr.IsZero() {
		ps.CurAddr = udpAddr.String()
	}
}

// stopAndReset stops timers associated with de and resets its state back to zero.
// It's called when a discovery endpoint is no longer present in the NetworkMap,
// or when magicsock is transition from running to stopped state (via SetPrivateKey(zero))
func (de *discoEndpoint) stopAndReset() {
	de.mu.Lock()
	defer de.mu.Unlock()

	de.c.logf("magicsock: doing cleanup for discovery key %x", de.discoKey[:])

	// Zero these fields so if the user re-starts the network, the discovery
	// state isn't a mix of before & after two sessions.
	de.lastSend = time.Time{}
	de.lastFullPing = time.Time{}
	de.bestAddr = netaddr.IPPort{}
	de.bestAddrLatency = 0
	de.bestAddrAt = time.Time{}
	de.trustBestAddrUntil = time.Time{}
	for _, es := range de.endpointState {
		es.lastPing = time.Time{}
	}

	for txid, sp := range de.sentPing {
		de.removeSentPingLocked(txid, sp)
	}
	if de.heartBeatTimer != nil {
		de.heartBeatTimer.Stop()
		de.heartBeatTimer = nil
	}
	de.pendingCLIPings = nil
}

// ippCache is a cache of *net.UDPAddr => netaddr.IPPort mappings.
//
// It's not safe for concurrent use.
type ippCache struct {
	c *lru.Cache
}

// IPPort is a caching wrapper around netaddr.FromStdAddr.
//
// It is not safe for concurrent use.
func (ic *ippCache) IPPort(u *net.UDPAddr) (netaddr.IPPort, bool) {
	if u == nil || len(u.IP) > 16 {
		return netaddr.IPPort{}, false
	}
	if ic.c == nil {
		ic.c = lru.New(64) // arbitrary
	}

	key := ippCacheKey{ipLen: uint8(len(u.IP)), port: uint16(u.Port), zone: u.Zone}
	copy(key.ip[:], u.IP[:])

	if v, ok := ic.c.Get(key); ok {
		return v.(netaddr.IPPort), true
	}
	ipp, ok := netaddr.FromStdAddr(u.IP, u.Port, u.Zone)
	if ok {
		ic.c.Add(key, ipp)
	}
	return ipp, ok
}

// ippCacheKey is the cache key type used by ippCache.IPPort.
// It must be comparable, being used as a map key in the lru package.
type ippCacheKey struct {
	ip    [16]byte
	port  uint16
	ipLen uint8 // bytes in ip that are valid; rest are zero
	zone  string
}

// derpStr replaces DERP IPs in s with "derp-".
func derpStr(s string) string { return strings.ReplaceAll(s, "127.3.3.40:", "derp-") }
