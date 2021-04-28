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
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"go4.org/mem"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/time/rate"
	"inet.af/netaddr"
	"tailscale.com/control/controlclient"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/disco"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netns"
	"tailscale.com/net/portmapper"
	"tailscale.com/net/stun"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/nettype"
	"tailscale.com/types/wgkey"
	"tailscale.com/util/uniq"
	"tailscale.com/version"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/wgcfg"
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
	debugUseDerpRouteEnv = os.Getenv("TS_DEBUG_ENABLE_DERP_ROUTE")
	debugUseDerpRoute, _ = strconv.ParseBool(debugUseDerpRouteEnv)
	// logDerpVerbose logs all received DERP packets, including their
	// full payload.
	logDerpVerbose, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_DERP"))
	// debugReSTUNStopOnIdle unconditionally enables the "shut down
	// STUN if magicsock is idle" behavior that normally only triggers
	// on mobile devices, lowers the shutdown interval, and logs more
	// verbosely about idle measurements.
	debugReSTUNStopOnIdle, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_RESTUN_STOP_ON_IDLE"))
)

// useDerpRoute reports whether magicsock should enable the DERP
// return path optimization (Issue 150).
func useDerpRoute() bool {
	if debugUseDerpRouteEnv != "" {
		return debugUseDerpRoute
	}
	ob := controlclient.DERPRouteFlag()
	if v, ok := ob.Get(); ok {
		return v
	}
	return false
}

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
	// This block mirrors the contents and field order of the Options
	// struct. Initialized once at construction, then constant.

	logf             logger.Logf
	port             uint16 // the preferred port from opts.Port; 0 means auto
	epFunc           func([]tailcfg.Endpoint)
	derpActiveFunc   func()
	idleFunc         func() time.Duration // nil means unknown
	packetListener   nettype.PacketListener
	noteRecvActivity func(tailcfg.DiscoKey) // or nil, see Options.NoteRecvActivity
	simulatedNetwork bool
	disableLegacy    bool

	// ================================================================
	// No locking required to access these fields, either because
	// they're static after construction, or are wholly owned by a
	// single goroutine.

	connCtx       context.Context // closed on Conn.Close
	connCtxCancel func()          // closes connCtx
	donec         <-chan struct{} // connCtx.Done()'s to avoid context.cancelCtx.Done()'s mutex per call

	// pconn4 and pconn6 are the underlying UDP sockets used to
	// send/receive packets for wireguard and other magicsock
	// protocols.
	pconn4 *RebindingUDPConn
	pconn6 *RebindingUDPConn

	// netChecker is the prober that discovers local network
	// conditions, including the closest DERP relay and NAT mappings.
	netChecker *netcheck.Client

	// portMapper is the NAT-PMP/PCP/UPnP prober/client, for requesting
	// port mappings from NAT devices.
	portMapper *portmapper.Client

	// sendLogLimit is a rate limiter for errors logged in the (hot)
	// packet sending codepath. It's so that, if magicsock gets into a
	// bad state, we don't spam one error per wireguard packet being
	// transmitted.
	// TODO(danderson): now that we have global rate-limiting, is this still useful?
	sendLogLimit *rate.Limiter

	// stunReceiveFunc holds the current STUN packet processing func.
	// Its Loaded value is always non-nil.
	stunReceiveFunc atomic.Value // of func(p []byte, fromAddr *net.UDPAddr)

	// derpRecvCh is used by receiveDERP to read DERP messages.
	derpRecvCh chan derpReadResult

	// bind is the wireguard-go conn.Bind for Conn.
	bind *connBind

	// ippEndpoint4 and ippEndpoint6 are owned by receiveIPv4 and
	// receiveIPv6, respectively, to cache an IPPort->endpoint for
	// hot flows.
	ippEndpoint4, ippEndpoint6 ippEndpointCache

	// ============================================================
	mu     sync.Mutex // guards all following fields; see userspaceEngine lock ordering rules
	muCond *sync.Cond

	started bool // Start was called
	closed  bool // Close was called

	// derpCleanupTimer is the timer that fires to occasionally clean
	// up idle DERP connections. It's only used when there is a non-home
	// DERP connection in use.
	derpCleanupTimer *time.Timer

	// derpCleanupTimerArmed is whether derpCleanupTimer is
	// scheduled to fire within derpCleanStaleInterval.
	derpCleanupTimerArmed bool

	// periodicReSTUNTimer, when non-nil, is an AfterFunc timer
	// that will call Conn.doPeriodicSTUN.
	periodicReSTUNTimer *time.Timer

	// endpointsUpdateActive indicates that updateEndpoints is
	// currently running. It's used to deduplicate concurrent endpoint
	// update requests.
	endpointsUpdateActive bool
	// wantEndpointsUpdate, if non-empty, means that a new endpoints
	// update should begin immediately after the currently-running one
	// completes. It can only be non-empty if
	// endpointsUpdateActive==true.
	wantEndpointsUpdate string // true if non-empty; string is reason
	// lastEndpoints records the endpoints found during the previous
	// endpoint discovery. It's used to avoid duplicate endpoint
	// change notifications.
	lastEndpoints []tailcfg.Endpoint

	// lastEndpointsTime is the last time the endpoints were updated,
	// even if there was no change.
	lastEndpointsTime time.Time

	// onEndpointRefreshed are funcs to run (in their own goroutines)
	// when endpoints are refreshed.
	onEndpointRefreshed map[*discoEndpoint]func()

	// peerSet is the set of peers that are currently configured in
	// WireGuard. These are not used to filter inbound or outbound
	// traffic at all, but only to track what state can be cleaned up
	// in other maps below that are keyed by peer public key.
	peerSet map[key.Public]struct{}

	// discoPrivate is the private naclbox key used for active
	// discovery traffic. It's created once near (but not during)
	// construction.
	discoPrivate key.Private
	discoPublic  tailcfg.DiscoKey // public of discoPrivate
	discoShort   string           // ShortString of discoPublic (to save logging work later)
	// nodeOfDisco tracks the networkmap Node entity for each peer
	// discovery key.
	//
	// TODO(danderson): the only thing we ever use from this is the
	// peer's WireGuard public key. This could be a map of DiscoKey to
	// NodeKey.
	nodeOfDisco map[tailcfg.DiscoKey]*tailcfg.Node
	discoOfNode map[tailcfg.NodeKey]tailcfg.DiscoKey
	discoOfAddr map[netaddr.IPPort]tailcfg.DiscoKey // validated non-DERP paths only
	// endpointsOfDisco tracks the wireguard-go endpoints for peers
	// with recent activity.
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
	//
	// Used only to communicate with legacy, pre-active-discovery
	// clients.
	addrsByUDP map[netaddr.IPPort]*addrSet
	// addrsByKey maps from public keys (as seen by incoming DERP
	// packets) to its addrSet (the same values as in addrsByUDP).
	//
	// Used only to communicate with legacy, pre-active-discovery
	// clients.
	addrsByKey map[key.Public]*addrSet

	// netInfoFunc is a callback that provides a tailcfg.NetInfo when
	// discovered network conditions change.
	//
	// TODO(danderson): why can't it be set at construction time?
	// There seem to be a few natural places in ipn/local.go to
	// swallow untimely invocations.
	netInfoFunc func(*tailcfg.NetInfo) // nil until set
	// netInfoLast is the NetInfo provided in the last call to
	// netInfoFunc. It's used to deduplicate calls to netInfoFunc.
	//
	// TODO(danderson): should all the deduping happen in
	// ipn/local.go? We seem to be doing dedupe at several layers, and
	// magicsock could do with any complexity reduction it can get.
	netInfoLast *tailcfg.NetInfo

	derpMap     *tailcfg.DERPMap // nil (or zero regions/nodes) means DERP is disabled
	netMap      *netmap.NetworkMap
	privateKey  key.Private        // WireGuard private key for this node
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

	// networkUp is whether the network is up (some interface is up
	// with IPv4 or IPv6). It's used to suppress log spam and prevent
	// new connection that'll fail.
	networkUp syncs.AtomicBool

	// havePrivateKey is whether privateKey is non-zero.
	havePrivateKey syncs.AtomicBool
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

var derpMagicIPAddr = netaddr.MustParseIP(DerpMagicIP)

// activeDerp contains fields for an active DERP connection.
type activeDerp struct {
	c       *derphttp.Client
	cancel  context.CancelFunc
	writeCh chan<- derpWriteRequest
	// lastWrite is the time of the last request for its write
	// channel (currently even if there was no write).
	// It is always non-nil and initialized to a non-zero Time.
	lastWrite  *time.Time
	createTime time.Time
}

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
	EndpointsFunc func([]tailcfg.Endpoint)

	// DERPActiveFunc optionally provides a func to be called when
	// a connection is made to a DERP server.
	DERPActiveFunc func()

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
	// enough and not too often.) The provided func is called
	// while holding userspaceEngine.wgLock and likely calls
	// Conn.CreateEndpoint, which acquires Conn.mu. As such, you
	// should not hold Conn.mu while calling it.
	NoteRecvActivity func(tailcfg.DiscoKey)

	// SimulatedNetwork can be set true in tests to signal that
	// the network is simulated and thus it's okay to bind on the
	// unspecified address (which we'd normally avoid to avoid
	// triggering macOS and Windows firwall dialog boxes during
	// "go test").
	SimulatedNetwork bool

	// DisableLegacyNetworking disables legacy peer handling. When
	// enabled, only active discovery-aware nodes will be able to
	// communicate with Conn.
	DisableLegacyNetworking bool

	// LinkMonitor is the link monitor to use.
	// With one, the portmapper won't be used.
	LinkMonitor *monitor.Mon
}

func (o *Options) logf() logger.Logf {
	if o.Logf == nil {
		panic("must provide magicsock.Options.logf")
	}
	return o.Logf
}

func (o *Options) endpointsFunc() func([]tailcfg.Endpoint) {
	if o == nil || o.EndpointsFunc == nil {
		return func([]tailcfg.Endpoint) {}
	}
	return o.EndpointsFunc
}

func (o *Options) derpActiveFunc() func() {
	if o == nil || o.DERPActiveFunc == nil {
		return func() {}
	}
	return o.DERPActiveFunc
}

// newConn is the error-free, network-listening-side-effect-free based
// of NewConn. Mostly for tests.
func newConn() *Conn {
	c := &Conn{
		disableLegacy:   true,
		sendLogLimit:    rate.NewLimiter(rate.Every(1*time.Minute), 1),
		addrsByUDP:      make(map[netaddr.IPPort]*addrSet),
		addrsByKey:      make(map[key.Public]*addrSet),
		derpRecvCh:      make(chan derpReadResult),
		derpStarted:     make(chan struct{}),
		peerLastDerp:    make(map[key.Public]int),
		endpointOfDisco: make(map[tailcfg.DiscoKey]*discoEndpoint),
		sharedDiscoKey:  make(map[tailcfg.DiscoKey]*[32]byte),
		discoOfAddr:     make(map[netaddr.IPPort]tailcfg.DiscoKey),
	}
	c.bind = &connBind{Conn: c, closed: true}
	c.muCond = sync.NewCond(&c.mu)
	c.networkUp.Set(true) // assume up until told otherwise
	return c
}

// NewConn creates a magic Conn listening on opts.Port.
// As the set of possible endpoints for a Conn changes, the
// callback opts.EndpointsFunc is called.
//
// It doesn't start doing anything until Start is called.
func NewConn(opts Options) (*Conn, error) {
	c := newConn()
	c.port = opts.Port
	c.logf = opts.logf()
	c.epFunc = opts.endpointsFunc()
	c.derpActiveFunc = opts.derpActiveFunc()
	c.idleFunc = opts.IdleFunc
	c.packetListener = opts.PacketListener
	c.noteRecvActivity = opts.NoteRecvActivity
	c.simulatedNetwork = opts.SimulatedNetwork
	c.disableLegacy = opts.DisableLegacyNetworking
	c.portMapper = portmapper.NewClient(logger.WithPrefix(c.logf, "portmapper: "))
	if opts.LinkMonitor != nil {
		c.portMapper.SetGatewayLookupFunc(opts.LinkMonitor.GatewayAndSelfIP)
	}

	if err := c.initialBind(); err != nil {
		return nil, err
	}

	c.connCtx, c.connCtxCancel = context.WithCancel(context.Background())
	c.donec = c.connCtx.Done()
	c.netChecker = &netcheck.Client{
		Logf:                logger.WithPrefix(c.logf, "netcheck: "),
		GetSTUNConn4:        func() netcheck.STUNConn { return c.pconn4 },
		SkipExternalNetwork: inTest(),
		PortMapper:          c.portMapper,
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
}

// ignoreSTUNPackets sets a STUN packet processing func that does nothing.
func (c *Conn) ignoreSTUNPackets() {
	c.stunReceiveFunc.Store(func([]byte, netaddr.IPPort) {})
}

// doPeriodicSTUN is called (in a new goroutine) by
// periodicReSTUNTimer when periodic STUNs are active.
func (c *Conn) doPeriodicSTUN() { c.ReSTUN("periodic") }

func (c *Conn) stopPeriodicReSTUNTimerLocked() {
	if t := c.periodicReSTUNTimer; t != nil {
		t.Stop()
		c.periodicReSTUNTimer = nil
	}
}

// c.mu must NOT be held.
func (c *Conn) updateEndpoints(why string) {
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		why := c.wantEndpointsUpdate
		c.wantEndpointsUpdate = ""
		if !c.closed {
			if why != "" {
				go c.updateEndpoints(why)
				return
			}
			if c.shouldDoPeriodicReSTUNLocked() {
				// Pick a random duration between 20
				// and 26 seconds (just under 30s, a
				// common UDP NAT timeout on Linux,
				// etc)
				d := tstime.RandomDurationBetween(20*time.Second, 26*time.Second)
				if t := c.periodicReSTUNTimer; t != nil {
					if debugReSTUNStopOnIdle {
						c.logf("resetting existing periodicSTUN to run in %v", d)
					}
					t.Reset(d)
				} else {
					if debugReSTUNStopOnIdle {
						c.logf("scheduling periodicSTUN to run in %v", d)
					}
					c.periodicReSTUNTimer = time.AfterFunc(d, c.doPeriodicSTUN)
				}
			} else {
				if debugReSTUNStopOnIdle {
					c.logf("periodic STUN idle")
				}
				c.stopPeriodicReSTUNTimerLocked()
			}
		}
		c.endpointsUpdateActive = false
		c.muCond.Broadcast()
	}()
	c.logf("[v1] magicsock: starting endpoint update (%s)", why)

	endpoints, err := c.determineEndpoints(c.connCtx)
	if err != nil {
		c.logf("magicsock: endpoint update (%s) failed: %v", why, err)
		// TODO(crawshaw): are there any conditions under which
		// we should trigger a retry based on the error here?
		return
	}

	if c.setEndpoints(endpoints) {
		c.logEndpointChange(endpoints)
		c.epFunc(endpoints)
	}
}

// setEndpoints records the new endpoints, reporting whether they're changed.
// It takes ownership of the slice.
func (c *Conn) setEndpoints(endpoints []tailcfg.Endpoint) (changed bool) {
	anySTUN := false
	for _, ep := range endpoints {
		if ep.Type == tailcfg.EndpointSTUN {
			anySTUN = true
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !anySTUN && c.derpMap == nil && !inTest() {
		// Don't bother storing or reporting this yet. We
		// don't have a DERP map or any STUN entries, so we're
		// just starting up. A DERP map should arrive shortly
		// and then we'll have more interesting endpoints to
		// report. This saves a map update.
		// TODO(bradfitz): this optimization is currently
		// skipped during the e2e tests because they depend
		// too much on the exact sequence of updates.  Fix the
		// tests. But a protocol rewrite might happen first.
		c.logf("[v1] magicsock: ignoring pre-DERP map, STUN-less endpoint update: %v", endpoints)
		return false
	}

	c.lastEndpointsTime = time.Now()
	for de, fn := range c.onEndpointRefreshed {
		go fn()
		delete(c.onEndpointRefreshed, de)
	}

	if endpointSetsEqual(endpoints, c.lastEndpoints) {
		return false
	}
	c.lastEndpoints = endpoints
	return true
}

// setNetInfoHavePortMap updates NetInfo.HavePortMap to true.
func (c *Conn) setNetInfoHavePortMap() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.netInfoLast == nil {
		// No NetInfo yet. Nothing to update.
		return
	}
	if c.netInfoLast.HavePortMap {
		// No change.
		return
	}
	ni := c.netInfoLast.Clone()
	ni.HavePortMap = true
	c.callNetInfoCallbackLocked(ni)
}

func (c *Conn) updateNetInfo(ctx context.Context) (*netcheck.Report, error) {
	c.mu.Lock()
	dm := c.derpMap
	c.mu.Unlock()

	if dm == nil || c.networkDown() {
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
		HavePortMap:           c.portMapper.HaveMapping(),
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
	c.callNetInfoCallbackLocked(ni)
}

func (c *Conn) callNetInfoCallbackLocked(ni *tailcfg.NetInfo) {
	c.netInfoLast = ni
	if c.netInfoFunc != nil {
		c.logf("[v1] magicsock: netInfo update: %+v", ni)
		go c.netInfoFunc(ni)
	}
}

// addValidDiscoPathForTest makes addr a validated disco address for
// discoKey. It's used in tests to enable receiving of packets from
// addr without having to spin up the entire active discovery
// machinery.
func (c *Conn) addValidDiscoPathForTest(discoKey tailcfg.DiscoKey, addr netaddr.IPPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.discoOfAddr[addr] = discoKey
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

// LastRecvActivityOfDisco returns the time we last got traffic from
// this endpoint (updated every ~10 seconds).
func (c *Conn) LastRecvActivityOfDisco(dk tailcfg.DiscoKey) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	de, ok := c.endpointOfDisco[dk]
	if !ok {
		return time.Time{}
	}
	unix := atomic.LoadInt64(&de.lastRecvUnixAtomic)
	if unix == 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

// Ping handles a "tailscale ping" CLI query.
func (c *Conn) Ping(peer *tailcfg.Node, res *ipnstate.PingResult, cb func(*ipnstate.PingResult)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.privateKey.IsZero() {
		res.Err = "local tailscaled stopped"
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
	if !ok { // peer is using outdated Tailscale version (pre-0.100)
		res.Err = "no discovery key for peer (pre Tailscale 0.100 version?). Try: ping 100.x.y.z"
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
		c.logf("[v1] magicsock: started peer %v for ping to %v", dk.ShortString(), peer.Key.ShortString())
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
		health.SetMagicSockDERPHome(0)
		return false
	}
	if derpNum == c.myDerp {
		// No change.
		return true
	}
	c.myDerp = derpNum
	health.SetMagicSockDERPHome(derpNum)

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

// startDerpHomeConnectLocked starts connecting to our DERP home, if any.
//
// c.mu must be held.
func (c *Conn) startDerpHomeConnectLocked() {
	c.goDerpConnect(c.myDerp)
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
func (c *Conn) determineEndpoints(ctx context.Context) ([]tailcfg.Endpoint, error) {
	nr, err := c.updateNetInfo(ctx)
	if err != nil {
		c.logf("magicsock.Conn.determineEndpoints: updateNetInfo: %v", err)
		return nil, err
	}

	already := make(map[netaddr.IPPort]tailcfg.EndpointType) // endpoint -> how it was found
	var eps []tailcfg.Endpoint                               // unique endpoints

	ipp := func(s string) (ipp netaddr.IPPort) {
		ipp, _ = netaddr.ParseIPPort(s)
		return
	}
	addAddr := func(ipp netaddr.IPPort, et tailcfg.EndpointType) {
		if ipp.IsZero() || (debugOmitLocalAddresses && et == tailcfg.EndpointLocal) {
			return
		}
		if _, ok := already[ipp]; !ok {
			already[ipp] = et
			eps = append(eps, tailcfg.Endpoint{Addr: ipp, Type: et})
		}
	}

	if ext, err := c.portMapper.CreateOrGetMapping(ctx); err == nil {
		addAddr(ext, tailcfg.EndpointPortmapped)
		c.setNetInfoHavePortMap()
	} else if !portmapper.IsNoMappingError(err) {
		c.logf("portmapper: %v", err)
	}

	if nr.GlobalV4 != "" {
		addAddr(ipp(nr.GlobalV4), tailcfg.EndpointSTUN)

		// If they're behind a hard NAT and are using a fixed
		// port locally, assume they might've added a static
		// port mapping on their router to the same explicit
		// port that tailscaled is running with. Worst case
		// it's an invalid candidate mapping.
		if nr.MappingVariesByDestIP.EqualBool(true) && c.port != 0 {
			if ip, _, err := net.SplitHostPort(nr.GlobalV4); err == nil {
				addAddr(ipp(net.JoinHostPort(ip, strconv.Itoa(int(c.port)))), tailcfg.EndpointSTUN4LocalPort)
			}
		}
	}
	if nr.GlobalV6 != "" {
		addAddr(ipp(nr.GlobalV6), tailcfg.EndpointSTUN)
	}

	c.ignoreSTUNPackets()

	if localAddr := c.pconn4.LocalAddr(); localAddr.IP.IsUnspecified() {
		ips, loopback, err := interfaces.LocalAddresses()
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 && len(eps) == 0 {
			// Only include loopback addresses if we have no
			// interfaces at all to use as endpoints and don't
			// have a public IPv4 or IPv6 address. This allows
			// for localhost testing when you're on a plane and
			// offline, for example.
			ips = loopback
		}
		for _, ip := range ips {
			addAddr(netaddr.IPPort{IP: ip, Port: uint16(localAddr.Port)}, tailcfg.EndpointLocal)
		}
	} else {
		// Our local endpoint is bound to a particular address.
		// Do not offer addresses on other local interfaces.
		addAddr(ipp(localAddr.String()), tailcfg.EndpointLocal)
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
	//
	// Despite this sorting, though, clients since 0.100 haven't relied
	// on the sorting order for any decisions.
	return eps, nil
}

// endpointSetsEqual reports whether x and y represent the same set of
// endpoints. The order doesn't matter.
//
// It does not mutate the slices.
func endpointSetsEqual(x, y []tailcfg.Endpoint) bool {
	if len(x) == len(y) {
		orderMatches := true
		for i := range x {
			if x[i] != y[i] {
				orderMatches = false
				break
			}
		}
		if orderMatches {
			return true
		}
	}
	m := map[tailcfg.Endpoint]int{}
	for _, v := range x {
		m[v] |= 1
	}
	for _, v := range y {
		m[v] |= 2
	}
	for _, n := range m {
		if n != 3 {
			return false
		}
	}
	return true
}

// LocalPort returns the current IPv4 listener's port number.
func (c *Conn) LocalPort() uint16 {
	laddr := c.pconn4.LocalAddr()
	return uint16(laddr.Port)
}

var errNetworkDown = errors.New("magicsock: network down")

func (c *Conn) networkDown() bool { return !c.networkUp.Get() }

func (c *Conn) Send(b []byte, ep conn.Endpoint) error {
	if c.networkDown() {
		return errNetworkDown
	}

	switch v := ep.(type) {
	default:
		panic(fmt.Sprintf("[unexpected] Endpoint type %T", v))
	case *discoEndpoint:
		return v.send(b)
	case *addrSet:
		return c.sendAddrSet(b, v)
	}
}

var errConnClosed = errors.New("Conn closed")

var errDropDerpPacket = errors.New("too many DERP packets queued; dropping")

var udpAddrPool = &sync.Pool{
	New: func() interface{} { return new(net.UDPAddr) },
}

// sendUDP sends UDP packet b to ipp.
// See sendAddr's docs on the return value meanings.
func (c *Conn) sendUDP(ipp netaddr.IPPort, b []byte) (sent bool, err error) {
	ua := udpAddrPool.Get().(*net.UDPAddr)
	defer udpAddrPool.Put(ua)
	return c.sendUDPStd(ipp.UDPAddrAt(ua), b)
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
	case <-c.donec:
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

	if c.networkDown() {
		return nil
	}

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
	if !peer.IsZero() && useDerpRoute() {
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

	// Note that derphttp.NewRegionClient does not dial the server
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

	dc.SetCanAckPings(true)
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
	c.scheduleCleanStaleDerpLocked()

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
	go c.derpActiveFunc()

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
		c.logf("[v1] magicsock: derp route for %s set to derp-%d (%s)", peerShort(peer), regionID, newDesc)
	} else {
		c.logf("[v1] magicsock: derp route for %s changed from derp-%d => derp-%d (%s)", peerShort(peer), old, regionID, newDesc)
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
	// If copyBuf is nil, that's a signal from the sender to ignore
	// this message.
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

	defer health.SetDERPRegionConnectedState(regionID, false)

	// peerPresent is the set of senders we know are present on this
	// connection, based on messages we've received from the server.
	peerPresent := map[key.Public]bool{}
	bo := backoff.NewBackoff(fmt.Sprintf("derp-%d", regionID), c.logf, 5*time.Second)
	var lastPacketTime time.Time

	for {
		msg, connGen, err := dc.RecvDetail()
		if err != nil {
			health.SetDERPRegionConnectedState(regionID, false)
			// Forget that all these peers have routes.
			for peer := range peerPresent {
				delete(peerPresent, peer)
				c.removeDerpPeerRoute(peer, regionID, dc)
			}
			if err == derphttp.ErrClientClosed {
				return
			}
			if c.networkDown() {
				c.logf("[v1] magicsock: derp.Recv(derp-%d): network down, closing", regionID)
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}

			c.logf("magicsock: [%p] derp.Recv(derp-%d): %v", dc, regionID, err)

			// If our DERP connection broke, it might be because our network
			// conditions changed. Start that check.
			c.ReSTUN("derp-recv-error")

			// Back off a bit before reconnecting.
			bo.BackOff(ctx, err)
			select {
			case <-ctx.Done():
				return
			default:
			}
			continue
		}
		bo.BackOff(ctx, nil) // reset

		now := time.Now()
		if lastPacketTime.IsZero() || now.Sub(lastPacketTime) > 5*time.Second {
			health.NoteDERPRegionReceivedFrame(regionID)
			lastPacketTime = now
		}

		switch m := msg.(type) {
		case derp.ServerInfoMessage:
			health.SetDERPRegionConnectedState(regionID, true)
			c.logf("magicsock: derp-%d connected; connGen=%v", regionID, connGen)
			continue
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
		case derp.PingMessage:
			// Best effort reply to the ping.
			pingData := [8]byte(m)
			go func() {
				if err := dc.SendPong(pingData); err != nil {
					c.logf("magicsock: derp-%d SendPong error: %v", regionID, err)
				}
			}()
			continue
		default:
			// Ignore.
			continue
		}

		select {
		case <-ctx.Done():
			return
		case c.derpRecvCh <- res:
		}

		select {
		case <-ctx.Done():
			return
		case <-didCopy:
			continue
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
//
// TODO(bradfitz): add a fast path that returns nil here for normal
// wireguard-go transport packets; wireguard-go only uses this
// Endpoint for the relatively rare non-data packets; but we need the
// Endpoint to find the UDPAddr to return to wireguard anyway, so no
// benefit unless we can, say, always return the same fake UDPAddr for
// all packets.
func (c *Conn) findEndpoint(ipp netaddr.IPPort, packet []byte) conn.Endpoint {
	c.mu.Lock()
	defer c.mu.Unlock()

	// See if they have a discoEndpoint, for a set of peers
	// both supporting active discovery.
	if dk, ok := c.discoOfAddr[ipp]; ok {
		if ep, ok := c.endpointOfDisco[dk]; ok {
			return ep
		}
	}

	return c.findLegacyEndpointLocked(ipp, packet)
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

// receiveIPv6 receives a UDP IPv6 packet. It is called by wireguard-go.
func (c *Conn) receiveIPv6(b []byte) (int, conn.Endpoint, error) {
	health.ReceiveIPv6.Enter()
	defer health.ReceiveIPv6.Exit()
	for {
		n, ipp, err := c.pconn6.ReadFromNetaddr(b)
		if err != nil {
			return 0, nil, err
		}
		if ep, ok := c.receiveIP(b[:n], ipp, &c.ippEndpoint6); ok {
			return n, ep, nil
		}
	}
}

// receiveIPv4 receives a UDP IPv4 packet. It is called by wireguard-go.
func (c *Conn) receiveIPv4(b []byte) (n int, ep conn.Endpoint, err error) {
	health.ReceiveIPv4.Enter()
	defer health.ReceiveIPv4.Exit()
	for {
		n, ipp, err := c.pconn4.ReadFromNetaddr(b)
		if err != nil {
			return 0, nil, err
		}
		if ep, ok := c.receiveIP(b[:n], ipp, &c.ippEndpoint4); ok {
			return n, ep, nil
		}
	}
}

// receiveIP is the shared bits of ReceiveIPv4 and ReceiveIPv6.
//
// ok is whether this read should be reported up to wireguard-go (our
// caller).
func (c *Conn) receiveIP(b []byte, ipp netaddr.IPPort, cache *ippEndpointCache) (ep conn.Endpoint, ok bool) {
	if stun.Is(b) {
		c.stunReceiveFunc.Load().(func([]byte, netaddr.IPPort))(b, ipp)
		return nil, false
	}
	if c.handleDiscoMessage(b, ipp) {
		return nil, false
	}
	if !c.havePrivateKey.Get() {
		// If we have no private key, we're logged out or
		// stopped. Don't try to pass these wireguard packets
		// up to wireguard-go; it'll just complain (issue 1167).
		return nil, false
	}
	if cache.ipp == ipp && cache.de != nil && cache.gen == cache.de.numStopAndReset() {
		ep = cache.de
	} else {
		ep = c.findEndpoint(ipp, b)
		if ep == nil {
			return nil, false
		}
		if de, ok := ep.(*discoEndpoint); ok {
			cache.ipp = ipp
			cache.de = de
			cache.gen = de.numStopAndReset()
		}
	}
	c.noteRecvActivityFromEndpoint(ep)
	return ep, true
}

// receiveDERP reads a packet from c.derpRecvCh into b and returns the associated endpoint.
// It is called by wireguard-go.
//
// If the packet was a disco message or the peer endpoint wasn't
// found, the returned error is errLoopAgain.
func (c *connBind) receiveDERP(b []byte) (n int, ep conn.Endpoint, err error) {
	health.ReceiveDERP.Enter()
	defer health.ReceiveDERP.Exit()
	for dm := range c.derpRecvCh {
		if c.Closed() {
			break
		}
		n, ep := c.processDERPReadResult(dm, b)
		if n == 0 {
			// No data read occurred. Wait for another packet.
			continue
		}
		return n, ep, nil
	}
	return 0, nil, net.ErrClosed
}

func (c *Conn) processDERPReadResult(dm derpReadResult, b []byte) (n int, ep conn.Endpoint) {
	if dm.copyBuf == nil {
		return 0, nil
	}
	var regionID int
	n, regionID = dm.n, dm.regionID
	ncopy := dm.copyBuf(b)
	if ncopy != n {
		err := fmt.Errorf("received DERP packet of length %d that's too big for WireGuard buf size %d", n, ncopy)
		c.logf("magicsock: %v", err)
		return 0, nil
	}

	ipp := netaddr.IPPort{IP: derpMagicIPAddr, Port: uint16(regionID)}
	if c.handleDiscoMessage(b[:n], ipp) {
		return 0, nil
	}

	var (
		didNoteRecvActivity bool
		discoEp             *discoEndpoint
		asEp                *addrSet
	)
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
			// been deleted during this time.
			c.mu.Lock()

			discoEp = c.endpointOfDisco[dk]
			c.logf("magicsock: DERP packet received from idle peer %v; created=%v", dm.src.ShortString(), discoEp != nil)
		}
	}
	if !c.disableLegacy {
		asEp = c.addrsByKey[dm.src]
	}
	c.mu.Unlock()

	if discoEp != nil {
		ep = discoEp
	} else if asEp != nil {
		ep = asEp
	} else {
		key := wgkey.Key(dm.src)
		c.logf("magicsock: DERP packet from unknown key: %s", key.ShortString())
		ep = c.findEndpoint(ipp, b[:n])
		if ep == nil {
			return 0, nil
		}
	}

	if !didNoteRecvActivity {
		c.noteRecvActivityFromEndpoint(ep)
	}
	return n, ep
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
			c.logf("[v1] magicsock: disco: %v->%v (%v, %v) sent %v", c.discoShort, dstDisco.ShortString(), dstKey.ShortString(), derpStr(dst.String()), disco.MessageSummary(m))
		}
	} else if err == nil {
		// Can't send. (e.g. no IPv6 locally)
	} else {
		if !c.networkDown() {
			c.logf("magicsock: disco: failed to send %T to %v: %v", m, dst, err)
		}
	}
	return sent, err
}

// handleDiscoMessage handles a discovery message and reports whether
// msg was a Tailscale inter-node discovery message.
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
func (c *Conn) handleDiscoMessage(msg []byte, src netaddr.IPPort) (isDiscoMsg bool) {
	const headerLen = len(disco.Magic) + len(tailcfg.DiscoKey{}) + disco.NonceLen
	if len(msg) < headerLen || string(msg[:len(disco.Magic)]) != disco.Magic {
		return false
	}

	// If the first four parts are the prefix of disco.Magic
	// (0x5453f09f) then it's definitely not a valid Wireguard
	// packet (which starts with little-endian uint32 1, 2, 3, 4).
	// Use naked returns for all following paths.
	isDiscoMsg = true

	var sender tailcfg.DiscoKey
	copy(sender[:], msg[len(disco.Magic):])

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	if debugDisco {
		c.logf("magicsock: disco: got disco-looking frame from %v", sender.ShortString())
	}
	if c.privateKey.IsZero() {
		// Ignore disco messages when we're stopped.
		// Still return true, to not pass it down to wireguard.
		return
	}
	if c.discoPrivate.IsZero() {
		if debugDisco {
			c.logf("magicsock: disco: ignoring disco-looking frame, no local key")
		}
		return
	}

	peerNode, ok := c.nodeOfDisco[sender]
	if !ok {
		if debugDisco {
			c.logf("magicsock: disco: ignoring disco-looking frame, don't know node for %v", sender.ShortString())
		}
		return
	}

	needsRecvActivityCall := false
	de, endpointFound0 := c.endpointOfDisco[sender]
	if !endpointFound0 {
		// We don't have an active endpoint for this sender but we knew about the node, so
		// it's an idle endpoint that doesn't yet exist in the wireguard config. We now have
		// to notify the userspace engine (via noteRecvActivity) so wireguard-go can create
		// an Endpoint (ultimately calling our CreateEndpoint).
		c.logf("magicsock: got disco message from idle peer, starting lazy conf for %v, %v", peerNode.Key.ShortString(), sender.ShortString())
		if c.noteRecvActivity == nil {
			c.logf("magicsock: [unexpected] have node without endpoint, without c.noteRecvActivity hook")
			return
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
			return
		}
		de, ok = c.endpointOfDisco[sender]
		if !ok {
			if _, ok := c.nodeOfDisco[sender]; !ok {
				// They just disappeared while we'd released the lock.
				return false
			}
			c.logf("magicsock: [unexpected] lazy endpoint not created for %v, %v", peerNode.Key.ShortString(), sender.ShortString())
			return
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
		return
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
		return
	}

	switch dm := dm.(type) {
	case *disco.Ping:
		c.handlePingLocked(dm, de, src, sender, peerNode)
	case *disco.Pong:
		if de == nil {
			return
		}
		de.handlePongConnLocked(dm, src)
	case *disco.CallMeMaybe:
		if src.IP != derpMagicIPAddr {
			// CallMeMaybe messages should only come via DERP.
			c.logf("[unexpected] CallMeMaybe packets should only come via DERP")
			return
		}
		if de != nil {
			c.logf("[v1] magicsock: disco: %v<-%v (%v, %v)  got call-me-maybe, %d endpoints",
				c.discoShort, de.discoShort,
				de.publicKey.ShortString(), derpStr(src.String()),
				len(dm.MyNumber))
			go de.handleCallMeMaybe(dm)
		}
	}
	return
}

func (c *Conn) handlePingLocked(dm *disco.Ping, de *discoEndpoint, src netaddr.IPPort, sender tailcfg.DiscoKey, peerNode *tailcfg.Node) {
	if peerNode == nil {
		c.logf("magicsock: disco: [unexpected] ignoring ping from unknown peer Node")
		return
	}
	likelyHeartBeat := src == de.lastPingFrom && time.Since(de.lastPingTime) < 5*time.Second
	de.lastPingFrom = src
	de.lastPingTime = time.Now()
	if !likelyHeartBeat || debugDisco {
		c.logf("[v1] magicsock: disco: %v<-%v (%v, %v)  got ping tx=%x", c.discoShort, de.discoShort, peerNode.Key.ShortString(), src, dm.TxID[:6])
	}

	// Remember this route if not present.
	c.setAddrToDiscoLocked(src, sender, nil)
	de.addCandidateEndpoint(src)

	ipDst := src
	discoDest := sender
	go c.sendDiscoMessage(ipDst, peerNode.Key, discoDest, &disco.Pong{
		TxID: dm.TxID,
		Src:  src,
	}, discoVerboseLog)
}

// enqueueCallMeMaybe schedules a send of disco.CallMeMaybe to de via derpAddr
// once we know that our STUN endpoint is fresh.
//
// derpAddr is de.derpAddr at the time of send. It's assumed the peer won't be
// flipping primary DERPs in the 0-30ms it takes to confirm our STUN endpoint.
// If they do, traffic will just go over DERP for a bit longer until the next
// discovery round.
func (c *Conn) enqueueCallMeMaybe(derpAddr netaddr.IPPort, de *discoEndpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.lastEndpointsTime.After(time.Now().Add(-endpointsFreshEnoughDuration)) {
		c.logf("magicsock: want call-me-maybe but endpoints stale; restunning")
		if c.onEndpointRefreshed == nil {
			c.onEndpointRefreshed = map[*discoEndpoint]func(){}
		}
		c.onEndpointRefreshed[de] = func() {
			c.logf("magicsock: STUN done; sending call-me-maybe to %v %v", de.discoShort, de.publicKey.ShortString())
			c.enqueueCallMeMaybe(derpAddr, de)
		}
		// TODO(bradfitz): make a new 'reSTUNQuickly' method
		// that passes down a do-a-lite-netcheck flag down to
		// netcheck that does 1 (or 2 max) STUN queries
		// (UDP-only, not HTTPs) to find our port mapping to
		// our home DERP and maybe one other. For now we do a
		// "full" ReSTUN which may or may not be a full one
		// (depending on age) and may do HTTPS timing queries
		// (if UDP is blocked). Good enough for now.
		go c.ReSTUN("refresh-for-peering")
		return
	}

	eps := make([]netaddr.IPPort, 0, len(c.lastEndpoints))
	for _, ep := range c.lastEndpoints {
		eps = append(eps, ep.Addr)
	}
	go de.sendDiscoMessage(derpAddr, &disco.CallMeMaybe{MyNumber: eps}, discoLog)
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
		c.logf("[v1] magicsock: disco: changing mapping of %v from %x=>%x", src, oldk.ShortString(), newk.ShortString())
	} else {
		c.logf("[v1] magicsock: disco: adding mapping of %v to %v", src, newk.ShortString())
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

func (c *Conn) SetNetworkUp(up bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.networkUp.Get() == up {
		return
	}

	c.logf("magicsock: SetNetworkUp(%v)", up)
	c.networkUp.Set(up)

	if up {
		c.startDerpHomeConnectLocked()
	} else {
		c.portMapper.NoteNetworkDown()
		c.closeAllDerpLocked("network-down")
	}
}

// SetPrivateKey sets the connection's private key.
//
// This is only used to be able prove our identity when connecting to
// DERP servers.
//
// If the private key changes, any DERP connections are torn down &
// recreated when needed.
func (c *Conn) SetPrivateKey(privateKey wgkey.Private) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldKey, newKey := c.privateKey, key.Private(privateKey)
	if newKey == oldKey {
		return nil
	}
	c.privateKey = newKey
	c.havePrivateKey.Set(!newKey.IsZero())

	if oldKey.IsZero() {
		c.everHadKey = true
		c.logf("magicsock: SetPrivateKey called (init)")
		if c.started {
			go c.ReSTUN("set-private-key")
		}
	} else if newKey.IsZero() {
		c.logf("magicsock: SetPrivateKey called (zeroed)")
		c.closeAllDerpLocked("zero-private-key")
		c.stopPeriodicReSTUNTimerLocked()
		c.onEndpointRefreshed = nil
	} else {
		c.logf("magicsock: SetPrivateKey called (changed)")
		c.closeAllDerpLocked("new-private-key")
	}

	// Key changed. Close existing DERP connections and reconnect to home.
	if c.myDerp != 0 && !newKey.IsZero() {
		c.logf("magicsock: private key changed, reconnecting to home derp-%d", c.myDerp)
		c.startDerpHomeConnectLocked()
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
func (c *Conn) SetNetworkMap(nm *netmap.NetworkMap) {
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
		if ep, ok := c.endpointOfDisco[n.DiscoKey]; ok && ep.publicKey == n.Key {
			ep.updateFromNode(n)
		} else if ok {
			c.logf("magicsock: disco key %v changed from node key %v to %v", n.DiscoKey, ep.publicKey.ShortString(), n.Key.ShortString())
			ep.stopAndReset()
			delete(c.endpointOfDisco, n.DiscoKey)
		}
	}

	c.logf("[v1] magicsock: got updated network map; %d peers (%d with discokey)", len(nm.Peers), numDisco)
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

func (c *Conn) logEndpointChange(endpoints []tailcfg.Endpoint) {
	c.logf("magicsock: endpoints changed: %s", logger.ArgWriter(func(buf *bufio.Writer) {
		for i, ep := range endpoints {
			if i > 0 {
				buf.WriteString(", ")
			}
			fmt.Fprintf(buf, "%s (%s)", ep.Addr, ep.Type)
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
	if c.closed {
		return
	}
	c.derpCleanupTimerArmed = false

	tooOld := time.Now().Add(-derpInactiveCleanupTime)
	dirty := false
	someNonHomeOpen := false
	for i, ad := range c.activeDerp {
		if i == c.myDerp {
			continue
		}
		if ad.lastWrite.Before(tooOld) {
			c.closeDerpLocked(i, "idle")
			dirty = true
		} else {
			someNonHomeOpen = true
		}
	}
	if dirty {
		c.logActiveDerpLocked()
	}
	if someNonHomeOpen {
		c.scheduleCleanStaleDerpLocked()
	}
}

func (c *Conn) scheduleCleanStaleDerpLocked() {
	if c.derpCleanupTimerArmed {
		// Already going to fire soon. Let the existing one
		// fire lest it get infinitely delayed by repeated
		// calls to scheduleCleanStaleDerpLocked.
		return
	}
	c.derpCleanupTimerArmed = true
	if c.derpCleanupTimer != nil {
		c.derpCleanupTimer.Reset(derpCleanStaleInterval)
	} else {
		c.derpCleanupTimer = time.AfterFunc(derpCleanStaleInterval, c.cleanStaleDerp)
	}
}

// DERPs reports the number of active DERP connections.
func (c *Conn) DERPs() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.activeDerp)
}

// Bind returns the wireguard-go conn.Bind for c.
func (c *Conn) Bind() conn.Bind {
	return c.bind
}

// connBind is a wireguard-go conn.Bind for a Conn.
// It bridges the behavior of wireguard-go and a Conn.
// wireguard-go calls Close then Open on device.Up.
// That won't work well for a Conn, which is only closed on shutdown.
// The subsequent Close is a real close.
type connBind struct {
	*Conn
	mu     sync.Mutex
	closed bool
}

// Open is called by WireGuard to create a UDP binding.
// The ignoredPort comes from wireguard-go, via the wgcfg config.
// We ignore that port value here, since we have the local port available easily.
func (c *connBind) Open(ignoredPort uint16) ([]conn.ReceiveFunc, uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		return nil, 0, errors.New("magicsock: connBind already open")
	}
	c.closed = false
	fns := []conn.ReceiveFunc{c.receiveIPv4, c.receiveIPv6, c.receiveDERP}
	// TODO: Combine receiveIPv4 and receiveIPv6 and receiveIP into a single
	// closure that closes over a *RebindingUDPConn?
	return fns, c.LocalPort(), nil
}

// SetMark is used by wireguard-go to set a mark bit for packets to avoid routing loops.
// We handle that ourselves elsewhere.
func (c *connBind) SetMark(value uint32) error {
	return nil
}

// Close closes the connBind, unless it is already closed.
func (c *connBind) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	// Unblock all outstanding receives.
	c.pconn4.Close()
	c.pconn6.Close()
	// Send an empty read result to unblock receiveDERP,
	// which will then check connBind.Closed.
	c.derpRecvCh <- derpReadResult{}
	return nil
}

// Closed reports whether c is closed.
func (c *connBind) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Close closes the connection.
//
// Only the first close does anything. Any later closes return nil.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if c.derpCleanupTimerArmed {
		c.derpCleanupTimer.Stop()
	}
	c.stopPeriodicReSTUNTimerLocked()
	c.portMapper.Close()

	for _, ep := range c.endpointOfDisco {
		ep.stopAndReset()
	}

	c.closed = true
	c.connCtxCancel()
	c.closeAllDerpLocked("conn-close")
	// Ignore errors from c.pconnN.Close.
	// They will frequently have been closed already by a call to connBind.Close.
	if c.pconn6 != nil {
		c.pconn6.Close()
	}
	c.pconn4.Close()

	// Wait on goroutines updating right at the end, once everything is
	// already closed. We want everything else in the Conn to be
	// consistently in the closed state before we release mu to wait
	// on the endpoint updater & derphttp.Connect.
	for c.goroutinesRunningLocked() {
		c.muCond.Wait()
	}
	return nil
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
		return 45 * time.Second
	}
	return sessionActiveTimeout
}

func (c *Conn) shouldDoPeriodicReSTUNLocked() bool {
	if c.networkDown() {
		return false
	}
	if len(c.peerSet) == 0 || c.privateKey.IsZero() {
		// If no peers, not worth doing.
		// Also don't if there's no key (not running).
		return false
	}
	if f := c.idleFunc; f != nil {
		idleFor := f()
		if debugReSTUNStopOnIdle {
			c.logf("magicsock: periodicReSTUN: idle for %v", idleFor.Round(time.Second))
		}
		if idleFor > maxIdleBeforeSTUNShutdown() {
			if c.netMap != nil && c.netMap.Debug != nil && c.netMap.Debug.ForceBackgroundSTUN {
				// Overridden by control.
				return true
			}
			return false
		}
	}
	return true
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
			c.logf("[v1] magicsock: ReSTUN: endpoint update active, need another later (%q)", why)
			c.wantEndpointsUpdate = why
		}
	} else {
		c.endpointsUpdateActive = true
		go c.updateEndpoints(why)
	}
}

func (c *Conn) initialBind() error {
	if err := c.bindSocket(&c.pconn4, "udp4"); err != nil {
		return fmt.Errorf("magicsock: initialBind IPv4 failed: %w", err)
	}
	c.portMapper.SetLocalPort(c.LocalPort())
	if err := c.bindSocket(&c.pconn6, "udp6"); err != nil {
		c.logf("magicsock: ignoring IPv6 bind failure: %v", err)
	}
	return nil
}

// listenPacket opens a packet listener.
// The network must be "udp4" or "udp6".
// Host is the (local) IP address to listen on; use the zero IP to leave unspecified.
func (c *Conn) listenPacket(network string, host netaddr.IP, port uint16) (net.PacketConn, error) {
	ctx := context.Background() // unused without DNS name to resolve
	// Translate host to package net: "" for the zero value, the IP address string otherwise.
	var s string
	if !host.IsZero() {
		s = host.String()
	}
	addr := net.JoinHostPort(s, fmt.Sprint(port))
	if c.packetListener != nil {
		return c.packetListener.ListenPacket(ctx, network, addr)
	}
	return netns.Listener().ListenPacket(ctx, network, addr)
}

// bindSocket initializes rucPtr if necessary and binds a UDP socket to it.
// Network indicates the UDP socket type; it must be "udp4" or "udp6".
// If rucPtr had an existing UDP socket bound, it closes that socket.
// The caller is responsible for informing the portMapper of any changes.
func (c *Conn) bindSocket(rucPtr **RebindingUDPConn, network string) error {
	var host netaddr.IP
	if inTest() && !c.simulatedNetwork {
		switch network {
		case "udp4":
			host = netaddr.MustParseIP("127.0.0.1")
		case "udp6":
			host = netaddr.MustParseIP("::1")
		default:
			panic("unrecognized network in bindSocket: " + network)
		}
	}

	if *rucPtr == nil {
		*rucPtr = new(RebindingUDPConn)
	}
	ruc := *rucPtr

	// Hold the ruc lock the entire time, so that the close+bind is atomic
	// from the perspective of ruc receive functions.
	ruc.mu.Lock()
	defer ruc.mu.Unlock()

	// Build a list of preferred ports.
	// Best is the port that the user requested.
	// Second best is the port that is currently in use.
	// If those fail, fall back to 0.
	var ports []uint16
	if c.port != 0 {
		ports = append(ports, c.port)
	}
	if ruc.pconn != nil {
		curPort := uint16(ruc.localAddrLocked().Port)
		ports = append(ports, curPort)
	}
	ports = append(ports, 0)
	// Remove duplicates. (All duplicates are consecutive.)
	uniq.ModifySlice(&ports, func(i, j int) bool { return ports[i] == ports[j] })

	var pconn net.PacketConn
	for _, port := range ports {
		// Close the existing conn, in case it is sitting on the port we want.
		err := ruc.closeLocked()
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, errNilPConn) {
			c.logf("magicsock: bindSocket %v close failed: %v", network, err)
		}
		// Open a new one with the desired port.
		pconn, err = c.listenPacket(network, host, port)
		if err != nil {
			c.logf("magicsock: unable to bind %v port %d: %v", network, port, err)
			continue
		}
		// Success.
		ruc.pconn = pconn
		if network == "udp4" {
			health.SetUDP4Unbound(false)
		}
		return nil
	}

	// Failed to bind, including on port 0 (!).
	// Set pconn to a dummy conn whose reads block until closed.
	// This keeps the receive funcs alive for a future in which
	// we get a link change and we can try binding again.
	ruc.pconn = newBlockForeverConn()
	if network == "udp4" {
		health.SetUDP4Unbound(true)
	}
	return fmt.Errorf("failed to bind any ports (tried %v)", ports)
}

// Rebind closes and re-binds the UDP sockets.
// It should be followed by a call to ReSTUN.
func (c *Conn) Rebind() {
	if err := c.bindSocket(&c.pconn4, "udp4"); err != nil {
		c.logf("magicsock: Rebind IPv4 failed: %w", err)
		return
	}
	c.portMapper.SetLocalPort(c.LocalPort())
	if err := c.bindSocket(&c.pconn6, "udp6"); err != nil {
		c.logf("magicsock: Rebind ignoring IPv6 bind failure: %v", err)
	}

	c.mu.Lock()
	c.closeAllDerpLocked("rebind")
	if !c.privateKey.IsZero() {
		c.startDerpHomeConnectLocked()
	}
	c.mu.Unlock()

	c.resetEndpointStates()
}

// resetEndpointStates resets the preferred address for all peers and
// re-enables spraying.
// This is called when connectivity changes enough that we no longer
// trust the old routes.
func (c *Conn) resetEndpointStates() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, de := range c.endpointOfDisco {
		de.noteConnectivityChange()
	}
	c.resetAddrSetStatesLocked()
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

// ParseEndpoint is called by WireGuard to connect to an endpoint.
//
// keyAddrs is the 32 byte public key of the peer followed by addrs.
// Addrs is either:
//
//  1) a comma-separated list of UDP ip:ports (the peer doesn't have a discovery key)
//  2) "<hex-discovery-key>.disco.tailscale:12345", a magic value that means the peer
//     is running code that supports active discovery, so CreateEndpoint returns
//     a discoEndpoint.
func (c *Conn) ParseEndpoint(keyAddrs string) (conn.Endpoint, error) {
	if len(keyAddrs) < 32 {
		c.logf("[unexpected] ParseEndpoint keyAddrs too short: %q", keyAddrs)
		return nil, errors.New("endpoint string too short")
	}
	var pk key.Public
	copy(pk[:], keyAddrs)
	addrs := keyAddrs[len(pk):]
	c.mu.Lock()
	defer c.mu.Unlock()

	c.logf("magicsock: ParseEndpoint: key=%s: %s", pk.ShortString(), derpStr(addrs))

	if !strings.HasSuffix(addrs, wgcfg.EndpointDiscoSuffix) {
		return c.createLegacyEndpointLocked(pk, addrs)
	}

	discoHex := strings.TrimSuffix(addrs, wgcfg.EndpointDiscoSuffix)
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

// RebindingUDPConn is a UDP socket that can be re-bound.
// Unix has no notion of re-binding a socket, so we swap it out for a new one.
type RebindingUDPConn struct {
	mu    sync.Mutex
	pconn net.PacketConn
}

// currentConn returns c's current pconn.
func (c *RebindingUDPConn) currentConn() net.PacketConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pconn
}

// ReadFrom reads a packet from c into b.
// It returns the number of bytes copied and the source address.
func (c *RebindingUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		pconn := c.currentConn()
		n, addr, err := pconn.ReadFrom(b)
		if err != nil && pconn != c.currentConn() {
			continue
		}
		return n, addr, err
	}
}

// ReadFromNetaddr reads a packet from c into b.
// It returns the number of bytes copied and the return address.
// It is identical to c.ReadFrom, except that it returns a netaddr.IPPort instead of a net.Addr.
// ReadFromNetaddr is designed to work with specific underlying connection types.
// If c's underlying connection returns a non-*net.UPDAddr return address, ReadFromNetaddr will return an error.
// ReadFromNetaddr exists because it removes an allocation per read,
// when c's underlying connection is a net.UDPConn.
func (c *RebindingUDPConn) ReadFromNetaddr(b []byte) (n int, ipp netaddr.IPPort, err error) {
	for {
		pconn := c.currentConn()

		// Optimization: Treat *net.UDPConn specially.
		// ReadFromUDP gets partially inlined, avoiding allocating a *net.UDPAddr,
		// as long as pAddr itself doesn't escape.
		// The non-*net.UDPConn case works, but it allocates.
		var pAddr *net.UDPAddr
		if udpConn, ok := pconn.(*net.UDPConn); ok {
			n, pAddr, err = udpConn.ReadFromUDP(b)
		} else {
			var addr net.Addr
			n, addr, err = pconn.ReadFrom(b)
			if addr != nil {
				pAddr, ok = addr.(*net.UDPAddr)
				if !ok {
					return 0, netaddr.IPPort{}, fmt.Errorf("RebindingUDPConn.ReadFromNetaddr: underlying connection returned address of type %T, want *netaddr.UDPAddr", addr)
				}
			}
		}

		if err != nil {
			if pconn != c.currentConn() {
				continue
			}
		} else {
			// Convert pAddr to a netaddr.IPPort.
			// This prevents pAddr from escaping.
			var ok bool
			ipp, ok = netaddr.FromStdAddr(pAddr.IP, pAddr.Port, pAddr.Zone)
			if !ok {
				return 0, netaddr.IPPort{}, errors.New("netaddr.FromStdAddr failed")
			}
		}
		return n, ipp, err
	}
}

func (c *RebindingUDPConn) LocalAddr() *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localAddrLocked()
}

func (c *RebindingUDPConn) localAddrLocked() *net.UDPAddr {
	return c.pconn.LocalAddr().(*net.UDPAddr)
}

// errNilPConn is returned by RebindingUDPConn.Close when there is no current pconn.
// It is for internal use only and should not be returned to users.
var errNilPConn = errors.New("nil pconn")

func (c *RebindingUDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *RebindingUDPConn) closeLocked() error {
	if c.pconn == nil {
		return errNilPConn
	}
	return c.pconn.Close()
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

func newBlockForeverConn() *blockForeverConn {
	c := new(blockForeverConn)
	c.cond = sync.NewCond(&c.mu)
	return c
}

// blockForeverConn is a net.PacketConn whose reads block until it is closed.
type blockForeverConn struct {
	mu     sync.Mutex
	cond   *sync.Cond
	closed bool
}

func (c *blockForeverConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.mu.Lock()
	for !c.closed {
		c.cond.Wait()
	}
	c.mu.Unlock()
	return 0, nil, net.ErrClosed
}

func (c *blockForeverConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Silently drop writes.
	return len(p), nil
}

func (c *blockForeverConn) LocalAddr() net.Addr {
	// Return a *net.UDPAddr because lots of code assumes that it will.
	return new(net.UDPAddr)
}

func (c *blockForeverConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.closed = true
	return nil
}

func (c *blockForeverConn) SetDeadline(t time.Time) error      { return errors.New("unimplemented") }
func (c *blockForeverConn) SetReadDeadline(t time.Time) error  { return errors.New("unimplemented") }
func (c *blockForeverConn) SetWriteDeadline(t time.Time) error { return errors.New("unimplemented") }

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
	k2 := wgkey.Key(k)
	return k2.ShortString()
}

func sbPrintAddr(sb *strings.Builder, a netaddr.IPPort) {
	is6 := a.IP.Is6()
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

	var tailAddr4 string
	var tailscaleIPs []netaddr.IP
	if c.netMap != nil {
		tailscaleIPs = make([]netaddr.IP, 0, len(c.netMap.Addresses))
		for _, addr := range c.netMap.Addresses {
			if !addr.IsSingleIP() {
				continue
			}
			sb.AddTailscaleIP(addr.IP)
			// TailAddr previously only allowed for a
			// single Tailscale IP. For compatibility for
			// a couple releases starting with 1.8, keep
			// that field pulled out separately.
			if addr.IP.Is4() {
				tailAddr4 = addr.IP.String()
			}
			tailscaleIPs = append(tailscaleIPs, addr.IP)
		}
	}

	sb.MutateSelfStatus(func(ss *ipnstate.PeerStatus) {
		ss.PublicKey = c.privateKey.Public()
		ss.Addrs = make([]string, 0, len(c.lastEndpoints))
		for _, ep := range c.lastEndpoints {
			ss.Addrs = append(ss.Addrs, ep.Addr.String())
		}
		ss.OS = version.OS()
		if c.netMap != nil {
			ss.HostName = c.netMap.Hostinfo.Hostname
			ss.DNSName = c.netMap.Name
			ss.UserID = c.netMap.User
			if c.netMap.SelfNode != nil {
				if c := c.netMap.SelfNode.Capabilities; len(c) > 0 {
					ss.Capabilities = append([]string(nil), c...)
				}
			}
		} else {
			ss.HostName, _ = os.Hostname()
		}
		if c.derpMap != nil {
			derpRegion, ok := c.derpMap.Regions[c.myDerp]
			if ok {
				ss.Relay = derpRegion.RegionCode
			}
		}
		ss.TailscaleIPs = tailscaleIPs
		ss.TailAddrDeprecated = tailAddr4
	})

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

func ippDebugString(ua netaddr.IPPort) string {
	if ua.IP == derpMagicIPAddr {
		return fmt.Sprintf("derp-%d", ua.Port)
	}
	return ua.String()
}

// discoEndpoint is a wireguard/conn.Endpoint for new-style peers that
// advertise a DiscoKey and participate in active discovery.
type discoEndpoint struct {
	// atomically accessed; declared first for alignment reasons
	lastRecvUnixAtomic    int64
	numStopAndResetAtomic int64

	// These fields are initialized once and never modified.
	c                  *Conn
	publicKey          tailcfg.NodeKey  // peer public key (for WireGuard + DERP)
	discoKey           tailcfg.DiscoKey // for discovery mesages
	discoShort         string           // ShortString of discoKey
	fakeWGAddr         netaddr.IPPort   // the UDP address we tell wireguard-go we're using
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

	bestAddr           addrLatency // best non-DERP path; zero if none
	bestAddrAt         time.Time   // time best address re-confirmed
	trustBestAddrUntil time.Time   // time when bestAddr expires
	sentPing           map[stun.TxID]sentPing
	endpointState      map[netaddr.IPPort]*endpointState
	isCallMeMaybeEP    map[netaddr.IPPort]bool

	pendingCLIPings []pendingCLIPing // any outstanding "tailscale ping" commands running
}

type pendingCLIPing struct {
	res *ipnstate.PingResult
	cb  func(*ipnstate.PingResult)
}

const (
	// sessionActiveTimeout is how long since the last activity we
	// try to keep an established discoEndpoint peering alive.
	// It's also the idle time at which we stop doing STUN queries to
	// keep NAT mappings alive.
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

	// derpInactiveCleanupTime is how long a non-home DERP connection
	// needs to be idle (last written to) before we close it.
	derpInactiveCleanupTime = 60 * time.Second

	// derpCleanStaleInterval is how often cleanStaleDerp runs when there
	// are potentially-stale DERP connections to close.
	derpCleanStaleInterval = 15 * time.Second

	// endpointsFreshEnoughDuration is how long we consider a
	// STUN-derived endpoint valid for. UDP NAT mappings typically
	// expire at 30 seconds, so this is a few seconds shy of that.
	endpointsFreshEnoughDuration = 27 * time.Second
)

// endpointState is some state and history for a specific endpoint of
// a discoEndpoint. (The subject is the discoEndpoint.endpointState
// map key)
type endpointState struct {
	// all fields guarded by discoEndpoint.mu

	// lastPing is the last (outgoing) ping time.
	lastPing time.Time

	// lastGotPing, if non-zero, means that this was an endpoint
	// that we learned about at runtime (from an incoming ping)
	// and that is not in the network map. If so, we keep the time
	// updated and use it to discard old candidates.
	lastGotPing time.Time

	// callMeMaybeTime, if non-zero, is the time this endpoint
	// was advertised last via a call-me-maybe disco message.
	callMeMaybeTime time.Time

	recentPongs []pongReply // ring buffer up to pongHistoryCount entries
	recentPong  uint16      // index into recentPongs of most recent; older before, wrapped

	index int16 // index in nodecfg.Node.Endpoints; meaningless if lastGotPing non-zero
}

// indexSentinelDeleted is the temporary value that endpointState.index takes while
// a discoEndpoint's endpoints are being updated from a new network map.
const indexSentinelDeleted = -1

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

func (de *discoEndpoint) deleteEndpointLocked(ep netaddr.IPPort) {
	delete(de.endpointState, ep)
	if de.bestAddr.IPPort == ep {
		de.bestAddr = addrLatency{}
	}
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

func (de *discoEndpoint) ClearSrc()           {}
func (de *discoEndpoint) SrcToString() string { panic("unused") } // unused by wireguard-go
func (de *discoEndpoint) SrcIP() net.IP       { panic("unused") } // unused by wireguard-go
func (de *discoEndpoint) DstToString() string { return de.wgEndpointHostPort }
func (de *discoEndpoint) DstIP() net.IP       { panic("unused") }
func (de *discoEndpoint) DstToBytes() []byte  { return packIPPort(de.fakeWGAddr) }

// addrForSendLocked returns the address(es) that should be used for
// sending the next packet. Zero, one, or both of UDP address and DERP
// addr may be non-zero.
//
// de.mu must be held.
func (de *discoEndpoint) addrForSendLocked(now time.Time) (udpAddr, derpAddr netaddr.IPPort) {
	udpAddr = de.bestAddr.IPPort
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
		de.c.logf("[v1] magicsock: disco: ending heartbeats for idle session to %v (%v)", de.publicKey.ShortString(), de.discoShort)
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
	if de.bestAddr.latency <= goodEnoughLatency {
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
		de.c.logf("[v1] magicsock: disco: timeout waiting for pong %x from %v (%v, %v)", txid[:6], sp.to, de.publicKey.ShortString(), de.discoShort)
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

//go:generate stringer -type=discoPingPurpose -trimprefix=ping
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
		if st.shouldDeleteLocked() {
			de.deleteEndpointLocked(ep)
			continue
		}
		if !st.lastPing.IsZero() && now.Sub(st.lastPing) < discoPingInterval {
			continue
		}

		firstPing := !sentAny
		sentAny = true

		if firstPing && sendCallMeMaybe {
			de.c.logf("[v1] magicsock: disco: send, starting discovery for %v (%v)", de.publicKey.ShortString(), de.discoShort)
		}

		de.startPingLocked(ep, now, pingDiscovery)
	}
	derpAddr := de.derpAddr
	if sentAny && sendCallMeMaybe && !derpAddr.IsZero() {
		// Have our magicsock.Conn figure out its STUN endpoint (if
		// it doesn't know already) and then send a CallMeMaybe
		// message to our peer via DERP informing them that we've
		// sent so our firewall ports are probably open and now
		// would be a good time for them to connect.
		go de.c.enqueueCallMeMaybe(derpAddr, de)
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
		st.index = indexSentinelDeleted // assume deleted until updated in next loop
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

	// Now delete anything unless it's still in the network map or
	// was a recently discovered endpoint.
	for ep, st := range de.endpointState {
		if st.shouldDeleteLocked() {
			de.deleteEndpointLocked(ep)
		}
	}
}

// addCandidateEndpoint adds ep as an endpoint to which we should send
// future pings.
//
// This is called once we've already verified that we got a valid
// discovery message from de via ep.
func (de *discoEndpoint) addCandidateEndpoint(ep netaddr.IPPort) {
	de.mu.Lock()
	defer de.mu.Unlock()

	if st, ok := de.endpointState[ep]; ok {
		if st.lastGotPing.IsZero() {
			// Already-known endpoint from the network map.
			return
		}
		st.lastGotPing = time.Now()
		return
	}

	// Newly discovered endpoint. Exciting!
	de.c.logf("[v1] magicsock: disco: adding %v as candidate endpoint for %v (%s)", ep, de.discoShort, de.publicKey.ShortString())
	de.endpointState[ep] = &endpointState{
		lastGotPing: time.Now(),
	}

	// If for some reason this gets very large, do some cleanup.
	if size := len(de.endpointState); size > 100 {
		for ep, st := range de.endpointState {
			if st.shouldDeleteLocked() {
				de.deleteEndpointLocked(ep)
			}
		}
		size2 := len(de.endpointState)
		de.c.logf("[v1] magicsock: disco: addCandidateEndpoint pruned %v candidate set from %v to %v entries", size, size2)
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
		de.c.logf("[v1] magicsock: disco: %v<-%v (%v, %v)  got pong tx=%x latency=%v pong.src=%v%v", de.c.discoShort, de.discoShort, de.publicKey.ShortString(), src, m.TxID[:6], latency.Round(time.Millisecond), m.Src, logger.ArgWriter(func(bw *bufio.Writer) {
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
			de.c.logf("magicsock: disco: node %v %v now using %v", de.publicKey.ShortString(), de.discoShort, sp.to)
			de.bestAddr = thisPong
		}
		if de.bestAddr.IPPort == thisPong.IPPort {
			de.bestAddr.latency = latency
			de.bestAddrAt = now
			de.trustBestAddrUntil = now.Add(trustUDPAddrDuration)
		}
	}
}

// addrLatency is an IPPort with an associated latency.
type addrLatency struct {
	netaddr.IPPort
	latency time.Duration
}

// betterAddr reports whether a is a better addr to use than b.
func betterAddr(a, b addrLatency) bool {
	if a.IPPort == b.IPPort {
		return false
	}
	if b.IsZero() {
		return true
	}
	if a.IsZero() {
		return false
	}
	if a.IP.Is6() && b.IP.Is4() {
		// Prefer IPv6 for being a bit more robust, as long as
		// the latencies are roughly equivalent.
		if a.latency/10*9 < b.latency {
			return true
		}
	} else if a.IP.Is4() && b.IP.Is6() {
		if betterAddr(b, a) {
			return false
		}
	}
	return a.latency < b.latency
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
func (de *discoEndpoint) handleCallMeMaybe(m *disco.CallMeMaybe) {
	de.mu.Lock()
	defer de.mu.Unlock()

	now := time.Now()
	for ep := range de.isCallMeMaybeEP {
		de.isCallMeMaybeEP[ep] = false // mark for deletion
	}
	if de.isCallMeMaybeEP == nil {
		de.isCallMeMaybeEP = map[netaddr.IPPort]bool{}
	}
	var newEPs []netaddr.IPPort
	for _, ep := range m.MyNumber {
		if ep.IP.Is6() && ep.IP.IsLinkLocalUnicast() {
			// We send these out, but ignore them for now.
			// TODO: teach the ping code to ping on all interfaces
			// for these.
			continue
		}
		de.isCallMeMaybeEP[ep] = true
		if es, ok := de.endpointState[ep]; ok {
			es.callMeMaybeTime = now
		} else {
			de.endpointState[ep] = &endpointState{callMeMaybeTime: now}
			newEPs = append(newEPs, ep)
		}
	}
	if len(newEPs) > 0 {
		de.c.logf("[v1] magicsock: disco: call-me-maybe from %v %v added new endpoints: %v",
			de.publicKey.ShortString(), de.discoShort,
			logger.ArgWriter(func(w *bufio.Writer) {
				for i, ep := range newEPs {
					if i > 0 {
						w.WriteString(", ")
					}
					w.WriteString(ep.String())
				}
			}))
	}

	// Delete any prior CalllMeMaybe endpoints that weren't included
	// in this message.
	for ep, want := range de.isCallMeMaybeEP {
		if !want {
			delete(de.isCallMeMaybeEP, ep)
			de.deleteEndpointLocked(ep)
		}
	}

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
	atomic.AddInt64(&de.numStopAndResetAtomic, 1)
	de.mu.Lock()
	defer de.mu.Unlock()

	de.c.logf("[v1] magicsock: doing cleanup for discovery key %x", de.discoKey[:])

	// Zero these fields so if the user re-starts the network, the discovery
	// state isn't a mix of before & after two sessions.
	de.lastSend = time.Time{}
	de.lastFullPing = time.Time{}
	de.bestAddr = addrLatency{}
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

func (de *discoEndpoint) numStopAndReset() int64 {
	return atomic.LoadInt64(&de.numStopAndResetAtomic)
}

// derpStr replaces DERP IPs in s with "derp-".
func derpStr(s string) string { return strings.ReplaceAll(s, "127.3.3.40:", "derp-") }

// ippEndpointCache is a mutex-free single-element cache, mapping from
// a single netaddr.IPPort to a single endpoint.
type ippEndpointCache struct {
	ipp netaddr.IPPort
	gen int64
	de  *discoEndpoint
}
