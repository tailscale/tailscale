// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package magicsock implements a socket that can change its communication path while
// in use, actively searching for the best way to communicate.
package magicsock

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"go4.org/mem"
	"golang.org/x/net/ipv6"
	"tailscale.com/control/controlknobs"
	"tailscale.com/disco"
	"tailscale.com/envknob"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/feature/condlite/expvar"
	"tailscale.com/health"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/batching"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/neterror"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/packet"
	"tailscale.com/net/ping"
	"tailscale.com/net/portmapper/portmappertype"
	"tailscale.com/net/sockopts"
	"tailscale.com/net/sockstats"
	"tailscale.com/net/stun"
	"tailscale.com/net/tstun"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/lazy"
	"tailscale.com/types/logger"
	"tailscale.com/types/netlogfunc"
	"tailscale.com/types/netmap"
	"tailscale.com/types/nettype"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/mak"
	"tailscale.com/util/ringlog"
	"tailscale.com/util/set"
	"tailscale.com/util/testenv"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgint"
)

const (
	// These are disco.Magic in big-endian form, 4 then 2 bytes. The
	// BPF filters need the magic in this format to match on it. Used
	// only in magicsock_linux.go, but defined here so that the test
	// which verifies this is the correct magic doesn't also need a
	// _linux variant.
	discoMagic1 = 0x5453f09f
	discoMagic2 = 0x92ac

	// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it
	// is the max supported by a default configuration of macOS. Some platforms
	// will silently clamp the value.
	socketBufferSize = 7 << 20
)

// Path is a label indicating the type of path a packet took.
type Path string

const (
	PathDirectIPv4    Path = "direct_ipv4"
	PathDirectIPv6    Path = "direct_ipv6"
	PathDERP          Path = "derp"
	PathPeerRelayIPv4 Path = "peer_relay_ipv4"
	PathPeerRelayIPv6 Path = "peer_relay_ipv6"
)

type pathLabel struct {
	// Path indicates the path that the packet took:
	// - direct_ipv4
	// - direct_ipv6
	// - derp
	// - peer_relay_ipv4
	// - peer_relay_ipv6
	Path Path
}

// metrics in wgengine contains the usermetrics counters for magicsock, it
// is however a bit special. All them metrics are labeled, but looking up
// the metric everytime we need to record it has an overhead, and includes
// a lock in MultiLabelMap. The metrics are therefore instead created with
// wgengine and the underlying expvar.Int is stored to be used directly.
type metrics struct {
	// inboundPacketsTotal is the total number of inbound packets received,
	// labeled by the path the packet took.
	inboundPacketsIPv4Total          expvar.Int
	inboundPacketsIPv6Total          expvar.Int
	inboundPacketsDERPTotal          expvar.Int
	inboundPacketsPeerRelayIPv4Total expvar.Int
	inboundPacketsPeerRelayIPv6Total expvar.Int

	// inboundBytesTotal is the total number of inbound bytes received,
	// labeled by the path the packet took.
	inboundBytesIPv4Total          expvar.Int
	inboundBytesIPv6Total          expvar.Int
	inboundBytesDERPTotal          expvar.Int
	inboundBytesPeerRelayIPv4Total expvar.Int
	inboundBytesPeerRelayIPv6Total expvar.Int

	// outboundPacketsTotal is the total number of outbound packets sent,
	// labeled by the path the packet took.
	outboundPacketsIPv4Total          expvar.Int
	outboundPacketsIPv6Total          expvar.Int
	outboundPacketsDERPTotal          expvar.Int
	outboundPacketsPeerRelayIPv4Total expvar.Int
	outboundPacketsPeerRelayIPv6Total expvar.Int

	// outboundBytesTotal is the total number of outbound bytes sent,
	// labeled by the path the packet took.
	outboundBytesIPv4Total          expvar.Int
	outboundBytesIPv6Total          expvar.Int
	outboundBytesDERPTotal          expvar.Int
	outboundBytesPeerRelayIPv4Total expvar.Int
	outboundBytesPeerRelayIPv6Total expvar.Int

	// outboundPacketsDroppedErrors is the total number of outbound packets
	// dropped due to errors.
	outboundPacketsDroppedErrors expvar.Int
}

// A Conn routes UDP packets and actively manages a list of its endpoints.
type Conn struct {
	// This block mirrors the contents and field order of the Options
	// struct. Initialized once at construction, then constant.

	eventBus               *eventbus.Bus
	eventClient            *eventbus.Client
	logf                   logger.Logf
	epFunc                 func([]tailcfg.Endpoint)
	derpActiveFunc         func()
	idleFunc               func() time.Duration // nil means unknown
	testOnlyPacketListener nettype.PacketListener
	noteRecvActivity       func(key.NodePublic) // or nil, see Options.NoteRecvActivity
	netMon                 *netmon.Monitor      // must be non-nil
	health                 *health.Tracker      // or nil
	controlKnobs           *controlknobs.Knobs  // or nil

	// ================================================================
	// No locking required to access these fields, either because
	// they're static after construction, or are wholly owned by a
	// single goroutine.

	connCtx       context.Context // closed on Conn.Close
	connCtxCancel func()          // closes connCtx
	donec         <-chan struct{} // connCtx.Done()'s to avoid context.cancelCtx.Done()'s mutex per call

	// A publisher for synchronization points to ensure correct ordering of
	// config changes between magicsock and wireguard.
	syncPub               *eventbus.Publisher[syncPoint]
	allocRelayEndpointPub *eventbus.Publisher[UDPRelayAllocReq]
	portUpdatePub         *eventbus.Publisher[router.PortUpdate]

	// pconn4 and pconn6 are the underlying UDP sockets used to
	// send/receive packets for wireguard and other magicsock
	// protocols.
	pconn4 RebindingUDPConn
	pconn6 RebindingUDPConn

	receiveBatchPool sync.Pool

	// closeDisco4 and closeDisco6 are io.Closers to shut down the raw
	// disco packet receivers. If nil, no raw disco receiver is
	// running for the given family.
	closeDisco4 io.Closer
	closeDisco6 io.Closer

	// netChecker is the prober that discovers local network
	// conditions, including the closest DERP relay and NAT mappings.
	netChecker *netcheck.Client

	// portMapper is the NAT-PMP/PCP/UPnP prober/client, for requesting
	// port mappings from NAT devices.
	// If nil, the portmapper is disabled.
	portMapper portmappertype.Client

	// derpRecvCh is used by receiveDERP to read DERP messages.
	// It must have buffer size > 0; see issue 3736.
	derpRecvCh chan derpReadResult

	// bind is the wireguard-go conn.Bind for Conn.
	bind *connBind

	// cloudInfo is used to query cloud metadata services.
	cloudInfo *cloudInfo

	// ============================================================
	// Fields that must be accessed via atomic load/stores.

	// noV4 and noV6 are whether IPv4 and IPv6 are known to be
	// missing.  They're only used to suppress log spam. The name
	// is named negatively because in early start-up, we don't yet
	// necessarily have a netcheck.Report and don't want to skip
	// logging.
	noV4, noV6 atomic.Bool

	silentDiscoOn atomic.Bool // whether silent disco is enabled

	probeUDPLifetimeOn atomic.Bool // whether probing of UDP lifetime is enabled

	// noV4Send is whether IPv4 UDP is known to be unable to transmit
	// at all. This could happen if the socket is in an invalid state
	// (as can happen on darwin after a network link status change).
	noV4Send atomic.Bool

	// networkUp is whether the network is up (some interface is up
	// with IPv4 or IPv6). It's used to suppress log spam and prevent
	// new connection that'll fail.
	networkUp atomic.Bool

	// Whether debugging logging is enabled.
	debugLogging atomic.Bool

	// havePrivateKey is whether privateKey is non-zero.
	havePrivateKey  atomic.Bool
	publicKeyAtomic syncs.AtomicValue[key.NodePublic] // or NodeKey zero value if !havePrivateKey

	// derpMapAtomic is the same as derpMap, but without requiring
	// sync.Mutex. For use with NewRegionClient's callback, to avoid
	// lock ordering deadlocks. See issue 3726 and mu field docs.
	derpMapAtomic atomic.Pointer[tailcfg.DERPMap]

	lastNetCheckReport atomic.Pointer[netcheck.Report]

	// port is the preferred port from opts.Port; 0 means auto.
	port atomic.Uint32

	// peerMTUEnabled is whether path MTU discovery to peers is enabled.
	//
	//lint:ignore U1000 used on Linux/Darwin only
	peerMTUEnabled atomic.Bool

	// connCounter maintains per-connection counters.
	connCounter syncs.AtomicValue[netlogfunc.ConnectionCounter]

	// captureHook, if non-nil, is the pcap logging callback when capturing.
	captureHook syncs.AtomicValue[packet.CaptureCallback]

	// hasPeerRelayServers is whether [relayManager] is configured with at least
	// one peer relay server via [relayManager.handleRelayServersSet]. It exists
	// to suppress calls into [relayManager] leading to wasted work involving
	// channel operations and goroutine creation.
	hasPeerRelayServers atomic.Bool

	// discoPrivate is the private naclbox key used for active
	// discovery traffic. It is always present, and immutable.
	discoPrivate key.DiscoPrivate
	// public of discoPrivate. It is always present and immutable.
	discoPublic key.DiscoPublic
	// ShortString of discoPublic (to save logging work later). It is always
	// present and immutable.
	discoShort string

	// ============================================================
	// mu guards all following fields; see userspaceEngine lock
	// ordering rules against the engine. For derphttp, mu must
	// be held before derphttp.Client.mu.
	mu     sync.Mutex
	muCond *sync.Cond

	onlyTCP443 atomic.Bool

	closed  bool        // Close was called
	closing atomic.Bool // Close is in progress (or done)

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
	onEndpointRefreshed map[*endpoint]func()

	// endpointTracker tracks the set of cached endpoints that we advertise
	// for a period of time before withdrawing them.
	endpointTracker endpointTracker

	// peerSet is the set of peers that are currently configured in
	// WireGuard. These are not used to filter inbound or outbound
	// traffic at all, but only to track what state can be cleaned up
	// in other maps below that are keyed by peer public key.
	peerSet set.Set[key.NodePublic]

	// peerMap tracks the networkmap Node entity for each peer
	// by node key, node ID, and discovery key.
	peerMap peerMap

	// relayManager manages allocation and handshaking of
	// [tailscale.com/net/udprelay.Server] endpoints.
	relayManager relayManager

	// discoInfo is the state for an active peer DiscoKey.
	discoInfo map[key.DiscoPublic]*discoInfo

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

	derpMap            *tailcfg.DERPMap              // nil (or zero regions/nodes) means DERP is disabled
	self               tailcfg.NodeView              // from last onNodeViewsUpdate
	peers              views.Slice[tailcfg.NodeView] // from last onNodeViewsUpdate, sorted by Node.ID; Note: [netmap.NodeMutation]'s rx'd in onNodeMutationsUpdate are never applied
	filt               *filter.Filter                // from last onFilterUpdate
	relayClientEnabled bool                          // whether we can allocate UDP relay endpoints on UDP relay servers or receive CallMeMaybeVia messages from peers
	lastFlags          debugFlags                    // at time of last onNodeViewsUpdate
	privateKey         key.NodePrivate               // WireGuard private key for this node
	everHadKey         bool                          // whether we ever had a non-zero private key
	myDerp             int                           // nearest DERP region ID; 0 means none/unknown
	homeless           bool                          // if true, don't try to find & stay conneted to a DERP home (myDerp will stay 0)
	derpStarted        chan struct{}                 // closed on first connection to DERP; for tests & cleaner Close
	activeDerp         map[int]activeDerp            // DERP regionID -> connection to a node in that region
	prevDerp           map[int]*syncs.WaitGroupChan

	// derpRoute contains optional alternate routes to use as an
	// optimization instead of contacting a peer via their home
	// DERP connection.  If they sent us a message on a different
	// DERP connection (which should really only be on our DERP
	// home connection, or what was once our home), then we
	// remember that route here to optimistically use instead of
	// creating a new DERP connection back to their home.
	derpRoute map[key.NodePublic]derpRoute

	// peerLastDerp tracks which DERP node we last used to speak with a
	// peer. It's only used to quiet logging, so we only log on change.
	peerLastDerp map[key.NodePublic]int

	// wgPinger is the WireGuard only pinger used for latency measurements.
	wgPinger lazy.SyncValue[*ping.Pinger]

	// getPeerByKey optionally specifies a function to look up a peer's
	// wireguard state by its public key. If nil, it's not used.
	getPeerByKey func(key.NodePublic) (_ wgint.Peer, ok bool)

	// lastErrRebind tracks the last time a rebind was performed after
	// experiencing a write error, and is used to throttle the rate of rebinds.
	lastErrRebind syncs.AtomicValue[time.Time]

	// staticEndpoints are user set endpoints that this node should
	// advertise amongst its wireguard endpoints. It is user's
	// responsibility to ensure that traffic from these endpoints is routed
	// to the node.
	staticEndpoints views.Slice[netip.AddrPort]

	// metrics contains the metrics for the magicsock instance.
	metrics *metrics
}

// SetDebugLoggingEnabled controls whether spammy debug logging is enabled.
//
// Note that this is currently independent from the log levels, even though
// they're pretty correlated: debugging logs should be [v1] (or higher), but
// some non-debug logs may also still have a [vN] annotation. The [vN] level
// controls which gets shown in stderr. The dlogf method, on the other hand,
// controls which gets even printed or uploaded at any level.
func (c *Conn) SetDebugLoggingEnabled(v bool) {
	c.debugLogging.Store(v)
}

// dlogf logs a debug message if debug logging is enabled via SetDebugLoggingEnabled.
func (c *Conn) dlogf(format string, a ...any) {
	if c.debugLogging.Load() {
		c.logf(format, a...)
	}
}

// Options contains options for Listen.
type Options struct {
	// EventBus, if non-nil, is used for event publication and subscription by
	// each Conn created from these Options. It must not be nil outside of
	// tests.
	EventBus *eventbus.Bus

	// Logf provides a log function to use. It must not be nil.
	// Use [logger.Discard] to disrcard logs.
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

	// TestOnlyPacketListener optionally specifies how to create PacketConns.
	// Only used by tests.
	TestOnlyPacketListener nettype.PacketListener

	// NoteRecvActivity, if provided, is a func for magicsock to call
	// whenever it receives a packet from a a peer if it's been more
	// than ~10 seconds since the last one. (10 seconds is somewhat
	// arbitrary; the sole user, lazy WireGuard configuration,
	// just doesn't need or want it called on
	// every packet, just every minute or two for WireGuard timeouts,
	// and 10 seconds seems like a good trade-off between often enough
	// and not too often.)
	// The provided func is likely to call back into
	// Conn.ParseEndpoint, which acquires Conn.mu. As such, you should
	// not hold Conn.mu while calling it.
	NoteRecvActivity func(key.NodePublic)

	// NetMon is the network monitor to use.
	// It must be non-nil.
	NetMon *netmon.Monitor

	// HealthTracker optionally specifies the health tracker to
	// report errors and warnings to.
	HealthTracker *health.Tracker

	// Metrics specifies the metrics registry to record metrics to.
	Metrics *usermetric.Registry

	// ControlKnobs are the set of control knobs to use.
	// If nil, they're ignored and not updated.
	ControlKnobs *controlknobs.Knobs

	// PeerByKeyFunc optionally specifies a function to look up a peer's
	// WireGuard state by its public key. If nil, it's not used.
	// In regular use, this will be wgengine.(*userspaceEngine).PeerByKey.
	PeerByKeyFunc func(key.NodePublic) (_ wgint.Peer, ok bool)

	// DisablePortMapper, if true, disables the portmapper.
	// This is primarily useful in tests.
	DisablePortMapper bool
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

// NodeViewsUpdate represents an update event of [tailcfg.NodeView] for all
// nodes. This event is published over an [eventbus.Bus]. It may be published
// with an invalid SelfNode, and/or zero/nil Peers. [magicsock.Conn] is the sole
// subscriber as of 2025-06. If you are adding more subscribers consider moving
// this type out of magicsock.
type NodeViewsUpdate struct {
	SelfNode tailcfg.NodeView
	Peers    []tailcfg.NodeView // sorted by Node.ID
}

// NodeMutationsUpdate represents an update event of one or more
// [netmap.NodeMutation]. This event is published over an [eventbus.Bus].
// [magicsock.Conn] is the sole subscriber as of 2025-06. If you are adding more
// subscribers consider moving this type out of magicsock.
type NodeMutationsUpdate struct {
	Mutations []netmap.NodeMutation
}

// FilterUpdate represents an update event for a [*filter.Filter]. This event is
// signaled over an [eventbus.Bus]. [magicsock.Conn] is the sole subscriber as
// of 2025-06. If you are adding more subscribers consider moving this type out
// of magicsock.
type FilterUpdate struct {
	*filter.Filter
}

// syncPoint is an event published over an [eventbus.Bus] by [Conn.Synchronize].
// It serves as a synchronization point, allowing to wait until magicsock
// has processed all pending events.
type syncPoint chan struct{}

// Wait blocks until [syncPoint.Signal] is called.
func (s syncPoint) Wait() {
	<-s
}

// Signal signals the sync point, unblocking the [syncPoint.Wait] call.
func (s syncPoint) Signal() {
	close(s)
}

// UDPRelayAllocReq represents a [*disco.AllocateUDPRelayEndpointRequest]
// reception event. This is signaled over an [eventbus.Bus] from
// [magicsock.Conn] towards [relayserver.extension].
type UDPRelayAllocReq struct {
	// RxFromNodeKey is the unauthenticated (DERP server claimed src) node key
	// of the transmitting party, noted at disco message reception time over
	// DERP. This node key is unambiguously-aligned with RxFromDiscoKey being
	// that the disco message is received over DERP.
	RxFromNodeKey key.NodePublic
	// RxFromDiscoKey is the disco key of the transmitting party, noted and
	// authenticated at reception time.
	RxFromDiscoKey key.DiscoPublic
	// Message is the disco message.
	Message *disco.AllocateUDPRelayEndpointRequest
}

// UDPRelayAllocResp represents a [*disco.AllocateUDPRelayEndpointResponse]
// that is yet to be transmitted over DERP (or delivered locally if
// ReqRxFromNodeKey is self). This is signaled over an [eventbus.Bus] from
// [relayserver.extension] towards [magicsock.Conn].
type UDPRelayAllocResp struct {
	// ReqRxFromNodeKey is copied from [UDPRelayAllocReq.RxFromNodeKey]. It
	// enables peer lookup leading up to transmission over DERP.
	ReqRxFromNodeKey key.NodePublic
	// ReqRxFromDiscoKey is copied from [UDPRelayAllocReq.RxFromDiscoKey].
	ReqRxFromDiscoKey key.DiscoPublic
	// Message is the disco message.
	Message *disco.AllocateUDPRelayEndpointResponse
}

// newConn is the error-free, network-listening-side-effect-free based
// of NewConn. Mostly for tests.
func newConn(logf logger.Logf) *Conn {
	discoPrivate := key.NewDisco()
	c := &Conn{
		logf:         logf,
		derpRecvCh:   make(chan derpReadResult, 1), // must be buffered, see issue 3736
		derpStarted:  make(chan struct{}),
		peerLastDerp: make(map[key.NodePublic]int),
		peerMap:      newPeerMap(),
		discoInfo:    make(map[key.DiscoPublic]*discoInfo),
		discoPrivate: discoPrivate,
		discoPublic:  discoPrivate.Public(),
		cloudInfo:    newCloudInfo(logf),
	}
	c.discoShort = c.discoPublic.ShortString()
	c.bind = &connBind{Conn: c, closed: true}
	c.receiveBatchPool = sync.Pool{New: func() any {
		msgs := make([]ipv6.Message, c.bind.BatchSize())
		for i := range msgs {
			msgs[i].Buffers = make([][]byte, 1)
			msgs[i].OOB = make([]byte, batching.MinControlMessageSize())
		}
		batch := &receiveBatch{
			msgs: msgs,
		}
		return batch
	}}
	c.muCond = sync.NewCond(&c.mu)
	c.networkUp.Store(true) // assume up until told otherwise
	return c
}

func (c *Conn) onUDPRelayAllocResp(allocResp UDPRelayAllocResp) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ep, ok := c.peerMap.endpointForNodeKey(allocResp.ReqRxFromNodeKey)
	if !ok {
		// If it's not a peer, it might be for self (we can peer relay through
		// ourselves), in which case we want to hand it down to [relayManager]
		// now versus taking a network round-trip through DERP.
		selfNodeKey := c.publicKeyAtomic.Load()
		if selfNodeKey.Compare(allocResp.ReqRxFromNodeKey) == 0 &&
			allocResp.ReqRxFromDiscoKey.Compare(c.discoPublic) == 0 {
			c.relayManager.handleRxDiscoMsg(c, allocResp.Message, selfNodeKey, allocResp.ReqRxFromDiscoKey, epAddr{})
			metricLocalDiscoAllocUDPRelayEndpointResponse.Add(1)
		}
		return
	}
	disco := ep.disco.Load()
	if disco == nil {
		return
	}
	if disco.key.Compare(allocResp.ReqRxFromDiscoKey) != 0 {
		return
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	derpAddr := ep.derpAddr
	go c.sendDiscoMessage(epAddr{ap: derpAddr}, ep.publicKey, disco.key, allocResp.Message, discoVerboseLog)
}

// Synchronize waits for all [eventbus] events published
// prior to this call to be processed by the receiver.
func (c *Conn) Synchronize() {
	if c.syncPub == nil {
		// Eventbus is not used; no need to synchronize (in certain tests).
		return
	}
	sp := syncPoint(make(chan struct{}))
	c.syncPub.Publish(sp)
	sp.Wait()
}

// NewConn creates a magic Conn listening on opts.Port.
// As the set of possible endpoints for a Conn changes, the
// callback opts.EndpointsFunc is called.
func NewConn(opts Options) (*Conn, error) {
	switch {
	case opts.NetMon == nil:
		return nil, errors.New("magicsock.Options.NetMon must be non-nil")
	case opts.EventBus == nil:
		return nil, errors.New("magicsock.Options.EventBus must be non-nil")
	}

	c := newConn(opts.logf())
	c.eventBus = opts.EventBus
	c.port.Store(uint32(opts.Port))
	c.controlKnobs = opts.ControlKnobs
	c.epFunc = opts.endpointsFunc()
	c.derpActiveFunc = opts.derpActiveFunc()
	c.idleFunc = opts.IdleFunc
	c.testOnlyPacketListener = opts.TestOnlyPacketListener
	c.noteRecvActivity = opts.NoteRecvActivity

	// Set up publishers and subscribers. Subscribe calls must return before
	// NewConn otherwise published events can be missed.
	ec := c.eventBus.Client("magicsock.Conn")
	c.eventClient = ec
	c.syncPub = eventbus.Publish[syncPoint](ec)
	c.allocRelayEndpointPub = eventbus.Publish[UDPRelayAllocReq](ec)
	c.portUpdatePub = eventbus.Publish[router.PortUpdate](ec)
	eventbus.SubscribeFunc(ec, c.onPortMapChanged)
	eventbus.SubscribeFunc(ec, c.onFilterUpdate)
	eventbus.SubscribeFunc(ec, c.onNodeViewsUpdate)
	eventbus.SubscribeFunc(ec, c.onNodeMutationsUpdate)
	eventbus.SubscribeFunc(ec, func(sp syncPoint) {
		c.dlogf("magicsock: received sync point after reconfig")
		sp.Signal()
	})
	eventbus.SubscribeFunc(ec, c.onUDPRelayAllocResp)

	c.connCtx, c.connCtxCancel = context.WithCancel(context.Background())
	c.donec = c.connCtx.Done()

	// Don't log the same log messages possibly every few seconds in our
	// portmapper.
	if buildfeatures.HasPortMapper && !opts.DisablePortMapper {
		portmapperLogf := logger.WithPrefix(c.logf, "portmapper: ")
		portmapperLogf = netmon.LinkChangeLogLimiter(c.connCtx, portmapperLogf, opts.NetMon)
		var disableUPnP func() bool
		if c.controlKnobs != nil {
			disableUPnP = c.controlKnobs.DisableUPnP.Load
		}
		newPortMapper, ok := portmappertype.HookNewPortMapper.GetOk()
		if ok {
			c.portMapper = newPortMapper(portmapperLogf, opts.EventBus, opts.NetMon, disableUPnP, c.onlyTCP443.Load)
		} else if !testenv.InTest() {
			panic("unexpected: HookNewPortMapper not set")
		}
	}

	c.netMon = opts.NetMon
	c.health = opts.HealthTracker
	c.getPeerByKey = opts.PeerByKeyFunc

	if err := c.rebind(keepCurrentPort); err != nil {
		return nil, err
	}

	c.netChecker = &netcheck.Client{
		Logf:                logger.WithPrefix(c.logf, "netcheck: "),
		NetMon:              c.netMon,
		SendPacket:          c.sendUDPNetcheck,
		SkipExternalNetwork: inTest(),
		PortMapper:          c.portMapper,
		UseDNSCache:         true,
	}

	c.metrics = registerMetrics(opts.Metrics)

	if d4, err := c.listenRawDisco("ip4"); err == nil {
		c.logf("[v1] using BPF disco receiver for IPv4")
		c.closeDisco4 = d4
	} else if !errors.Is(err, errors.ErrUnsupported) {
		c.logf("[v1] couldn't create raw v4 disco listener, using regular listener instead: %v", err)
	}
	if d6, err := c.listenRawDisco("ip6"); err == nil {
		c.logf("[v1] using BPF disco receiver for IPv6")
		c.closeDisco6 = d6
	} else if !errors.Is(err, errors.ErrUnsupported) {
		c.logf("[v1] couldn't create raw v6 disco listener, using regular listener instead: %v", err)
	}

	c.logf("magicsock: disco key = %v", c.discoShort)
	return c, nil
}

// registerMetrics wires up the metrics for wgengine, instead of
// registering the label metric directly, the underlying expvar is exposed.
// See metrics for more info.
func registerMetrics(reg *usermetric.Registry) *metrics {
	pathDirectV4 := pathLabel{Path: PathDirectIPv4}
	pathDirectV6 := pathLabel{Path: PathDirectIPv6}
	pathDERP := pathLabel{Path: PathDERP}
	pathPeerRelayV4 := pathLabel{Path: PathPeerRelayIPv4}
	pathPeerRelayV6 := pathLabel{Path: PathPeerRelayIPv6}
	inboundPacketsTotal := usermetric.NewMultiLabelMapWithRegistry[pathLabel](
		reg,
		"tailscaled_inbound_packets_total",
		"counter",
		"Counts the number of packets received from other peers",
	)
	inboundBytesTotal := usermetric.NewMultiLabelMapWithRegistry[pathLabel](
		reg,
		"tailscaled_inbound_bytes_total",
		"counter",
		"Counts the number of bytes received from other peers",
	)
	outboundPacketsTotal := usermetric.NewMultiLabelMapWithRegistry[pathLabel](
		reg,
		"tailscaled_outbound_packets_total",
		"counter",
		"Counts the number of packets sent to other peers",
	)
	outboundBytesTotal := usermetric.NewMultiLabelMapWithRegistry[pathLabel](
		reg,
		"tailscaled_outbound_bytes_total",
		"counter",
		"Counts the number of bytes sent to other peers",
	)
	outboundPacketsDroppedErrors := reg.DroppedPacketsOutbound()

	m := new(metrics)

	// Map clientmetrics to the usermetric counters.
	metricRecvDataPacketsIPv4.Register(&m.inboundPacketsIPv4Total)
	metricRecvDataPacketsIPv6.Register(&m.inboundPacketsIPv6Total)
	metricRecvDataPacketsDERP.Register(&m.inboundPacketsDERPTotal)
	metricRecvDataPacketsPeerRelayIPv4.Register(&m.inboundPacketsPeerRelayIPv4Total)
	metricRecvDataPacketsPeerRelayIPv6.Register(&m.inboundPacketsPeerRelayIPv6Total)
	metricRecvDataBytesIPv4.Register(&m.inboundBytesIPv4Total)
	metricRecvDataBytesIPv6.Register(&m.inboundBytesIPv6Total)
	metricRecvDataBytesDERP.Register(&m.inboundBytesDERPTotal)
	metricRecvDataBytesPeerRelayIPv4.Register(&m.inboundBytesPeerRelayIPv4Total)
	metricRecvDataBytesPeerRelayIPv6.Register(&m.inboundBytesPeerRelayIPv6Total)
	metricSendDataPacketsIPv4.Register(&m.outboundPacketsIPv4Total)
	metricSendDataPacketsIPv6.Register(&m.outboundPacketsIPv6Total)
	metricSendDataPacketsDERP.Register(&m.outboundPacketsDERPTotal)
	metricSendDataPacketsPeerRelayIPv4.Register(&m.outboundPacketsPeerRelayIPv4Total)
	metricSendDataPacketsPeerRelayIPv6.Register(&m.outboundPacketsPeerRelayIPv6Total)
	metricSendDataBytesIPv4.Register(&m.outboundBytesIPv4Total)
	metricSendDataBytesIPv6.Register(&m.outboundBytesIPv6Total)
	metricSendDataBytesDERP.Register(&m.outboundBytesDERPTotal)
	metricSendDataBytesPeerRelayIPv4.Register(&m.outboundBytesPeerRelayIPv4Total)
	metricSendDataBytesPeerRelayIPv6.Register(&m.outboundBytesPeerRelayIPv6Total)
	metricSendUDP.Register(&m.outboundPacketsIPv4Total)
	metricSendUDP.Register(&m.outboundPacketsIPv6Total)
	metricSendDERP.Register(&m.outboundPacketsDERPTotal)
	metricSendPeerRelay.Register(&m.outboundPacketsPeerRelayIPv4Total)
	metricSendPeerRelay.Register(&m.outboundPacketsPeerRelayIPv6Total)

	inboundPacketsTotal.Set(pathDirectV4, &m.inboundPacketsIPv4Total)
	inboundPacketsTotal.Set(pathDirectV6, &m.inboundPacketsIPv6Total)
	inboundPacketsTotal.Set(pathDERP, &m.inboundPacketsDERPTotal)
	inboundPacketsTotal.Set(pathPeerRelayV4, &m.inboundPacketsPeerRelayIPv4Total)
	inboundPacketsTotal.Set(pathPeerRelayV6, &m.inboundPacketsPeerRelayIPv6Total)

	inboundBytesTotal.Set(pathDirectV4, &m.inboundBytesIPv4Total)
	inboundBytesTotal.Set(pathDirectV6, &m.inboundBytesIPv6Total)
	inboundBytesTotal.Set(pathDERP, &m.inboundBytesDERPTotal)
	inboundBytesTotal.Set(pathPeerRelayV4, &m.inboundBytesPeerRelayIPv4Total)
	inboundBytesTotal.Set(pathPeerRelayV6, &m.inboundBytesPeerRelayIPv6Total)

	outboundPacketsTotal.Set(pathDirectV4, &m.outboundPacketsIPv4Total)
	outboundPacketsTotal.Set(pathDirectV6, &m.outboundPacketsIPv6Total)
	outboundPacketsTotal.Set(pathDERP, &m.outboundPacketsDERPTotal)
	outboundPacketsTotal.Set(pathPeerRelayV4, &m.outboundPacketsPeerRelayIPv4Total)
	outboundPacketsTotal.Set(pathPeerRelayV6, &m.outboundPacketsPeerRelayIPv6Total)

	outboundBytesTotal.Set(pathDirectV4, &m.outboundBytesIPv4Total)
	outboundBytesTotal.Set(pathDirectV6, &m.outboundBytesIPv6Total)
	outboundBytesTotal.Set(pathDERP, &m.outboundBytesDERPTotal)
	outboundBytesTotal.Set(pathPeerRelayV4, &m.outboundBytesPeerRelayIPv4Total)
	outboundBytesTotal.Set(pathPeerRelayV6, &m.outboundBytesPeerRelayIPv6Total)

	outboundPacketsDroppedErrors.Set(usermetric.DropLabels{Reason: usermetric.ReasonError}, &m.outboundPacketsDroppedErrors)

	return m
}

// deregisterMetrics unregisters the underlying usermetrics expvar counters
// from clientmetrics.
func deregisterMetrics() {
	metricRecvDataPacketsIPv4.UnregisterAll()
	metricRecvDataPacketsIPv6.UnregisterAll()
	metricRecvDataPacketsDERP.UnregisterAll()
	metricRecvDataPacketsPeerRelayIPv4.UnregisterAll()
	metricRecvDataPacketsPeerRelayIPv6.UnregisterAll()
	metricRecvDataBytesIPv4.UnregisterAll()
	metricRecvDataBytesIPv6.UnregisterAll()
	metricRecvDataBytesDERP.UnregisterAll()
	metricRecvDataBytesPeerRelayIPv4.UnregisterAll()
	metricRecvDataBytesPeerRelayIPv6.UnregisterAll()
	metricSendDataPacketsIPv4.UnregisterAll()
	metricSendDataPacketsIPv6.UnregisterAll()
	metricSendDataPacketsDERP.UnregisterAll()
	metricSendDataPacketsPeerRelayIPv4.UnregisterAll()
	metricSendDataPacketsPeerRelayIPv6.UnregisterAll()
	metricSendDataBytesIPv4.UnregisterAll()
	metricSendDataBytesIPv6.UnregisterAll()
	metricSendDataBytesDERP.UnregisterAll()
	metricSendDataBytesPeerRelayIPv4.UnregisterAll()
	metricSendDataBytesPeerRelayIPv6.UnregisterAll()
	metricSendUDP.UnregisterAll()
	metricSendDERP.UnregisterAll()
	metricSendPeerRelay.UnregisterAll()
}

// InstallCaptureHook installs a callback which is called to
// log debug information into the pcap stream. This function
// can be called with a nil argument to uninstall the capture
// hook.
func (c *Conn) InstallCaptureHook(cb packet.CaptureCallback) {
	if !buildfeatures.HasCapture {
		return
	}
	c.captureHook.Store(cb)
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
	metricUpdateEndpoints.Add(1)
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
					if debugReSTUNStopOnIdle() {
						c.logf("resetting existing periodicSTUN to run in %v", d)
					}
					t.Reset(d)
				} else {
					if debugReSTUNStopOnIdle() {
						c.logf("scheduling periodicSTUN to run in %v", d)
					}
					c.periodicReSTUNTimer = time.AfterFunc(d, c.doPeriodicSTUN)
				}
			} else {
				if debugReSTUNStopOnIdle() {
					c.logf("periodic STUN idle")
				}
				c.stopPeriodicReSTUNTimerLocked()
			}
		}
		c.endpointsUpdateActive = false
		c.muCond.Broadcast()
	}()
	c.dlogf("[v1] magicsock: starting endpoint update (%s)", why)
	if c.noV4Send.Load() && runtime.GOOS != "js" && !c.onlyTCP443.Load() && !hostinfo.IsInVM86() {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if !closed {
			c.logf("magicsock: last netcheck reported send error. Rebinding.")
			c.Rebind()
		}
	}

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
		c.dlogf("[v1] magicsock: ignoring pre-DERP map, STUN-less endpoint update: %v", endpoints)
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

// SetStaticEndpoints sets static endpoints to the provided value and triggers
// an asynchronous update of the endpoints that this node advertises.
// Static endpoints are endpoints explicitly configured by user.
func (c *Conn) SetStaticEndpoints(ep views.Slice[netip.AddrPort]) {
	c.mu.Lock()
	if reflect.DeepEqual(c.staticEndpoints.AsSlice(), ep.AsSlice()) {
		c.mu.Unlock()
		return
	}
	c.staticEndpoints = ep
	c.mu.Unlock()
	// Technically this is not a reSTUNning, but ReSTUN does what we need at
	// this point- calls updateEndpoints or queues an update if there is
	// already an in-progress update.
	c.ReSTUN("static-endpoint-change")
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

	report, err := c.netChecker.GetReport(ctx, dm, &netcheck.GetReportOpts{
		// Pass information about the last time that we received a
		// frame from a DERP server to our netchecker to help avoid
		// flapping the home region while there's still active
		// communication.
		//
		// NOTE(andrew-d): I don't love that we're depending on the
		// health package here, but I'd rather do that and not store
		// the exact same state in two different places.
		GetLastDERPActivity: c.health.GetDERPRegionReceivedTime,
		OnlyTCP443:          c.onlyTCP443.Load(),
	})
	if err != nil {
		return nil, err
	}

	c.lastNetCheckReport.Store(report)
	c.noV4.Store(!report.IPv4)
	c.noV6.Store(!report.IPv6)
	c.noV4Send.Store(!report.IPv4CanSend)

	ni := &tailcfg.NetInfo{
		DERPLatency:           map[string]float64{},
		MappingVariesByDestIP: report.MappingVariesByDestIP,
		UPnP:                  report.UPnP,
		PMP:                   report.PMP,
		PCP:                   report.PCP,
	}
	if c.portMapper != nil {
		ni.HavePortMap = c.portMapper.HaveMapping()
	}
	for rid, d := range report.RegionV4Latency {
		ni.DERPLatency[fmt.Sprintf("%d-v4", rid)] = d.Seconds()
	}
	for rid, d := range report.RegionV6Latency {
		ni.DERPLatency[fmt.Sprintf("%d-v6", rid)] = d.Seconds()
	}
	ni.WorkingIPv6.Set(report.IPv6)
	ni.OSHasIPv6.Set(report.OSHasIPv6)
	ni.WorkingUDP.Set(report.UDP)
	ni.WorkingICMPv4.Set(report.ICMPv4)
	ni.PreferredDERP = c.maybeSetNearestDERP(report)
	ni.FirewallMode = hostinfo.FirewallMode()

	c.callNetInfoCallback(ni)
	return report, nil
}

// callNetInfoCallback calls the callback (if previously
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
		c.dlogf("[v1] magicsock: netInfo update: %+v", ni)
		go c.netInfoFunc(ni)
	}
}

// addValidDiscoPathForTest makes addr a validated disco address for
// discoKey. It's used in tests to enable receiving of packets from
// addr without having to spin up the entire active discovery
// machinery.
func (c *Conn) addValidDiscoPathForTest(nodeKey key.NodePublic, addr netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerMap.setNodeKeyForEpAddr(epAddr{ap: addr}, nodeKey)
}

// SetNetInfoCallback sets the func to be called whenever the network conditions
// change.
//
// At most one func can be registered; the most recent one replaces any previous
// registration.
//
// This is called by LocalBackend.
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

// LastRecvActivityOfNodeKey describes the time we last got traffic from
// this endpoint (updated every ~10 seconds).
func (c *Conn) LastRecvActivityOfNodeKey(nk key.NodePublic) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	de, ok := c.peerMap.endpointForNodeKey(nk)
	if !ok {
		return "never"
	}
	saw := de.lastRecvWG.LoadAtomic()
	if saw == 0 {
		return "never"
	}
	return mono.Since(saw).Round(time.Second).String()
}

// Ping handles a "tailscale ping" CLI query.
func (c *Conn) Ping(peer tailcfg.NodeView, res *ipnstate.PingResult, size int, cb func(*ipnstate.PingResult)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.privateKey.IsZero() {
		res.Err = "local tailscaled stopped"
		cb(res)
		return
	}
	if peer.Addresses().Len() > 0 {
		res.NodeIP = peer.Addresses().At(0).Addr().String()
	}
	res.NodeName = peer.Name() // prefer DNS name
	if res.NodeName == "" {
		res.NodeName = peer.Hostinfo().Hostname() // else hostname
	} else {
		res.NodeName, _, _ = strings.Cut(res.NodeName, ".")
	}

	ep, ok := c.peerMap.endpointForNodeKey(peer.Key())
	if !ok {
		res.Err = "unknown peer"
		cb(res)
		return
	}
	ep.discoPing(res, size, cb)
}

// c.mu must be held
func (c *Conn) populateCLIPingResponseLocked(res *ipnstate.PingResult, latency time.Duration, ep epAddr) {
	res.LatencySeconds = latency.Seconds()
	if ep.ap.Addr() != tailcfg.DerpMagicIPAddr {
		if ep.vni.IsSet() {
			res.PeerRelay = ep.String()
		} else {
			res.Endpoint = ep.String()
		}
		return
	}
	regionID := int(ep.ap.Port())
	res.DERPRegionID = regionID
	res.DERPRegionCode = c.derpRegionCodeLocked(regionID)
}

// GetEndpointChanges returns the most recent changes for a particular
// endpoint. The returned EndpointChange structs are for debug use only and
// there are no guarantees about order, size, or content.
func (c *Conn) GetEndpointChanges(peer tailcfg.NodeView) ([]EndpointChange, error) {
	c.mu.Lock()
	if c.privateKey.IsZero() {
		c.mu.Unlock()
		return nil, fmt.Errorf("tailscaled stopped")
	}
	ep, ok := c.peerMap.endpointForNodeKey(peer.Key())
	c.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("unknown peer")
	}

	return ep.debugUpdates.GetAll(), nil
}

// DiscoPublicKey returns the discovery public key.
func (c *Conn) DiscoPublicKey() key.DiscoPublic {
	return c.discoPublic
}

// determineEndpoints returns the machine's endpoint addresses. It does a STUN
// lookup (via netcheck) to determine its public address. Additionally any
// static enpoints provided by user are always added to the returned endpoints
// without validating if the node can be reached via those endpoints.
//
// c.mu must NOT be held.
func (c *Conn) determineEndpoints(ctx context.Context) ([]tailcfg.Endpoint, error) {
	var havePortmap bool
	var portmapExt netip.AddrPort
	if runtime.GOOS != "js" && c.portMapper != nil {
		portmapExt, havePortmap = c.portMapper.GetCachedMappingOrStartCreatingOne()
	}

	nr, err := c.updateNetInfo(ctx)
	if err != nil {
		c.logf("magicsock.Conn.determineEndpoints: updateNetInfo: %v", err)
		return nil, err
	}

	if runtime.GOOS == "js" {
		// TODO(bradfitz): why does control require an
		// endpoint? Otherwise it doesn't stream map responses
		// back.
		return []tailcfg.Endpoint{
			{
				Addr: netip.MustParseAddrPort("[fe80:123:456:789::1]:12345"),
				Type: tailcfg.EndpointLocal,
			},
		}, nil
	}

	var already map[netip.AddrPort]tailcfg.EndpointType // endpoint -> how it was found
	var eps []tailcfg.Endpoint                          // unique endpoints

	ipp := func(s string) (ipp netip.AddrPort) {
		ipp, _ = netip.ParseAddrPort(s)
		return
	}
	addAddr := func(ipp netip.AddrPort, et tailcfg.EndpointType) {
		if !ipp.IsValid() || (debugOmitLocalAddresses() && et == tailcfg.EndpointLocal) {
			return
		}
		if _, ok := already[ipp]; !ok {
			mak.Set(&already, ipp, et)
			eps = append(eps, tailcfg.Endpoint{Addr: ipp, Type: et})
		}
	}

	// If we didn't have a portmap earlier, maybe it's done by now.
	if !havePortmap && c.portMapper != nil {
		portmapExt, havePortmap = c.portMapper.GetCachedMappingOrStartCreatingOne()
	}
	if havePortmap {
		addAddr(portmapExt, tailcfg.EndpointPortmapped)
		c.setNetInfoHavePortMap()
	}

	v4Addrs, v6Addrs := nr.GetGlobalAddrs()
	for _, addr := range v4Addrs {
		addAddr(addr, tailcfg.EndpointSTUN)
	}
	for _, addr := range v6Addrs {
		addAddr(addr, tailcfg.EndpointSTUN)
	}

	if len(v4Addrs) >= 1 {
		// If they're behind a hard NAT and are using a fixed
		// port locally, assume they might've added a static
		// port mapping on their router to the same explicit
		// port that tailscaled is running with. Worst case
		// it's an invalid candidate mapping.
		if port := c.port.Load(); nr.MappingVariesByDestIP.EqualBool(true) && port != 0 {
			addAddr(netip.AddrPortFrom(v4Addrs[0].Addr(), uint16(port)), tailcfg.EndpointSTUN4LocalPort)
		}
	}

	// Temporarily (2024-07-08) during investigations, allow setting
	// pretend endpoint(s) for testing NAT traversal scenarios.
	// TODO(bradfitz): probably promote this to the config file.
	// https://github.com/tailscale/tailscale/issues/12578
	for _, ap := range pretendpoints() {
		addAddr(ap, tailcfg.EndpointExplicitConf)
	}

	// If we're on a cloud instance, we might have a public IPv4 or IPv6
	// address that we can be reached at. Find those, if they exist, and
	// add them.
	if addrs, err := c.cloudInfo.GetPublicIPs(ctx); err == nil {
		var port4, port6 uint16
		if addr := c.pconn4.LocalAddr(); addr != nil {
			port4 = uint16(addr.Port)
		}
		if addr := c.pconn6.LocalAddr(); addr != nil {
			port6 = uint16(addr.Port)
		}

		for _, addr := range addrs {
			if addr.Is4() && port4 > 0 {
				addAddr(netip.AddrPortFrom(addr, port4), tailcfg.EndpointLocal)
			} else if addr.Is6() && port6 > 0 {
				addAddr(netip.AddrPortFrom(addr, port6), tailcfg.EndpointLocal)
			}
		}
	}

	// Update our set of endpoints by adding any endpoints that we
	// previously found but haven't expired yet. This also updates the
	// cache with the set of endpoints discovered in this function.
	//
	// NOTE: we do this here and not below so that we don't cache local
	// endpoints; we know that the local endpoints we discover are all
	// possible local endpoints since we determine them by looking at the
	// set of addresses on our local interfaces.
	//
	// TODO(andrew): If we pull in any cached endpoints, we should probably
	// do something to ensure we're propagating the removal of those cached
	// endpoints if they do actually time out without being rediscovered.
	// For now, though, rely on a minor LinkChange event causing this to
	// re-run.
	eps = c.endpointTracker.update(time.Now(), eps)

	for _, ep := range c.staticEndpoints.All() {
		addAddr(ep, tailcfg.EndpointExplicitConf)
	}

	if localAddr := c.pconn4.LocalAddr(); localAddr.IP.IsUnspecified() {
		ips, loopback, err := netmon.LocalAddresses()
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
			addAddr(netip.AddrPortFrom(ip, uint16(localAddr.Port)), tailcfg.EndpointLocal)
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
	if runtime.GOOS == "js" {
		return 12345
	}
	laddr := c.pconn4.LocalAddr()
	return uint16(laddr.Port)
}

var errNetworkDown = errors.New("magicsock: network down")

func (c *Conn) networkDown() bool { return !c.networkUp.Load() }

// Send implements conn.Bind.
//
// See https://pkg.go.dev/github.com/tailscale/wireguard-go/conn#Bind.Send
func (c *Conn) Send(buffs [][]byte, ep conn.Endpoint, offset int) (err error) {
	n := int64(len(buffs))
	defer func() {
		if err != nil {
			c.metrics.outboundPacketsDroppedErrors.Add(n)
		}
	}()
	metricSendData.Add(n)
	if c.networkDown() {
		metricSendDataNetworkDown.Add(n)
		return errNetworkDown
	}
	switch ep := ep.(type) {
	case *endpoint:
		return ep.send(buffs, offset)
	case *lazyEndpoint:
		// A [*lazyEndpoint] may end up on this TX codepath when wireguard-go is
		// deemed "under handshake load" and ends up transmitting a cookie reply
		// using the received [conn.Endpoint] in [device.SendHandshakeCookie].
		if ep.src.ap.Addr().Is6() {
			return c.pconn6.WriteWireGuardBatchTo(buffs, ep.src, offset)
		}
		return c.pconn4.WriteWireGuardBatchTo(buffs, ep.src, offset)
	}
	return nil
}

var errConnClosed = errors.New("Conn closed")

var errDropDerpPacket = errors.New("too many DERP packets queued; dropping")

var errNoUDP = errors.New("no UDP available on platform")

var errUnsupportedConnType = errors.New("unsupported connection type")

func (c *Conn) sendUDPBatch(addr epAddr, buffs [][]byte, offset int) (sent bool, err error) {
	isIPv6 := false
	switch {
	case addr.ap.Addr().Is4():
	case addr.ap.Addr().Is6():
		isIPv6 = true
	default:
		panic("bogus sendUDPBatch addr type")
	}
	if isIPv6 {
		err = c.pconn6.WriteWireGuardBatchTo(buffs, addr, offset)
	} else {
		err = c.pconn4.WriteWireGuardBatchTo(buffs, addr, offset)
	}
	if err != nil {
		var errGSO neterror.ErrUDPGSODisabled
		if errors.As(err, &errGSO) {
			c.logf("magicsock: %s", errGSO.Error())
			err = errGSO.RetryErr
		} else {
			c.maybeRebindOnError(err)
		}
	}
	return err == nil, err
}

// sendUDP sends UDP packet b to ipp.
// See sendAddr's docs on the return value meanings.
func (c *Conn) sendUDP(ipp netip.AddrPort, b []byte, isDisco bool, isGeneveEncap bool) (sent bool, err error) {
	if runtime.GOOS == "js" {
		return false, errNoUDP
	}
	sent, err = c.sendUDPStd(ipp, b)
	if err != nil {
		if isGeneveEncap {
			metricSendPeerRelayError.Add(1)
		} else {
			metricSendUDPError.Add(1)
		}
		c.maybeRebindOnError(err)
	} else {
		if sent && !isDisco {
			switch {
			case ipp.Addr().Is4():
				if isGeneveEncap {
					c.metrics.outboundPacketsPeerRelayIPv4Total.Add(1)
					c.metrics.outboundBytesPeerRelayIPv4Total.Add(int64(len(b)))
				} else {
					c.metrics.outboundPacketsIPv4Total.Add(1)
					c.metrics.outboundBytesIPv4Total.Add(int64(len(b)))
				}
			case ipp.Addr().Is6():
				if isGeneveEncap {
					c.metrics.outboundPacketsPeerRelayIPv6Total.Add(1)
					c.metrics.outboundBytesPeerRelayIPv6Total.Add(int64(len(b)))
				} else {
					c.metrics.outboundPacketsIPv6Total.Add(1)
					c.metrics.outboundBytesIPv6Total.Add(int64(len(b)))
				}
			}
		}
	}
	return
}

// maybeRebindOnError performs a rebind and restun if the error is one that is
// known to be healed by a rebind, and the rebind is not throttled.
func (c *Conn) maybeRebindOnError(err error) {
	ok, reason := shouldRebind(err)
	if !ok {
		return
	}

	if c.lastErrRebind.Load().Before(time.Now().Add(-5 * time.Second)) {
		c.logf("magicsock: performing rebind due to %q", reason)
		c.lastErrRebind.Store(time.Now())
		c.Rebind()
		go c.ReSTUN(reason)
	} else {
		c.logf("magicsock: not performing %q rebind due to throttle", reason)
	}
}

// sendUDPNetcheck sends b via UDP to addr. It is used exclusively by netcheck.
// It returns the number of bytes sent along with any error encountered. It
// returns errors.ErrUnsupported if the client is explicitly configured to only
// send data over TCP port 443 and/or we're running on wasm.
func (c *Conn) sendUDPNetcheck(b []byte, addr netip.AddrPort) (int, error) {
	if c.onlyTCP443.Load() || runtime.GOOS == "js" {
		return 0, errors.ErrUnsupported
	}
	switch {
	case addr.Addr().Is4():
		return c.pconn4.WriteToUDPAddrPort(b, addr)
	case addr.Addr().Is6():
		return c.pconn6.WriteToUDPAddrPort(b, addr)
	default:
		panic("bogus sendUDPNetcheck addr type")
	}
}

// sendUDPStd sends UDP packet b to addr.
// See sendAddr's docs on the return value meanings.
func (c *Conn) sendUDPStd(addr netip.AddrPort, b []byte) (sent bool, err error) {
	if c.onlyTCP443.Load() {
		return false, nil
	}
	switch {
	case addr.Addr().Is4():
		_, err = c.pconn4.WriteToUDPAddrPort(b, addr)
		if err != nil && (c.noV4.Load() || neterror.TreatAsLostUDP(err)) {
			return false, nil
		}
	case addr.Addr().Is6():
		_, err = c.pconn6.WriteToUDPAddrPort(b, addr)
		if err != nil && (c.noV6.Load() || neterror.TreatAsLostUDP(err)) {
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
func (c *Conn) sendAddr(addr netip.AddrPort, pubKey key.NodePublic, b []byte, isDisco bool, isGeneveEncap bool) (sent bool, err error) {
	if addr.Addr() != tailcfg.DerpMagicIPAddr {
		return c.sendUDP(addr, b, isDisco, isGeneveEncap)
	}

	regionID := int(addr.Port())
	ch := c.derpWriteChanForRegion(regionID, pubKey)
	if ch == nil {
		metricSendDERPErrorChan.Add(1)
		return false, nil
	}

	// TODO(bradfitz): this makes garbage for now; we could use a
	// buffer pool later.  Previously we passed ownership of this
	// to derpWriteRequest and waited for derphttp.Client.Send to
	// complete, but that's too slow while holding wireguard-go
	// internal locks.
	pkt := bytes.Clone(b)

	wr := derpWriteRequest{addr, pubKey, pkt, isDisco}
	for range 3 {
		select {
		case <-c.donec:
			metricSendDERPErrorClosed.Add(1)
			return false, errConnClosed
		case ch <- wr:
			metricSendDERPQueued.Add(1)
			return true, nil
		default:
			select {
			case <-ch:
				metricSendDERPDropped.Add(1)
			default:
			}
		}
	}
	// gave up after 3 write attempts
	metricSendDERPErrorQueue.Add(1)
	// Too many writes queued. Drop packet.
	return false, errDropDerpPacket
}

type receiveBatch struct {
	msgs []ipv6.Message
}

func (c *Conn) getReceiveBatchForBuffs(buffs [][]byte) *receiveBatch {
	batch := c.receiveBatchPool.Get().(*receiveBatch)
	for i := range buffs {
		batch.msgs[i].Buffers[0] = buffs[i]
		batch.msgs[i].OOB = batch.msgs[i].OOB[:cap(batch.msgs[i].OOB)]
	}
	return batch
}

func (c *Conn) putReceiveBatch(batch *receiveBatch) {
	for i := range batch.msgs {
		batch.msgs[i] = ipv6.Message{Buffers: batch.msgs[i].Buffers, OOB: batch.msgs[i].OOB}
	}
	c.receiveBatchPool.Put(batch)
}

func (c *Conn) receiveIPv4() conn.ReceiveFunc {
	return c.mkReceiveFunc(&c.pconn4, c.health.ReceiveFuncStats(health.ReceiveIPv4),
		&c.metrics.inboundPacketsIPv4Total,
		&c.metrics.inboundPacketsPeerRelayIPv4Total,
		&c.metrics.inboundBytesIPv4Total,
		&c.metrics.inboundBytesPeerRelayIPv4Total,
	)
}

// receiveIPv6 creates an IPv6 ReceiveFunc reading from c.pconn6.
func (c *Conn) receiveIPv6() conn.ReceiveFunc {
	return c.mkReceiveFunc(&c.pconn6, c.health.ReceiveFuncStats(health.ReceiveIPv6),
		&c.metrics.inboundPacketsIPv6Total,
		&c.metrics.inboundPacketsPeerRelayIPv6Total,
		&c.metrics.inboundBytesIPv6Total,
		&c.metrics.inboundBytesPeerRelayIPv6Total,
	)
}

// mkReceiveFunc creates a ReceiveFunc reading from ruc.
// The provided healthItem and metrics are updated if non-nil.
func (c *Conn) mkReceiveFunc(ruc *RebindingUDPConn, healthItem *health.ReceiveFuncStats, directPacketMetric, peerRelayPacketMetric, directBytesMetric, peerRelayBytesMetric *expvar.Int) conn.ReceiveFunc {
	// epCache caches an epAddr->endpoint for hot flows.
	var epCache epAddrEndpointCache

	return func(buffs [][]byte, sizes []int, eps []conn.Endpoint) (_ int, retErr error) {
		if buildfeatures.HasHealth && healthItem != nil {
			healthItem.Enter()
			defer healthItem.Exit()
			defer func() {
				if retErr != nil && !c.closing.Load() {
					c.logf("Receive func %s exiting with error: %T, %v", healthItem.Name(), retErr, retErr)
				}
			}()
		}
		if ruc == nil {
			panic("nil RebindingUDPConn")
		}

		batch := c.getReceiveBatchForBuffs(buffs)
		defer c.putReceiveBatch(batch)
		for {
			numMsgs, err := ruc.ReadBatch(batch.msgs[:len(buffs)], 0)
			if err != nil {
				if neterror.PacketWasTruncated(err) {
					continue
				}
				return 0, err
			}

			reportToCaller := false
			for i, msg := range batch.msgs[:numMsgs] {
				if msg.N == 0 {
					sizes[i] = 0
					continue
				}
				ipp := msg.Addr.(*net.UDPAddr).AddrPort()
				if ep, size, isGeneveEncap, ok := c.receiveIP(msg.Buffers[0][:msg.N], ipp, &epCache); ok {
					if isGeneveEncap {
						if peerRelayPacketMetric != nil {
							peerRelayPacketMetric.Add(1)
						}
						if peerRelayBytesMetric != nil {
							peerRelayBytesMetric.Add(int64(msg.N))
						}
					} else {
						if directPacketMetric != nil {
							directPacketMetric.Add(1)
						}
						if directBytesMetric != nil {
							directBytesMetric.Add(int64(msg.N))
						}
					}
					eps[i] = ep
					sizes[i] = size
					reportToCaller = true
				} else {
					sizes[i] = 0
				}
			}
			if reportToCaller {
				return numMsgs, nil
			}
		}
	}
}

// looksLikeInitiationMsg returns true if b looks like a WireGuard initiation
// message, otherwise it returns false.
func looksLikeInitiationMsg(b []byte) bool {
	return len(b) == device.MessageInitiationSize &&
		binary.LittleEndian.Uint32(b) == device.MessageInitiationType
}

// receiveIP is the shared bits of ReceiveIPv4 and ReceiveIPv6.
//
// size is the length of 'b' to report up to wireguard-go (only relevant if
// 'ok' is true).
//
// isGeneveEncap is whether 'b' is encapsulated by a Geneve header (only
// relevant if 'ok' is true).
//
// ok is whether this read should be reported up to wireguard-go (our
// caller).
func (c *Conn) receiveIP(b []byte, ipp netip.AddrPort, cache *epAddrEndpointCache) (_ conn.Endpoint, size int, isGeneveEncap bool, ok bool) {
	var ep *endpoint
	size = len(b)

	var geneve packet.GeneveHeader
	pt, isGeneveEncap := packetLooksLike(b)
	src := epAddr{ap: ipp}
	if isGeneveEncap {
		err := geneve.Decode(b)
		if err != nil {
			// Decode only returns an error when 'b' is too short, and
			// 'isGeneveEncap' indicates it's a sufficient length.
			c.logf("[unexpected] geneve header decoding error: %v", err)
			return nil, 0, false, false
		}
		src.vni = geneve.VNI
	}
	switch pt {
	case packetLooksLikeDisco:
		if isGeneveEncap {
			b = b[packet.GeneveFixedHeaderLength:]
		}
		// The Geneve header control bit should only be set for relay handshake
		// messages terminating on or originating from a UDP relay server. We
		// have yet to open the encrypted disco payload to determine the
		// [disco.MessageType], but we assert it should be handshake-related.
		shouldByRelayHandshakeMsg := geneve.Control == true
		c.handleDiscoMessage(b, src, shouldByRelayHandshakeMsg, key.NodePublic{}, discoRXPathUDP)
		return nil, 0, false, false
	case packetLooksLikeSTUNBinding:
		c.netChecker.ReceiveSTUNPacket(b, ipp)
		return nil, 0, false, false
	default:
		// Fall through for all other packet types as they are assumed to
		// be potentially WireGuard.
	}

	if !c.havePrivateKey.Load() {
		// If we have no private key, we're logged out or
		// stopped. Don't try to pass these wireguard packets
		// up to wireguard-go; it'll just complain (issue 1167).
		return nil, 0, false, false
	}

	// geneveInclusivePacketLen holds the packet length prior to any potential
	// Geneve header stripping.
	geneveInclusivePacketLen := len(b)
	if src.vni.IsSet() {
		// Strip away the Geneve header before returning the packet to
		// wireguard-go.
		//
		// TODO(jwhited): update [github.com/tailscale/wireguard-go/conn.ReceiveFunc]
		//  to support returning start offset in order to get rid of this memmove perf
		//  penalty.
		size = copy(b, b[packet.GeneveFixedHeaderLength:])
		b = b[:size]
	}

	if cache.epAddr == src && cache.de != nil && cache.gen == cache.de.numStopAndReset() {
		ep = cache.de
	} else {
		c.mu.Lock()
		de, ok := c.peerMap.endpointForEpAddr(src)
		c.mu.Unlock()
		if !ok {
			// TODO(jwhited): reuse [lazyEndpoint] across calls to receiveIP()
			//  for the same batch & [epAddr] src.
			return &lazyEndpoint{c: c, src: src}, size, isGeneveEncap, true
		}
		cache.epAddr = src
		cache.de = de
		cache.gen = de.numStopAndReset()
		ep = de
	}
	now := mono.Now()
	ep.lastRecvUDPAny.StoreAtomic(now)
	connNoted := ep.noteRecvActivity(src, now)
	if buildfeatures.HasNetLog {
		if update := c.connCounter.Load(); update != nil {
			update(0, netip.AddrPortFrom(ep.nodeAddr, 0), ipp, 1, geneveInclusivePacketLen, true)
		}
	}
	if src.vni.IsSet() && (connNoted || looksLikeInitiationMsg(b)) {
		// connNoted is periodic, but we also want to verify if the peer is who
		// we believe for all initiation messages, otherwise we could get
		// unlucky and fail to JIT configure the "correct" peer.
		// TODO(jwhited): relax this to include direct connections
		//  See http://go/corp/29422 & http://go/corp/30042
		return &lazyEndpoint{c: c, maybeEP: ep, src: src}, size, isGeneveEncap, true
	}
	return ep, size, isGeneveEncap, true
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

// TS_DISCO_PONG_IPV4_DELAY, if set, is a time.Duration string that is how much
// fake latency to add before replying to disco pings. This can be used to bias
// peers towards using IPv6 when both IPv4 and IPv6 are available at similar
// speeds.
var debugIPv4DiscoPingPenalty = envknob.RegisterDuration("TS_DISCO_PONG_IPV4_DELAY")

// sendDiscoAllocateUDPRelayEndpointRequest is primarily an alias for
// sendDiscoMessage, but it will alternatively send m over the eventbus if dst
// is a DERP IP:port, and dstKey is self. This saves a round-trip through DERP
// when we are attempting to allocate on a self (in-process) peer relay server.
func (c *Conn) sendDiscoAllocateUDPRelayEndpointRequest(dst epAddr, dstKey key.NodePublic, dstDisco key.DiscoPublic, allocReq *disco.AllocateUDPRelayEndpointRequest, logLevel discoLogLevel) (sent bool, err error) {
	isDERP := dst.ap.Addr() == tailcfg.DerpMagicIPAddr
	selfNodeKey := c.publicKeyAtomic.Load()
	if isDERP && dstKey.Compare(selfNodeKey) == 0 {
		c.allocRelayEndpointPub.Publish(UDPRelayAllocReq{
			RxFromNodeKey:  selfNodeKey,
			RxFromDiscoKey: c.discoPublic,
			Message:        allocReq,
		})
		metricLocalDiscoAllocUDPRelayEndpointRequest.Add(1)
		return true, nil
	}
	return c.sendDiscoMessage(dst, dstKey, dstDisco, allocReq, logLevel)
}

// sendDiscoMessage sends discovery message m to dstDisco at dst.
//
// If dst.ap is a DERP IP:port, then dstKey must be non-zero.
//
// If dst.vni.isSet(), the [disco.Message] will be preceded by a Geneve header
// with the VNI field set to the value returned by vni.get().
//
// The dstKey should only be non-zero if the dstDisco key
// unambiguously maps to exactly one peer.
func (c *Conn) sendDiscoMessage(dst epAddr, dstKey key.NodePublic, dstDisco key.DiscoPublic, m disco.Message, logLevel discoLogLevel) (sent bool, err error) {
	isDERP := dst.ap.Addr() == tailcfg.DerpMagicIPAddr
	if _, isPong := m.(*disco.Pong); isPong && !isDERP && dst.ap.Addr().Is4() {
		time.Sleep(debugIPv4DiscoPingPenalty())
	}

	isRelayHandshakeMsg := false
	switch m.(type) {
	case *disco.BindUDPRelayEndpoint, *disco.BindUDPRelayEndpointAnswer:
		isRelayHandshakeMsg = true
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false, errConnClosed
	}
	var di *discoInfo
	switch {
	case isRelayHandshakeMsg:
		var ok bool
		di, ok = c.relayManager.discoInfo(dstDisco)
		if !ok {
			c.mu.Unlock()
			return false, errors.New("unknown relay server")
		}
	case c.peerMap.knownPeerDiscoKey(dstDisco):
		di = c.discoInfoForKnownPeerLocked(dstDisco)
	default:
		// This is an attempt to send to an unknown peer that is not a relay
		// server. This can happen when a call to the current function, which is
		// often via a new goroutine, races with applying a change in the
		// netmap, e.g. the associated peer(s) for dstDisco goes away.
		c.mu.Unlock()
		return false, errors.New("unknown peer")
	}
	c.mu.Unlock()

	pkt := make([]byte, 0, 512) // TODO: size it correctly? pool? if it matters.
	if dst.vni.IsSet() {
		gh := packet.GeneveHeader{
			Version:  0,
			Protocol: packet.GeneveProtocolDisco,
			VNI:      dst.vni,
			Control:  isRelayHandshakeMsg,
		}
		pkt = append(pkt, make([]byte, packet.GeneveFixedHeaderLength)...)
		err := gh.Encode(pkt)
		if err != nil {
			return false, err
		}
	}
	pkt = append(pkt, disco.Magic...)
	pkt = c.discoPublic.AppendTo(pkt)

	if isDERP {
		metricSendDiscoDERP.Add(1)
	} else {
		metricSendDiscoUDP.Add(1)
	}

	box := di.sharedKey.Seal(m.AppendMarshal(nil))
	pkt = append(pkt, box...)
	const isDisco = true
	sent, err = c.sendAddr(dst.ap, dstKey, pkt, isDisco, dst.vni.IsSet())
	if sent {
		if logLevel == discoLog || (logLevel == discoVerboseLog && debugDisco()) {
			node := "?"
			if !dstKey.IsZero() {
				node = dstKey.ShortString()
			}
			c.dlogf("[v1] magicsock: disco: %v->%v (%v, %v) sent %v len %v\n", c.discoShort, dstDisco.ShortString(), node, derpStr(dst.String()), disco.MessageSummary(m), len(pkt))
		}
		if isDERP {
			metricSentDiscoDERP.Add(1)
		} else {
			metricSentDiscoUDP.Add(1)
		}
		switch m.(type) {
		case *disco.Ping:
			metricSentDiscoPing.Add(1)
		case *disco.Pong:
			metricSentDiscoPong.Add(1)
		case *disco.CallMeMaybe:
			metricSentDiscoCallMeMaybe.Add(1)
		case *disco.CallMeMaybeVia:
			metricSentDiscoCallMeMaybeVia.Add(1)
		case *disco.BindUDPRelayEndpoint:
			metricSentDiscoBindUDPRelayEndpoint.Add(1)
		case *disco.BindUDPRelayEndpointAnswer:
			metricSentDiscoBindUDPRelayEndpointAnswer.Add(1)
		case *disco.AllocateUDPRelayEndpointRequest:
			metricSentDiscoAllocUDPRelayEndpointRequest.Add(1)
		case *disco.AllocateUDPRelayEndpointResponse:
			metricSentDiscoAllocUDPRelayEndpointResponse.Add(1)
		}
	} else if err == nil {
		// Can't send. (e.g. no IPv6 locally)
	} else {
		if !c.networkDown() && pmtuShouldLogDiscoTxErr(m, err) {
			c.logf("magicsock: disco: failed to send %v to %v %s: %v", disco.MessageSummary(m), dst, dstKey.ShortString(), err)
		}
	}
	return sent, err
}

type discoRXPath string

const (
	discoRXPathUDP       discoRXPath = "UDP socket"
	discoRXPathDERP      discoRXPath = "DERP"
	discoRXPathRawSocket discoRXPath = "raw socket"
)

const discoHeaderLen = len(disco.Magic) + key.DiscoPublicRawLen

type packetLooksLikeType int

const (
	packetLooksLikeWireGuard packetLooksLikeType = iota
	packetLooksLikeSTUNBinding
	packetLooksLikeDisco
)

// packetLooksLike reports a [packetsLooksLikeType] for 'msg', and whether
// 'msg' is encapsulated by a Geneve header (or naked).
//
// [packetLooksLikeSTUNBinding] is never Geneve-encapsulated.
//
// Naked STUN binding, Naked Disco, Geneve followed by Disco, naked WireGuard,
// and Geneve followed by WireGuard can be confidently distinguished based on
// the following:
//
//  1. STUN binding @ msg[1] (0x01) is sufficiently non-overlapping with the
//     Geneve header where the LSB is always 0 (part of 6 "reserved" bits).
//
//  2. STUN binding @ msg[1] (0x01) is sufficiently non-overlapping with naked
//     WireGuard, which is always a 0 byte value (WireGuard message type
//     occupies msg[0:4], and msg[1:4] are always 0).
//
//  3. STUN binding @ msg[1] (0x01) is sufficiently non-overlapping with the
//     second byte of [disco.Magic] (0x53).
//
//  4. [disco.Magic] @ msg[2:4] (0xf09f) is sufficiently non-overlapping with a
//     Geneve protocol field value of [packet.GeneveProtocolDisco] or
//     [packet.GeneveProtocolWireGuard] .
//
//  5. [disco.Magic] @ msg[0] (0x54) is sufficiently non-overlapping with the
//     first byte of a WireGuard packet (0x01-0x04).
//
//  6. [packet.GeneveHeader] with a Geneve protocol field value of
//     [packet.GeneveProtocolDisco] or [packet.GeneveProtocolWireGuard]
//     (msg[2:4]) is sufficiently non-overlapping with the second 2 bytes of a
//     WireGuard packet which are always 0x0000.
func packetLooksLike(msg []byte) (t packetLooksLikeType, isGeneveEncap bool) {
	if stun.Is(msg) &&
		msg[1] == 0x01 { // method binding
		return packetLooksLikeSTUNBinding, false
	}

	// TODO(jwhited): potentially collapse into disco.LooksLikeDiscoWrapper()
	//  if safe to do so.
	looksLikeDisco := func(msg []byte) bool {
		if len(msg) >= discoHeaderLen && string(msg[:len(disco.Magic)]) == disco.Magic {
			return true
		}
		return false
	}

	// Do we have a Geneve header?
	if len(msg) >= packet.GeneveFixedHeaderLength &&
		msg[0]&0xC0 == 0 && // version bits that we always transmit as 0s
		msg[1]&0x3F == 0 && // reserved bits that we always transmit as 0s
		msg[7] == 0 { // reserved byte that we always transmit as 0
		switch binary.BigEndian.Uint16(msg[2:4]) {
		case packet.GeneveProtocolDisco:
			if looksLikeDisco(msg[packet.GeneveFixedHeaderLength:]) {
				return packetLooksLikeDisco, true
			} else {
				// The Geneve header is well-formed, and it indicated this
				// was disco, but it's not. The evaluated bytes at this point
				// are always distinct from naked WireGuard (msg[2:4] are always
				// 0x0000) and naked Disco (msg[2:4] are always 0xf09f), but
				// maintain pre-Geneve behavior and fall back to assuming it's
				// naked WireGuard.
				return packetLooksLikeWireGuard, false
			}
		case packet.GeneveProtocolWireGuard:
			return packetLooksLikeWireGuard, true
		default:
			// The Geneve header is well-formed, but the protocol field value is
			// unknown to us. The evaluated bytes at this point are not
			// necessarily distinct from naked WireGuard or naked Disco, fall
			// through.
		}
	}

	if looksLikeDisco(msg) {
		return packetLooksLikeDisco, false
	} else {
		return packetLooksLikeWireGuard, false
	}
}

// handleDiscoMessage handles a discovery message. The caller is assumed to have
// verified 'msg' returns [packetLooksLikeDisco] from packetLooksLike().
//
// A discovery message has the form:
//
//   - magic             [6]byte
//   - senderDiscoPubKey [32]byte
//   - nonce             [24]byte
//   - naclbox of payload (see tailscale.com/disco package for inner payload format)
//
// For messages received over DERP, the src.ap.Addr() will be derpMagicIP (with
// src.ap.Port() being the region ID) and the derpNodeSrc will be the node key
// it was received from at the DERP layer. derpNodeSrc is zero when received
// over UDP.
//
// If 'msg' was encapsulated by a Geneve header it is assumed to have already
// been stripped.
//
// 'shouldBeRelayHandshakeMsg' will be true if 'msg' was encapsulated
// by a Geneve header with the control bit set.
func (c *Conn) handleDiscoMessage(msg []byte, src epAddr, shouldBeRelayHandshakeMsg bool, derpNodeSrc key.NodePublic, via discoRXPath) {
	sender := key.DiscoPublicFromRaw32(mem.B(msg[len(disco.Magic):discoHeaderLen]))

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	if debugDisco() {
		c.logf("magicsock: disco: got disco-looking frame from %v via %s len %v", sender.ShortString(), via, len(msg))
	}
	if c.privateKey.IsZero() {
		// Ignore disco messages when we're stopped.
		return
	}

	var di *discoInfo
	switch {
	case shouldBeRelayHandshakeMsg:
		var ok bool
		di, ok = c.relayManager.discoInfo(sender)
		if !ok {
			if debugDisco() {
				c.logf("magicsock: disco: ignoring disco-looking relay handshake frame, no active handshakes with key %v over %v", sender.ShortString(), src)
			}
			return
		}
	case c.peerMap.knownPeerDiscoKey(sender):
		di = c.discoInfoForKnownPeerLocked(sender)
	default:
		metricRecvDiscoBadPeer.Add(1)
		if debugDisco() {
			c.logf("magicsock: disco: ignoring disco-looking frame, don't know of key %v", sender.ShortString())
		}
		return
	}

	isDERP := src.ap.Addr() == tailcfg.DerpMagicIPAddr
	if !isDERP && !shouldBeRelayHandshakeMsg {
		// Record receive time for UDP transport packets.
		pi, ok := c.peerMap.byEpAddr[src]
		if ok {
			pi.ep.lastRecvUDPAny.StoreAtomic(mono.Now())
		}
	}

	// We're now reasonably sure we're expecting communication from 'sender',
	// do the heavy crypto lifting to see what they want.

	sealedBox := msg[discoHeaderLen:]
	payload, ok := di.sharedKey.Open(sealedBox)
	if !ok {
		// This might have been intended for a previous
		// disco key.  When we restart we get a new disco key
		// and old packets might've still been in flight (or
		// scheduled). This is particularly the case for LANs
		// or non-NATed endpoints. UDP offloading on Linux
		// can also cause this when a disco message is
		// received via raw socket at the head of a coalesced
		// group of messages. Don't log in normal case.
		// Callers may choose to pass on to wireguard, in case
		// it's actually a wireguard packet (super unlikely, but).
		if debugDisco() {
			c.logf("magicsock: disco: failed to open naclbox from %v (wrong rcpt?) via %s", sender, via)
		}
		metricRecvDiscoBadKey.Add(1)
		return
	}

	// Emit information about the disco frame into the pcap stream
	// if a capture hook is installed.
	if cb := c.captureHook.Load(); cb != nil {
		// TODO(jwhited): include VNI context?
		cb(packet.PathDisco, time.Now(), disco.ToPCAPFrame(src.ap, derpNodeSrc, payload), packet.CaptureMeta{})
	}

	dm, err := disco.Parse(payload)
	if debugDisco() {
		c.logf("magicsock: disco: disco.Parse = %T, %v", dm, err)
	}
	if err != nil {
		// Couldn't parse it, but it was inside a correctly
		// signed box, so just ignore it, assuming it's from a
		// newer version of Tailscale that we don't
		// understand. Not even worth logging about, lest it
		// be too spammy for old clients.
		metricRecvDiscoBadParse.Add(1)
		return
	}

	if isDERP {
		metricRecvDiscoDERP.Add(1)
	} else {
		metricRecvDiscoUDP.Add(1)
	}

	if shouldBeRelayHandshakeMsg {
		challenge, ok := dm.(*disco.BindUDPRelayEndpointChallenge)
		if !ok {
			// We successfully parsed the disco message, but it wasn't a
			// challenge. We should never receive other message types
			// from a relay server with the Geneve header control bit set.
			c.logf("[unexpected] %T packets should not come from a relay server with Geneve control bit set", dm)
			return
		}
		c.relayManager.handleRxDiscoMsg(c, challenge, key.NodePublic{}, di.discoKey, src)
		metricRecvDiscoBindUDPRelayEndpointChallenge.Add(1)
		return
	}

	switch dm := dm.(type) {
	case *disco.Ping:
		metricRecvDiscoPing.Add(1)
		c.handlePingLocked(dm, src, di, derpNodeSrc)
	case *disco.Pong:
		metricRecvDiscoPong.Add(1)
		// There might be multiple nodes for the sender's DiscoKey.
		// Ask each to handle it, stopping once one reports that
		// the Pong's TxID was theirs.
		knownTxID := false
		c.peerMap.forEachEndpointWithDiscoKey(sender, func(ep *endpoint) (keepGoing bool) {
			if ep.handlePongConnLocked(dm, di, src) {
				knownTxID = true
				return false
			}
			return true
		})
		if !knownTxID && src.vni.IsSet() {
			// If it's an unknown TxID, and it's Geneve-encapsulated, then
			// make [relayManager] aware. It might be in the middle of probing
			// src.
			c.relayManager.handleRxDiscoMsg(c, dm, key.NodePublic{}, di.discoKey, src)
		}
	case *disco.CallMeMaybe, *disco.CallMeMaybeVia:
		var via *disco.CallMeMaybeVia
		isVia := false
		msgType := "CallMeMaybe"
		cmm, ok := dm.(*disco.CallMeMaybe)
		if ok {
			metricRecvDiscoCallMeMaybe.Add(1)
		} else {
			metricRecvDiscoCallMeMaybeVia.Add(1)
			via = dm.(*disco.CallMeMaybeVia)
			msgType = "CallMeMaybeVia"
			isVia = true
		}

		if !isDERP || derpNodeSrc.IsZero() {
			// CallMeMaybe{Via} messages should only come via DERP.
			c.logf("[unexpected] %s packets should only come via DERP", msgType)
			return
		}
		nodeKey := derpNodeSrc
		ep, ok := c.peerMap.endpointForNodeKey(nodeKey)
		if !ok {
			if isVia {
				metricRecvDiscoCallMeMaybeViaBadNode.Add(1)
			} else {
				metricRecvDiscoCallMeMaybeBadNode.Add(1)
			}
			c.logf("magicsock: disco: ignoring %s from %v; %v is unknown", msgType, sender.ShortString(), derpNodeSrc.ShortString())
			return
		}
		// If the "disable-relay-client" node attr is set for this node, it
		// can't be a UDP relay client, so drop any CallMeMaybeVia messages it
		// receives.
		if isVia && !c.relayClientEnabled {
			c.logf("magicsock: disco: ignoring %s from %v; disable-relay-client node attr is set", msgType, sender.ShortString())
			return
		}

		ep.mu.Lock()
		relayCapable := ep.relayCapable
		lastBest := ep.bestAddr
		lastBestIsTrusted := mono.Now().Before(ep.trustBestAddrUntil)
		ep.mu.Unlock()
		if isVia && !relayCapable {
			c.logf("magicsock: disco: ignoring %s from %v; %v is not known to be relay capable", msgType, sender.ShortString(), sender.ShortString())
			return
		}
		epDisco := ep.disco.Load()
		if epDisco == nil {
			return
		}
		if epDisco.key != di.discoKey {
			if isVia {
				metricRecvDiscoCallMeMaybeViaBadDisco.Add(1)
			} else {
				metricRecvDiscoCallMeMaybeBadDisco.Add(1)
			}
			c.logf("[unexpected] %s from peer via DERP whose netmap discokey != disco source", msgType)
			return
		}
		if isVia {
			c.dlogf("[v1] magicsock: disco: %v<-%v via %v (%v, %v)  got call-me-maybe-via, %d endpoints",
				c.discoShort, epDisco.short, via.ServerDisco.ShortString(),
				ep.publicKey.ShortString(), derpStr(src.String()),
				len(via.AddrPorts))
			c.relayManager.handleCallMeMaybeVia(ep, lastBest, lastBestIsTrusted, via)
		} else {
			c.dlogf("[v1] magicsock: disco: %v<-%v (%v, %v)  got call-me-maybe, %d endpoints",
				c.discoShort, epDisco.short,
				ep.publicKey.ShortString(), derpStr(src.String()),
				len(cmm.MyNumber))
			go ep.handleCallMeMaybe(cmm)
		}
	case *disco.AllocateUDPRelayEndpointRequest, *disco.AllocateUDPRelayEndpointResponse:
		var resp *disco.AllocateUDPRelayEndpointResponse
		isResp := false
		msgType := "AllocateUDPRelayEndpointRequest"
		req, ok := dm.(*disco.AllocateUDPRelayEndpointRequest)
		if ok {
			metricRecvDiscoAllocUDPRelayEndpointRequest.Add(1)
		} else {
			metricRecvDiscoAllocUDPRelayEndpointResponse.Add(1)
			resp = dm.(*disco.AllocateUDPRelayEndpointResponse)
			msgType = "AllocateUDPRelayEndpointResponse"
			isResp = true
		}

		if !isDERP {
			// These messages should only come via DERP.
			c.logf("[unexpected] %s packets should only come via DERP", msgType)
			return
		}
		nodeKey := derpNodeSrc
		ep, ok := c.peerMap.endpointForNodeKey(nodeKey)
		if !ok {
			c.logf("magicsock: disco: ignoring %s from %v; %v is unknown", msgType, sender.ShortString(), derpNodeSrc.ShortString())
			return
		}
		epDisco := ep.disco.Load()
		if epDisco == nil {
			return
		}
		if epDisco.key != di.discoKey {
			if isResp {
				metricRecvDiscoAllocUDPRelayEndpointResponseBadDisco.Add(1)
			} else {
				metricRecvDiscoAllocUDPRelayEndpointRequestBadDisco.Add(1)
			}
			c.logf("[unexpected] %s from peer via DERP whose netmap discokey != disco source", msgType)
			return
		}

		if isResp {
			c.dlogf("[v1] magicsock: disco: %v<-%v (%v, %v) got %s, %d endpoints",
				c.discoShort, epDisco.short,
				ep.publicKey.ShortString(), derpStr(src.String()),
				msgType,
				len(resp.AddrPorts))
			c.relayManager.handleRxDiscoMsg(c, resp, nodeKey, di.discoKey, src)
			return
		} else if sender.Compare(req.ClientDisco[0]) != 0 && sender.Compare(req.ClientDisco[1]) != 0 {
			// An allocation request must contain the sender's disco key in
			// ClientDisco. One of the relay participants must be the sender.
			c.logf("magicsock: disco: %s from %v; %v does not contain sender's disco key",
				msgType, sender.ShortString(), derpNodeSrc.ShortString())
			return
		} else {
			c.dlogf("[v1] magicsock: disco: %v<-%v (%v, %v) got %s disco[0]=%v disco[1]=%v",
				c.discoShort, epDisco.short,
				ep.publicKey.ShortString(), derpStr(src.String()),
				msgType,
				req.ClientDisco[0].ShortString(), req.ClientDisco[1].ShortString())
		}

		if c.filt == nil {
			return
		}
		// Binary search of peers is O(log n) while c.mu is held.
		// TODO: We might be able to use ep.nodeAddr instead of all addresses,
		//  or we might be able to release c.mu before doing this work. Keep it
		//  simple and slow for now. c.peers.AsSlice is a copy. We may need to
		//  write our own binary search for a [views.Slice].
		peerI, ok := slices.BinarySearchFunc(c.peers.AsSlice(), ep.nodeID, func(peer tailcfg.NodeView, target tailcfg.NodeID) int {
			if peer.ID() < target {
				return -1
			} else if peer.ID() > target {
				return 1
			}
			return 0
		})
		if !ok {
			// unexpected
			return
		}
		if !nodeHasCap(c.filt, c.peers.At(peerI), c.self, tailcfg.PeerCapabilityRelay) {
			return
		}
		c.allocRelayEndpointPub.Publish(UDPRelayAllocReq{
			RxFromDiscoKey: sender,
			RxFromNodeKey:  nodeKey,
			Message:        req,
		})
	}
	return
}

// unambiguousNodeKeyOfPingLocked attempts to look up an unambiguous mapping
// from a DiscoKey dk (which sent ping dm) to a NodeKey. ok is true
// if there's the NodeKey is known unambiguously.
//
// derpNodeSrc is non-zero if the disco ping arrived via DERP.
//
// c.mu must be held.
func (c *Conn) unambiguousNodeKeyOfPingLocked(dm *disco.Ping, dk key.DiscoPublic, derpNodeSrc key.NodePublic) (nk key.NodePublic, ok bool) {
	if !derpNodeSrc.IsZero() {
		if ep, ok := c.peerMap.endpointForNodeKey(derpNodeSrc); ok {
			epDisco := ep.disco.Load()
			if epDisco != nil && epDisco.key == dk {
				return derpNodeSrc, true
			}
		}
	}

	// Pings after 1.16.0 contains its node source. See if it maps back.
	if !dm.NodeKey.IsZero() {
		if ep, ok := c.peerMap.endpointForNodeKey(dm.NodeKey); ok {
			epDisco := ep.disco.Load()
			if epDisco != nil && epDisco.key == dk {
				return dm.NodeKey, true
			}
		}
	}

	// If there's exactly 1 node in our netmap with DiscoKey dk,
	// then it's not ambiguous which node key dm was from.
	if set := c.peerMap.nodesOfDisco[dk]; len(set) == 1 {
		for nk = range set {
			return nk, true
		}
	}

	return nk, false
}

// di is the discoInfo of the source of the ping.
// derpNodeSrc is non-zero if the ping arrived via DERP.
func (c *Conn) handlePingLocked(dm *disco.Ping, src epAddr, di *discoInfo, derpNodeSrc key.NodePublic) {
	likelyHeartBeat := src == di.lastPingFrom && time.Since(di.lastPingTime) < 5*time.Second
	di.lastPingFrom = src
	di.lastPingTime = time.Now()
	isDerp := src.ap.Addr() == tailcfg.DerpMagicIPAddr

	if src.vni.IsSet() {
		if isDerp {
			c.logf("[unexpected] got Geneve-encapsulated disco ping from %v/%v over DERP", src, derpNodeSrc)
			return
		}

		// [relayManager] is always responsible for handling (replying) to
		// Geneve-encapsulated [disco.Ping] messages in the interest of
		// simplicity. It might be in the middle of probing src, so it must be
		// made aware.
		c.relayManager.handleRxDiscoMsg(c, dm, key.NodePublic{}, di.discoKey, src)
		return
	}

	// This is a naked [disco.Ping] without a VNI.

	// If we can figure out with certainty which node key this disco
	// message is for, eagerly update our [epAddr]<>node and disco<>node
	// mappings to make p2p path discovery faster in simple
	// cases. Without this, disco would still work, but would be
	// reliant on DERP call-me-maybe to establish the disco<>node
	// mapping, and on subsequent disco handlePongConnLocked to establish
	// the IP:port<>disco mapping.
	if nk, ok := c.unambiguousNodeKeyOfPingLocked(dm, di.discoKey, derpNodeSrc); ok {
		if !isDerp {
			c.peerMap.setNodeKeyForEpAddr(src, nk)
		}
	}

	// numNodes tracks how many nodes (node keys) are associated with the disco
	// key tied to this inbound ping. Multiple nodes may share the same disco
	// key in the case of node sharing and users switching accounts.
	var numNodes int
	// If we got a ping over DERP, then derpNodeSrc is non-zero and we reply
	// over DERP (in which case ipDst is also a DERP address).
	// But if the ping was over UDP (ipDst is not a DERP address), then dstKey
	// will be zero here, but that's fine: sendDiscoMessage only requires
	// a dstKey if the dst ip:port is DERP.
	dstKey := derpNodeSrc

	// Remember this route if not present.
	var dup bool
	if isDerp {
		if _, ok := c.peerMap.endpointForNodeKey(derpNodeSrc); ok {
			numNodes = 1
		}
	} else {
		c.peerMap.forEachEndpointWithDiscoKey(di.discoKey, func(ep *endpoint) (keepGoing bool) {
			if ep.addCandidateEndpoint(src.ap, dm.TxID) {
				dup = true
				return false
			}
			numNodes++
			if numNodes == 1 && dstKey.IsZero() {
				dstKey = ep.publicKey
			}
			return true
		})
		if dup {
			return
		}
		if numNodes > 1 {
			// Zero it out if it's ambiguous, so sendDiscoMessage logging
			// isn't confusing.
			dstKey = key.NodePublic{}
		}
	}

	if numNodes == 0 {
		c.logf("[unexpected] got disco ping from %v/%v for node not in peers", src, derpNodeSrc)
		return
	}

	if !likelyHeartBeat || debugDisco() {
		pingNodeSrcStr := dstKey.ShortString()
		if numNodes > 1 {
			pingNodeSrcStr = "[one-of-multi]"
		}
		c.dlogf("[v1] magicsock: disco: %v<-%v (%v, %v)  got ping tx=%x padding=%v", c.discoShort, di.discoShort, pingNodeSrcStr, src, dm.TxID[:6], dm.Padding)
	}

	ipDst := src
	discoDest := di.discoKey
	go c.sendDiscoMessage(ipDst, dstKey, discoDest, &disco.Pong{
		TxID: dm.TxID,
		Src:  src.ap,
	}, discoVerboseLog)
}

// enqueueCallMeMaybe schedules a send of disco.CallMeMaybe to de via derpAddr
// once we know that our STUN endpoint is fresh.
//
// derpAddr is de.derpAddr at the time of send. It's assumed the peer won't be
// flipping primary DERPs in the 0-30ms it takes to confirm our STUN endpoint.
// If they do, traffic will just go over DERP for a bit longer until the next
// discovery round.
func (c *Conn) enqueueCallMeMaybe(derpAddr netip.AddrPort, de *endpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()

	epDisco := de.disco.Load()
	if epDisco == nil {
		return
	}

	if !c.lastEndpointsTime.After(time.Now().Add(-endpointsFreshEnoughDuration)) {
		c.dlogf("[v1] magicsock: want call-me-maybe but endpoints stale; restunning")

		mak.Set(&c.onEndpointRefreshed, de, func() {
			c.dlogf("[v1] magicsock: STUN done; sending call-me-maybe to %v %v", epDisco.short, de.publicKey.ShortString())
			c.enqueueCallMeMaybe(derpAddr, de)
		})
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

	eps := make([]netip.AddrPort, 0, len(c.lastEndpoints))
	for _, ep := range c.lastEndpoints {
		eps = append(eps, ep.Addr)
	}
	go de.c.sendDiscoMessage(epAddr{ap: derpAddr}, de.publicKey, epDisco.key, &disco.CallMeMaybe{MyNumber: eps}, discoLog)
	if debugSendCallMeUnknownPeer() {
		// Send a callMeMaybe packet to a non-existent peer
		unknownKey := key.NewNode().Public()
		c.logf("magicsock: sending CallMeMaybe to unknown peer per TS_DEBUG_SEND_CALLME_UNKNOWN_PEER")
		go de.c.sendDiscoMessage(epAddr{ap: derpAddr}, unknownKey, epDisco.key, &disco.CallMeMaybe{MyNumber: eps}, discoLog)
	}
}

// discoInfoForKnownPeerLocked returns the previous or new discoInfo for k.
//
// Callers must only pass key.DiscoPublic's that are present in and
// lifetime-managed via [Conn].peerMap. UDP relay server disco keys are discovered
// at relay endpoint allocation time or [disco.CallMeMaybeVia] reception time
// and therefore must never pass through this method.
//
// c.mu must be held.
func (c *Conn) discoInfoForKnownPeerLocked(k key.DiscoPublic) *discoInfo {
	di, ok := c.discoInfo[k]
	if !ok {
		di = &discoInfo{
			discoKey:   k,
			discoShort: k.ShortString(),
			sharedKey:  c.discoPrivate.Shared(k),
		}
		c.discoInfo[k] = di
	}
	return di
}

func (c *Conn) SetNetworkUp(up bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.networkUp.Load() == up {
		return
	}

	c.logf("magicsock: SetNetworkUp(%v)", up)
	c.networkUp.Store(up)

	if up {
		c.startDerpHomeConnectLocked()
	} else {
		if c.portMapper != nil {
			c.portMapper.NoteNetworkDown()
		}
		c.closeAllDerpLocked("network-down")
	}
}

// SetPreferredPort sets the connection's preferred local port.
func (c *Conn) SetPreferredPort(port uint16) {
	if uint16(c.port.Load()) == port {
		return
	}
	c.port.Store(uint32(port))

	if err := c.rebind(dropCurrentPort); err != nil {
		c.logf("%v", err)
		return
	}
	c.resetEndpointStates()
}

// SetPrivateKey sets the connection's private key.
//
// This is only used to be able prove our identity when connecting to
// DERP servers.
//
// If the private key changes, any DERP connections are torn down &
// recreated when needed.
func (c *Conn) SetPrivateKey(privateKey key.NodePrivate) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldKey, newKey := c.privateKey, privateKey
	if newKey.Equal(oldKey) {
		return nil
	}
	c.privateKey = newKey
	c.havePrivateKey.Store(!newKey.IsZero())

	if newKey.IsZero() {
		c.publicKeyAtomic.Store(key.NodePublic{})
	} else {
		c.publicKeyAtomic.Store(newKey.Public())
	}

	if oldKey.IsZero() {
		c.everHadKey = true
		c.logf("magicsock: SetPrivateKey called (init)")
		go c.ReSTUN("set-private-key")
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
		c.peerMap.forEachEndpoint(func(ep *endpoint) {
			ep.stopAndReset()
		})
	}

	return nil
}

// UpdatePeers is called when the set of WireGuard peers changes. It
// then removes any state for old peers.
//
// The caller passes ownership of newPeers map to UpdatePeers.
func (c *Conn) UpdatePeers(newPeers set.Set[key.NodePublic]) {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldPeers := c.peerSet
	c.peerSet = newPeers

	// Clean up any key.NodePublic-keyed maps for peers that no longer
	// exist.
	for peer := range oldPeers {
		if !newPeers.Contains(peer) {
			delete(c.derpRoute, peer)
			delete(c.peerLastDerp, peer)
		}
	}

	if len(oldPeers) == 0 && len(newPeers) > 0 {
		go c.ReSTUN("non-zero-peers")
	}
}

func nodesEqual(x, y views.Slice[tailcfg.NodeView]) bool {
	if x.Len() != y.Len() {
		return false
	}
	for i := range x.Len() {
		if !x.At(i).Equal(y.At(i)) {
			return false
		}
	}
	return true
}

// debugRingBufferSize returns a maximum size for our set of endpoint ring
// buffers by assuming that a single large update is ~500 bytes, and that we
// want to not use more than 1MiB of memory on phones / 4MiB on other devices.
// Calculate the per-endpoint ring buffer size by dividing that out, but always
// storing at least two entries.
func debugRingBufferSize(numPeers int) int {
	const defaultVal = 2
	if numPeers == 0 {
		return defaultVal
	}
	var maxRingBufferSize int
	if runtime.GOOS == "ios" || runtime.GOOS == "android" {
		maxRingBufferSize = 1 << 20
		// But as of 2024-03-20, we now just disable the ring buffer entirely
		// on mobile as it hadn't proven useful enough to justify even 1 MB.
	} else {
		maxRingBufferSize = 4 << 20
	}
	if v := debugRingBufferMaxSizeBytes(); v > 0 {
		maxRingBufferSize = v
	}

	const averageRingBufferElemSize = 512
	return max(defaultVal, maxRingBufferSize/(averageRingBufferElemSize*numPeers))
}

// debugFlags are the debug flags in use by the magicsock package.
// They might be set by envknob and/or controlknob.
// The value is comparable.
type debugFlags struct {
	heartbeatDisabled  bool
	probeUDPLifetimeOn bool
}

func (c *Conn) debugFlagsLocked() (f debugFlags) {
	f.heartbeatDisabled = debugEnableSilentDisco() || c.silentDiscoOn.Load()
	f.probeUDPLifetimeOn = c.probeUDPLifetimeOn.Load()
	return
}

// SetSilentDisco toggles silent disco based on v.
func (c *Conn) SetSilentDisco(v bool) {
	old := c.silentDiscoOn.Swap(v)
	if old == v {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerMap.forEachEndpoint(func(ep *endpoint) {
		ep.setHeartbeatDisabled(v)
	})
}

// SilentDisco returns true if silent disco is enabled, otherwise false.
func (c *Conn) SilentDisco() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	flags := c.debugFlagsLocked()
	return flags.heartbeatDisabled
}

// SetProbeUDPLifetime toggles probing of UDP lifetime based on v.
func (c *Conn) SetProbeUDPLifetime(v bool) {
	old := c.probeUDPLifetimeOn.Swap(v)
	if old == v {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerMap.forEachEndpoint(func(ep *endpoint) {
		ep.setProbeUDPLifetimeOn(v)
	})
}

// capVerIsRelayCapable returns true if version is relay client and server
// capable, otherwise it returns false.
func capVerIsRelayCapable(version tailcfg.CapabilityVersion) bool {
	return version >= 121
}

// onFilterUpdate is called when a [FilterUpdate] is received over the
// [eventbus.Bus].
func (c *Conn) onFilterUpdate(f FilterUpdate) {
	c.mu.Lock()
	c.filt = f.Filter
	self := c.self
	peers := c.peers
	relayClientEnabled := c.relayClientEnabled
	c.mu.Unlock() // release c.mu before potentially calling c.updateRelayServersSet which is O(m * n)

	if !relayClientEnabled {
		// Early return if we cannot operate as a relay client.
		return
	}

	// The filter has changed, and we are operating as a relay server client.
	// Re-evaluate it in order to produce an updated relay server set.
	c.updateRelayServersSet(f.Filter, self, peers)
}

// updateRelayServersSet iterates all peers and self, evaluating filt for each
// one in order to determine which are relay server candidates. filt, self, and
// peers are passed as args (vs c.mu-guarded fields) to enable callers to
// release c.mu before calling as this is O(m * n) (we iterate all cap rules 'm'
// in filt for every peer 'n').
//
// Calls to updateRelayServersSet must never run concurrent to
// [endpoint.setDERPHome], otherwise [candidatePeerRelay] DERP home changes may
// be missed from the perspective of [relayManager].
//
// TODO: Optimize this so that it's not O(m * n). This might involve:
//  1. Changes to [filter.Filter], e.g. adding a CapsWithValues() to check for
//     a given capability instead of building and returning a map of all of
//     them.
//  2. Moving this work upstream into [nodeBackend] or similar, and publishing
//     the computed result over the eventbus instead.
func (c *Conn) updateRelayServersSet(filt *filter.Filter, self tailcfg.NodeView, peers views.Slice[tailcfg.NodeView]) {
	relayServers := make(set.Set[candidatePeerRelay])
	nodes := append(peers.AsSlice(), self)
	for _, maybeCandidate := range nodes {
		if maybeCandidate.ID() != self.ID() && !capVerIsRelayCapable(maybeCandidate.Cap()) {
			// If maybeCandidate's [tailcfg.CapabilityVersion] is not relay-capable,
			// we skip it. If maybeCandidate happens to be self, then this check is
			// unnecessary as self is always capable from this point (the statically
			// compiled [tailcfg.CurrentCapabilityVersion]) forward.
			continue
		}
		if !nodeHasCap(filt, maybeCandidate, self, tailcfg.PeerCapabilityRelayTarget) {
			continue
		}
		relayServers.Add(candidatePeerRelay{
			nodeKey:          maybeCandidate.Key(),
			discoKey:         maybeCandidate.DiscoKey(),
			derpHomeRegionID: uint16(maybeCandidate.HomeDERP()),
		})
	}
	c.relayManager.handleRelayServersSet(relayServers)
	if len(relayServers) > 0 {
		c.hasPeerRelayServers.Store(true)
	} else {
		c.hasPeerRelayServers.Store(false)
	}
}

// nodeHasCap returns true if src has cap on dst, otherwise it returns false.
func nodeHasCap(filt *filter.Filter, src, dst tailcfg.NodeView, cap tailcfg.PeerCapability) bool {
	if filt == nil ||
		!src.Valid() ||
		!dst.Valid() {
		return false
	}
	for _, srcPrefix := range src.Addresses().All() {
		if !srcPrefix.IsSingleIP() {
			continue
		}
		srcAddr := srcPrefix.Addr()
		for _, dstPrefix := range dst.Addresses().All() {
			if !dstPrefix.IsSingleIP() {
				continue
			}
			dstAddr := dstPrefix.Addr()
			if dstAddr.BitLen() == srcAddr.BitLen() { // same address family
				// [nodeBackend.peerCapsLocked] only returns/considers the
				// [tailcfg.PeerCapMap] between the passed src and the _first_
				// host (/32 or /128) address for self. We are consistent with
				// that behavior here. If src and dst host addresses are of the
				// same address family they either have the capability or not.
				// We do not check against additional host addresses of the same
				// address family.
				return filt.CapsWithValues(srcAddr, dstAddr).HasCapability(cap)
			}
		}
	}
	return false
}

// candidatePeerRelay represents the identifiers and DERP home region ID for a
// peer relay server.
type candidatePeerRelay struct {
	nodeKey          key.NodePublic
	discoKey         key.DiscoPublic
	derpHomeRegionID uint16
}

func (c *candidatePeerRelay) isValid() bool {
	return !c.nodeKey.IsZero() && !c.discoKey.IsZero()
}

// onNodeViewsUpdate is called when a [NodeViewsUpdate] is received over the
// [eventbus.Bus].
func (c *Conn) onNodeViewsUpdate(update NodeViewsUpdate) {
	peersChanged := c.updateNodes(update)

	relayClientEnabled := update.SelfNode.Valid() &&
		!update.SelfNode.HasCap(tailcfg.NodeAttrDisableRelayClient) &&
		!update.SelfNode.HasCap(tailcfg.NodeAttrOnlyTCP443)

	c.mu.Lock()
	relayClientChanged := c.relayClientEnabled != relayClientEnabled
	c.relayClientEnabled = relayClientEnabled
	filt := c.filt
	self := c.self
	peers := c.peers
	isClosed := c.closed
	c.mu.Unlock() // release c.mu before potentially calling c.updateRelayServersSet which is O(m * n)

	if isClosed {
		return // nothing to do here, the conn is closed and the update is no longer relevant
	}

	if peersChanged || relayClientChanged {
		if !relayClientEnabled {
			c.relayManager.handleRelayServersSet(nil)
			c.hasPeerRelayServers.Store(false)
		} else {
			c.updateRelayServersSet(filt, self, peers)
		}
	}
}

// updateNodes updates [Conn] to reflect the [tailcfg.NodeView]'s contained
// in update. It returns true if update.Peers was unequal to c.peers, otherwise
// false.
func (c *Conn) updateNodes(update NodeViewsUpdate) (peersChanged bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return false
	}

	priorPeers := c.peers
	metricNumPeers.Set(int64(len(update.Peers)))

	// Update c.self & c.peers regardless, before the following early return.
	c.self = update.SelfNode
	curPeers := views.SliceOf(update.Peers)
	c.peers = curPeers

	// [debugFlags] are mutable in [Conn.SetSilentDisco] &
	// [Conn.SetProbeUDPLifetime]. These setters are passed [controlknobs.Knobs]
	// values by [ipnlocal.LocalBackend] around netmap reception.
	// [controlknobs.Knobs] are simply self [tailcfg.NodeCapability]'s. They are
	// useful as a global view of notable feature toggles, but the magicsock
	// setters are completely unnecessary as we have the same values right here
	// (update.SelfNode.Capabilities) at a time they are considered most
	// up-to-date.
	// TODO: mutate [debugFlags] here instead of in various [Conn] setters.
	flags := c.debugFlagsLocked()

	peersChanged = !nodesEqual(priorPeers, curPeers)
	if !peersChanged && c.lastFlags == flags {
		// The rest of this function is all adjusting state for peers that have
		// changed. But if the set of peers is equal and the debug flags (for
		// silent disco and probe UDP lifetime) haven't changed, there is no
		// need to do anything else.
		return
	}

	c.lastFlags = flags

	c.logf("[v1] magicsock: got updated network map; %d peers", len(update.Peers))

	entriesPerBuffer := debugRingBufferSize(len(update.Peers))

	// Try a pass of just upserting nodes and creating missing
	// endpoints. If the set of nodes is the same, this is an
	// efficient alloc-free update. If the set of nodes is different,
	// we'll fall through to the next pass, which allocates but can
	// handle full set updates.
	for _, n := range update.Peers {
		if n.ID() == 0 {
			devPanicf("node with zero ID")
			continue
		}
		if n.Key().IsZero() {
			devPanicf("node with zero key")
			continue
		}
		ep, ok := c.peerMap.endpointForNodeID(n.ID())
		if ok && ep.publicKey != n.Key() {
			// The node rotated public keys. Delete the old endpoint and create
			// it anew.
			c.peerMap.deleteEndpoint(ep)
			ok = false
		}
		if ok {
			// At this point we're modifying an existing endpoint (ep) whose
			// public key and nodeID match n. Its other fields (such as disco
			// key or endpoints) might've changed.

			if n.DiscoKey().IsZero() && !n.IsWireGuardOnly() {
				// Discokey transitioned from non-zero to zero? This should not
				// happen in the wild, however it could mean:
				// 1. A node was downgraded from post 0.100 to pre 0.100.
				// 2. A Tailscale node key was extracted and used on a
				//    non-Tailscale node (should not enter here due to the
				//    IsWireGuardOnly check)
				// 3. The server is misbehaving.
				c.peerMap.deleteEndpoint(ep)
				continue
			}
			var oldDiscoKey key.DiscoPublic
			if epDisco := ep.disco.Load(); epDisco != nil {
				oldDiscoKey = epDisco.key
			}
			ep.updateFromNode(n, flags.heartbeatDisabled, flags.probeUDPLifetimeOn)
			c.peerMap.upsertEndpoint(ep, oldDiscoKey) // maybe update discokey mappings in peerMap
			continue
		}

		if ep, ok := c.peerMap.endpointForNodeKey(n.Key()); ok {
			// At this point n.Key() should be for a key we've never seen before. If
			// ok was true above, it was an update to an existing matching key and
			// we don't get this far. If ok was false above, that means it's a key
			// that differs from the one the NodeID had. But double check.
			if ep.nodeID != n.ID() {
				// Server error.
				devPanicf("public key moved between nodeIDs (old=%v new=%v, key=%s)", ep.nodeID, n.ID(), n.Key().String())
			} else {
				// Internal data structures out of sync.
				devPanicf("public key found in peerMap but not by nodeID")
			}
			continue
		}
		if n.DiscoKey().IsZero() && !n.IsWireGuardOnly() {
			// Ancient pre-0.100 node, which does not have a disco key.
			// No longer supported.
			continue
		}

		ep = &endpoint{
			c:                 c,
			nodeID:            n.ID(),
			publicKey:         n.Key(),
			publicKeyHex:      n.Key().UntypedHexString(),
			sentPing:          map[stun.TxID]sentPing{},
			endpointState:     map[netip.AddrPort]*endpointState{},
			heartbeatDisabled: flags.heartbeatDisabled,
			isWireguardOnly:   n.IsWireGuardOnly(),
		}
		switch runtime.GOOS {
		case "ios", "android":
			// Omit, to save memory. Prior to 2024-03-20 we used to limit it to
			// ~1MB on mobile but we never used the data so the memory was just
			// wasted.
		default:
			ep.debugUpdates = ringlog.New[EndpointChange](entriesPerBuffer)
		}
		if n.Addresses().Len() > 0 {
			ep.nodeAddr = n.Addresses().At(0).Addr()
		}
		ep.initFakeUDPAddr()
		if n.DiscoKey().IsZero() {
			ep.disco.Store(nil)
		} else {
			ep.disco.Store(&endpointDisco{
				key:   n.DiscoKey(),
				short: n.DiscoKey().ShortString(),
			})
		}

		if debugPeerMap() {
			c.logEndpointCreated(n)
		}

		ep.updateFromNode(n, flags.heartbeatDisabled, flags.probeUDPLifetimeOn)
		c.peerMap.upsertEndpoint(ep, key.DiscoPublic{})
	}

	// If the set of nodes changed since the last onNodeViewsUpdate, the
	// upsert loop just above made c.peerMap contain the union of the
	// old and new peers - which will be larger than the set from the
	// current netmap. If that happens, go through the allocful
	// deletion path to clean up moribund nodes.
	if c.peerMap.nodeCount() != len(update.Peers) {
		keep := set.Set[key.NodePublic]{}
		for _, n := range update.Peers {
			keep.Add(n.Key())
		}
		c.peerMap.forEachEndpoint(func(ep *endpoint) {
			if !keep.Contains(ep.publicKey) {
				c.peerMap.deleteEndpoint(ep)
			}
		})
	}

	// discokeys might have changed in the above. Discard unused info.
	for dk := range c.discoInfo {
		if !c.peerMap.knownPeerDiscoKey(dk) {
			delete(c.discoInfo, dk)
		}
	}

	return peersChanged
}

func devPanicf(format string, a ...any) {
	if testenv.InTest() || envknob.CrashOnUnexpected() {
		panic(fmt.Sprintf(format, a...))
	}
}

func (c *Conn) logEndpointCreated(n tailcfg.NodeView) {
	c.logf("magicsock: created endpoint key=%s: disco=%s; %v", n.Key().ShortString(), n.DiscoKey().ShortString(), logger.ArgWriter(func(w *bufio.Writer) {
		if regionID := n.HomeDERP(); regionID != 0 {
			code := c.derpRegionCodeLocked(regionID)
			if code != "" {
				code = "(" + code + ")"
			}
			fmt.Fprintf(w, "derp=%v%s ", regionID, code)
		}

		for _, a := range n.AllowedIPs().All() {
			if a.IsSingleIP() {
				fmt.Fprintf(w, "aip=%v ", a.Addr())
			} else {
				fmt.Fprintf(w, "aip=%v ", a)
			}
		}
		for _, ep := range n.Endpoints().All() {
			fmt.Fprintf(w, "ep=%v ", ep)
		}
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

// Bind returns the wireguard-go conn.Bind for c.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind
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

// This is a compile-time assertion that connBind implements the wireguard-go
// conn.Bind interface.
var _ conn.Bind = (*connBind)(nil)

// BatchSize returns the number of buffers expected to be passed to
// the ReceiveFuncs, and the maximum expected to be passed to SendBatch.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind.BatchSize
func (c *connBind) BatchSize() int {
	// TODO(raggi): determine by properties rather than hardcoding platform behavior
	switch runtime.GOOS {
	case "linux":
		return conn.IdealBatchSize
	default:
		return 1
	}
}

// Open is called by WireGuard to create a UDP binding.
// The ignoredPort comes from wireguard-go, via the wgcfg config.
// We ignore that port value here, since we have the local port available easily.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind.Open
func (c *connBind) Open(ignoredPort uint16) ([]conn.ReceiveFunc, uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		return nil, 0, errors.New("magicsock: connBind already open")
	}
	c.closed = false
	fns := []conn.ReceiveFunc{c.receiveIPv4(), c.receiveIPv6(), c.receiveDERP}
	if runtime.GOOS == "js" {
		fns = []conn.ReceiveFunc{c.receiveDERP}
	}
	// TODO: Combine receiveIPv4 and receiveIPv6 and receiveIP into a single
	// closure that closes over a *RebindingUDPConn?
	return fns, c.LocalPort(), nil
}

// SetMark is used by wireguard-go to set a mark bit for packets to avoid routing loops.
// We handle that ourselves elsewhere.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind.SetMark
func (c *connBind) SetMark(value uint32) error {
	return nil
}

// Close closes the connBind, unless it is already closed.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind.Close
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
	if c.closeDisco4 != nil {
		c.closeDisco4.Close()
	}
	if c.closeDisco6 != nil {
		c.closeDisco6.Close()
	}
	// Send an empty read result to unblock receiveDERP,
	// which will then check connBind.Closed.
	// connBind.Closed takes c.mu, but c.derpRecvCh is buffered.
	c.derpRecvCh <- derpReadResult{}
	return nil
}

// isClosed reports whether c is closed.
func (c *connBind) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Close closes the connection.
//
// Only the first close does anything. Any later closes return nil.
func (c *Conn) Close() error {
	// Close the [eventbus.Client] to wait for subscribers to
	// return before acquiring c.mu:
	//  1. Event handlers also acquire c.mu, they can deadlock with c.Close().
	//  2. Event handlers may not guard against undesirable post/in-progress
	//     Conn.Close() behaviors.
	c.eventClient.Close()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closing.Store(true)
	if c.derpCleanupTimerArmed {
		c.derpCleanupTimer.Stop()
	}
	c.stopPeriodicReSTUNTimerLocked()
	if c.portMapper != nil {
		c.portMapper.Close()
	}

	c.peerMap.forEachEndpoint(func(ep *endpoint) {
		ep.stopAndReset()
	})

	c.closed = true
	c.connCtxCancel()
	c.closeAllDerpLocked("conn-close")
	// Ignore errors from c.pconnN.Close.
	// They will frequently have been closed already by a call to connBind.Close.
	c.pconn6.Close()
	c.pconn4.Close()
	if c.closeDisco4 != nil {
		c.closeDisco4.Close()
	}
	if c.closeDisco6 != nil {
		c.closeDisco6.Close()
	}
	// Wait on goroutines updating right at the end, once everything is
	// already closed. We want everything else in the Conn to be
	// consistently in the closed state before we release mu to wait
	// on the endpoint updater & derphttp.Connect.
	for c.goroutinesRunningLocked() {
		c.muCond.Wait()
	}

	if pinger := c.getPinger(); pinger != nil {
		pinger.Close()
	}

	deregisterMetrics()

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
		default:
			return true
		}
	}
	return false
}

func (c *Conn) shouldDoPeriodicReSTUNLocked() bool {
	if c.networkDown() || c.homeless {
		return false
	}
	if len(c.peerSet) == 0 || c.privateKey.IsZero() {
		// If no peers, not worth doing.
		// Also don't if there's no key (not running).
		return false
	}
	if f := c.idleFunc; f != nil {
		idleFor := f()
		if debugReSTUNStopOnIdle() {
			c.logf("magicsock: periodicReSTUN: idle for %v", idleFor.Round(time.Second))
		}
		if idleFor > sessionActiveTimeout {
			if c.controlKnobs != nil && c.controlKnobs.ForceBackgroundSTUN.Load() {
				// Overridden by control.
				return true
			}
			return false
		}
	}
	return true
}

func (c *Conn) onPortMapChanged(portmappertype.Mapping) { c.ReSTUN("portmap-changed") }

// ReSTUN triggers an address discovery.
// The provided why string is for debug logging only.
// If Conn.staticEndpoints have been updated, calling ReSTUN will also result in
// the new endpoints being advertised.
func (c *Conn) ReSTUN(why string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		// raced with a shutdown.
		return
	}
	metricReSTUNCalls.Add(1)

	// If the user stopped the app, stop doing work. (When the
	// user stops Tailscale via the GUI apps, ipn/local.go
	// reconfigures the engine with a zero private key.)
	//
	// This used to just check c.privateKey.IsZero, but that broke
	// some end-to-end tests that didn't ever set a private
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
			c.dlogf("[v1] magicsock: ReSTUN: endpoint update active, need another later (%q)", why)
			c.wantEndpointsUpdate = why
		}
	} else {
		c.endpointsUpdateActive = true
		go c.updateEndpoints(why)
	}
}

// listenPacket opens a packet listener.
// The network must be "udp4" or "udp6".
func (c *Conn) listenPacket(network string, port uint16) (nettype.PacketConn, error) {
	ctx := context.Background() // unused without DNS name to resolve
	if network == "udp4" {
		ctx = sockstats.WithSockStats(ctx, sockstats.LabelMagicsockConnUDP4, c.logf)
	} else {
		ctx = sockstats.WithSockStats(ctx, sockstats.LabelMagicsockConnUDP6, c.logf)
	}
	addr := net.JoinHostPort("", fmt.Sprint(port))
	if c.testOnlyPacketListener != nil {
		return nettype.MakePacketListenerWithNetIP(c.testOnlyPacketListener).ListenPacket(ctx, network, addr)
	}
	return nettype.MakePacketListenerWithNetIP(netns.Listener(c.logf, c.netMon)).ListenPacket(ctx, network, addr)
}

// bindSocket binds a UDP socket to ruc.
// Network indicates the UDP socket type; it must be "udp4" or "udp6".
// If ruc had an existing UDP socket bound, it closes that socket.
// The caller is responsible for informing the portMapper of any changes.
// If curPortFate is set to dropCurrentPort, no attempt is made to reuse
// the current port.
func (c *Conn) bindSocket(ruc *RebindingUDPConn, network string, curPortFate currentPortFate) error {
	if debugBindSocket() {
		c.logf("magicsock: bindSocket: network=%q curPortFate=%v", network, curPortFate)
	}

	// Hold the ruc lock the entire time, so that the close+bind is atomic
	// from the perspective of ruc receive functions.
	ruc.mu.Lock()
	defer ruc.mu.Unlock()

	if runtime.GOOS == "js" {
		ruc.setConnLocked(newBlockForeverConn(), "", c.bind.BatchSize())
		return nil
	}

	if debugAlwaysDERP() {
		c.logf("disabled %v per TS_DEBUG_ALWAYS_USE_DERP", network)
		ruc.setConnLocked(newBlockForeverConn(), "", c.bind.BatchSize())
		return nil
	}

	// Build a list of preferred ports.
	// Best is the port that the user requested.
	// Second best is the port that is currently in use.
	// If those fail, fall back to 0.
	var ports []uint16
	if port := uint16(c.port.Load()); port != 0 {
		ports = append(ports, port)
	}
	if ruc.pconn != nil && curPortFate == keepCurrentPort {
		curPort := uint16(ruc.localAddrLocked().Port)
		ports = append(ports, curPort)
	}
	ports = append(ports, 0)
	// Remove duplicates. (All duplicates are consecutive.)
	ports = slices.Compact(ports)

	if debugBindSocket() {
		c.logf("magicsock: bindSocket: candidate ports: %+v", ports)
	}

	var pconn nettype.PacketConn
	for _, port := range ports {
		// Close the existing conn, in case it is sitting on the port we want.
		err := ruc.closeLocked()
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, errNilPConn) {
			c.logf("magicsock: bindSocket %v close failed: %v", network, err)
		}
		// Open a new one with the desired port.
		pconn, err = c.listenPacket(network, port)
		if err != nil {
			c.logf("magicsock: unable to bind %v port %d: %v", network, port, err)
			continue
		}
		if c.portUpdatePub.ShouldPublish() {
			_, gotPortStr, err := net.SplitHostPort(pconn.LocalAddr().String())
			if err != nil {
				c.logf("could not parse port from %s: %w", pconn.LocalAddr().String(), err)
			} else {
				gotPort, err := strconv.ParseUint(gotPortStr, 10, 16)
				if err != nil {
					c.logf("could not parse port from %s: %w", gotPort, err)
				} else {
					c.portUpdatePub.Publish(router.PortUpdate{
						UDPPort:         uint16(gotPort),
						EndpointNetwork: network,
					})
				}
			}
		}
		trySetUDPSocketOptions(pconn, c.logf)

		// Success.
		if debugBindSocket() {
			c.logf("magicsock: bindSocket: successfully listened %v port %d", network, port)
		}
		ruc.setConnLocked(pconn, network, c.bind.BatchSize())
		if network == "udp4" {
			c.health.SetUDP4Unbound(false)
		}
		return nil
	}

	// Failed to bind, including on port 0 (!).
	// Set pconn to a dummy conn whose reads block until closed.
	// This keeps the receive funcs alive for a future in which
	// we get a link change and we can try binding again.
	ruc.setConnLocked(newBlockForeverConn(), "", c.bind.BatchSize())
	if network == "udp4" {
		c.health.SetUDP4Unbound(true)
	}
	return fmt.Errorf("failed to bind any ports (tried %v)", ports)
}

type currentPortFate uint8

const (
	keepCurrentPort = currentPortFate(0)
	dropCurrentPort = currentPortFate(1)
)

// rebind closes and re-binds the UDP sockets.
// We consider it successful if we manage to bind the IPv4 socket.
func (c *Conn) rebind(curPortFate currentPortFate) error {
	if err := c.bindSocket(&c.pconn6, "udp6", curPortFate); err != nil {
		c.logf("magicsock: Rebind ignoring IPv6 bind failure: %v", err)
	}
	if err := c.bindSocket(&c.pconn4, "udp4", curPortFate); err != nil {
		return fmt.Errorf("magicsock: Rebind IPv4 failed: %w", err)
	}
	if c.portMapper != nil {
		c.portMapper.SetLocalPort(c.LocalPort())
	}
	c.UpdatePMTUD()
	return nil
}

// Rebind closes and re-binds the UDP sockets and resets the DERP connection.
// It should be followed by a call to ReSTUN.
func (c *Conn) Rebind() {
	metricRebindCalls.Add(1)
	if err := c.rebind(keepCurrentPort); err != nil {
		c.logf("%v", err)
		return
	}

	var ifIPs []netip.Prefix
	if c.netMon != nil {
		st := c.netMon.InterfaceState()
		defIf := st.DefaultRouteInterface
		ifIPs = st.InterfaceIPs[defIf]
		c.logf("Rebind; defIf=%q, ips=%v", defIf, ifIPs)
	}

	if len(ifIPs) > 0 {
		c.maybeCloseDERPsOnRebind(ifIPs)
	}
	c.resetEndpointStates()
}

// resetEndpointStates resets the preferred address for all peers.
// This is called when connectivity changes enough that we no longer
// trust the old routes.
func (c *Conn) resetEndpointStates() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerMap.forEachEndpoint(func(ep *endpoint) {
		ep.noteConnectivityChange()
	})
}

// packIPPort packs an IPPort into the form wanted by WireGuard.
func packIPPort(ua netip.AddrPort) []byte {
	ip := ua.Addr().Unmap()
	a := ip.As16()
	ipb := a[:]
	if ip.Is4() {
		ipb = ipb[12:]
	}
	b := make([]byte, 0, len(ipb)+2)
	b = append(b, ipb...)
	b = append(b, byte(ua.Port()))
	b = append(b, byte(ua.Port()>>8))
	return b
}

// ParseEndpoint implements conn.Bind; it's called by WireGuard to connect to an endpoint.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind.ParseEndpoint
func (c *Conn) ParseEndpoint(nodeKeyStr string) (conn.Endpoint, error) {
	k, err := key.ParseNodePublicUntyped(mem.S(nodeKeyStr))
	if err != nil {
		return nil, fmt.Errorf("magicsock: ParseEndpoint: parse failed on %q: %w", nodeKeyStr, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errConnClosed
	}
	ep, ok := c.peerMap.endpointForNodeKey(k)
	if !ok {
		// We should never be telling WireGuard about a new peer
		// before magicsock knows about it.
		c.logf("[unexpected] magicsock: ParseEndpoint: unknown node key=%s", k.ShortString())
		return nil, fmt.Errorf("magicsock: ParseEndpoint: unknown peer %q", k.ShortString())
	}

	return ep, nil
}

func newBlockForeverConn() *blockForeverConn {
	c := new(blockForeverConn)
	c.cond = sync.NewCond(&c.mu)
	return c
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

// onNodeMutationsUpdate is called when a [NodeMutationsUpdate] is received over
// the [eventbus.Bus]. Note: It does not apply these mutations to c.peers.
func (c *Conn) onNodeMutationsUpdate(update NodeMutationsUpdate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, m := range update.Mutations {
		nodeID := m.NodeIDBeingMutated()
		ep, ok := c.peerMap.endpointForNodeID(nodeID)
		if !ok {
			continue
		}
		switch m := m.(type) {
		case netmap.NodeMutationDERPHome:
			ep.setDERPHome(uint16(m.DERPRegion))
		case netmap.NodeMutationEndpoints:
			ep.mu.Lock()
			ep.setEndpointsLocked(views.SliceOf(m.Endpoints))
			ep.mu.Unlock()
		}
	}
}

// UpdateStatus implements the interface needed by ipnstate.StatusBuilder.
//
// This method adds in the magicsock-specific information only. Most
// of the status is otherwise populated by LocalBackend.
func (c *Conn) UpdateStatus(sb *ipnstate.StatusBuilder) {
	c.mu.Lock()
	defer c.mu.Unlock()

	sb.MutateSelfStatus(func(ss *ipnstate.PeerStatus) {
		ss.Addrs = make([]string, 0, len(c.lastEndpoints))
		for _, ep := range c.lastEndpoints {
			ss.Addrs = append(ss.Addrs, ep.Addr.String())
		}
		if c.derpMap != nil {
			if reg, ok := c.derpMap.Regions[c.myDerp]; ok {
				ss.Relay = reg.RegionCode
			}
		}
	})

	if sb.WantPeers {
		c.peerMap.forEachEndpoint(func(ep *endpoint) {
			ps := &ipnstate.PeerStatus{InMagicSock: true}
			ep.populatePeerStatus(ps)
			sb.AddPeer(ep.publicKey, ps)
		})
	}

	c.foreachActiveDerpSortedLocked(func(node int, ad activeDerp) {
		// TODO(bradfitz): add a method to ipnstate.StatusBuilder
		// to include all the DERP connections we have open
		// and add it here. See the other caller of foreachActiveDerpSortedLocked.
	})
}

// SetConnectionCounter specifies a per-connection statistics aggregator.
// Nil may be specified to disable statistics gathering.
func (c *Conn) SetConnectionCounter(fn netlogfunc.ConnectionCounter) {
	if buildfeatures.HasNetLog {
		c.connCounter.Store(fn)
	}
}

// SetHomeless sets whether magicsock should idle harder and not have a DERP
// home connection active and not search for its nearest DERP home. In this
// homeless mode, the node is unreachable by others.
func (c *Conn) SetHomeless(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.homeless = v

	if v && c.myDerp != 0 {
		oldHome := c.myDerp
		c.myDerp = 0
		c.closeDerpLocked(oldHome, "set-homeless")
	}
	if !v {
		go c.updateEndpoints("set-homeless-disabled")
	}
}

const (
	// sessionActiveTimeout is how long since the last activity we
	// try to keep an established endpoint peering alive.
	// It's also the idle time at which we stop doing STUN queries to
	// keep NAT mappings alive.
	sessionActiveTimeout = 45 * time.Second

	// upgradeUDPDirectInterval is how often we try to upgrade to a better,
	// direct UDP path even if we have some direct UDP path that works.
	upgradeUDPDirectInterval = 1 * time.Minute

	// upgradeUDPRelayInterval is how often we try to discover UDP relay paths
	// even if we have a UDP relay path that works.
	upgradeUDPRelayInterval = 1 * time.Minute

	// discoverUDPRelayPathsInterval is the minimum time between UDP relay path
	// discovery.
	discoverUDPRelayPathsInterval = 30 * time.Second

	// heartbeatInterval is how often pings to the best UDP address
	// are sent.
	heartbeatInterval = 3 * time.Second

	// trustUDPAddrDuration is how long we trust a UDP address as the exclusive
	// path (without using DERP) without having heard a Pong reply.
	trustUDPAddrDuration = 6500 * time.Millisecond

	// goodEnoughLatency is the latency at or under which we don't
	// try to upgrade to a better path.
	goodEnoughLatency = 5 * time.Millisecond

	// endpointsFreshEnoughDuration is how long we consider a
	// STUN-derived endpoint valid for. UDP NAT mappings typically
	// expire at 30 seconds, so this is a few seconds shy of that.
	endpointsFreshEnoughDuration = 27 * time.Second
)

// Constants that are variable for testing.
var (
	// pingTimeoutDuration is how long we wait for a pong reply before
	// assuming it's never coming.
	pingTimeoutDuration = 5 * time.Second

	// discoPingInterval is the minimum time between pings
	// to an endpoint. (Except in the case of CallMeMaybe frames
	// resetting the counter, as the first pings likely didn't through
	// the firewall)
	discoPingInterval = 5 * time.Second

	// wireguardPingInterval is the minimum time between pings to an endpoint.
	// Pings are only sent if we have not observed bidirectional traffic with an
	// endpoint in at least this duration.
	wireguardPingInterval = 5 * time.Second
)

// indexSentinelDeleted is the temporary value that endpointState.index takes while
// a endpoint's endpoints are being updated from a new network map.
const indexSentinelDeleted = -1

// getPinger lazily instantiates a pinger and returns it, if it was
// already instantiated it returns the existing one.
func (c *Conn) getPinger() *ping.Pinger {
	return c.wgPinger.Get(func() *ping.Pinger {
		return ping.New(c.connCtx, c.dlogf, netns.Listener(c.logf, c.netMon))
	})
}

// DebugPickNewDERP picks a new DERP random home temporarily (even if just for
// seconds) and reports it to control. It exists to test DERP home changes and
// netmap deltas, etc. It serves no useful user purpose.
func (c *Conn) DebugPickNewDERP() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	dm := c.derpMap
	if dm == nil {
		return errors.New("no derpmap")
	}
	if c.netInfoLast == nil {
		return errors.New("no netinfo")
	}
	for _, r := range dm.Regions {
		if r.RegionID == c.myDerp {
			continue
		}
		c.logf("magicsock: [debug] switching derp home to random %v (%v)", r.RegionID, r.RegionCode)
		go c.setNearestDERP(r.RegionID)
		ni2 := c.netInfoLast.Clone()
		ni2.PreferredDERP = r.RegionID
		c.callNetInfoCallbackLocked(ni2)
		return nil
	}
	return errors.New("too few regions")
}

func (c *Conn) DebugForcePreferDERP(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.logf("magicsock: [debug] force preferred DERP set to: %d", n)
	c.netChecker.SetForcePreferredDERP(n)
}

func trySetUDPSocketOptions(pconn nettype.PacketConn, logf logger.Logf) {
	directions := []sockopts.BufferDirection{sockopts.ReadDirection, sockopts.WriteDirection}
	for _, direction := range directions {
		forceErr, portableErr := sockopts.SetBufferSize(pconn, direction, socketBufferSize)
		if forceErr != nil {
			logf("magicsock: [warning] failed to force-set UDP %v buffer size to %d: %v; using kernel default values (impacts throughput only)", direction, socketBufferSize, forceErr)
		}
		if portableErr != nil {
			logf("magicsock: failed to set UDP %v buffer size to %d: %v", direction, socketBufferSize, portableErr)
		}
	}

	err := sockopts.SetICMPErrImmunity(pconn)
	if err != nil {
		logf("magicsock: %v", err)
	}
}

// derpStr replaces DERP IPs in s with "derp-".
func derpStr(s string) string { return strings.ReplaceAll(s, "127.3.3.40:", "derp-") }

// epAddrEndpointCache is a mutex-free single-element cache, mapping from
// a single [epAddr] to a single [*endpoint].
type epAddrEndpointCache struct {
	epAddr epAddr
	gen    int64
	de     *endpoint
}

// discoInfo is the info and state for the DiscoKey
// in the [Conn.discoInfo] and [relayManager.discoInfoByServerDisco] map keys.
//
// When the disco protocol is used to handshake with a peer relay server, the
// corresponding discoInfo is held in [relayManager.discoInfoByServerDisco]
// instead of [Conn.discoInfo].
//
// Note that a DiscoKey does not necessarily map to exactly one
// node. In the case of shared nodes and users switching accounts, two
// nodes in the NetMap may legitimately have the same DiscoKey.  As
// such, no fields in here should be considered node-specific.
type discoInfo struct {
	// discoKey is the same as the corresponding map key,
	// just so you can pass around a *discoInfo alone.
	// Not modified once initialized.
	discoKey key.DiscoPublic

	// discoShort is discoKey.ShortString().
	// Not modified once initialized;
	discoShort string

	// sharedKey is the precomputed key for communication with the
	// peer that has the DiscoKey used to look up this *discoInfo in
	// the corresponding map.
	// Not modified once initialized.
	sharedKey key.DiscoShared

	// Mutable fields follow, owned by [Conn.mu]. These are irrelevant when
	// discoInfo is a peer relay server disco key in the
	// [relayManager.discoInfoByServerDisco] map:

	// lastPingFrom is the src of a ping for discoKey.
	lastPingFrom epAddr

	// lastPingTime is the last time of a ping for discoKey.
	lastPingTime time.Time
}

var (
	metricNumPeers     = clientmetric.NewGauge("magicsock_netmap_num_peers")
	metricNumDERPConns = clientmetric.NewGauge("magicsock_num_derp_conns")

	metricRebindCalls     = clientmetric.NewCounter("magicsock_rebind_calls")
	metricReSTUNCalls     = clientmetric.NewCounter("magicsock_restun_calls")
	metricUpdateEndpoints = clientmetric.NewCounter("magicsock_update_endpoints")

	// Sends (data or disco)
	metricSendDERPQueued      = clientmetric.NewCounter("magicsock_send_derp_queued")
	metricSendDERPErrorChan   = clientmetric.NewCounter("magicsock_send_derp_error_chan")
	metricSendDERPErrorClosed = clientmetric.NewCounter("magicsock_send_derp_error_closed")
	metricSendDERPErrorQueue  = clientmetric.NewCounter("magicsock_send_derp_error_queue")
	metricSendDERPDropped     = clientmetric.NewCounter("magicsock_send_derp_dropped")
	metricSendUDPError        = clientmetric.NewCounter("magicsock_send_udp_error")
	metricSendPeerRelayError  = clientmetric.NewCounter("magicsock_send_peer_relay_error")
	metricSendDERPError       = clientmetric.NewCounter("magicsock_send_derp_error")

	// Sends (data)
	//
	// Note: Prior to v1.78 metricSendUDP & metricSendDERP counted sends of data
	// AND disco packets. They were updated in v1.78 to only count data packets.
	// metricSendPeerRelay was added in v1.86 and has always counted only data
	// packets.
	metricSendUDP       = clientmetric.NewAggregateCounter("magicsock_send_udp")
	metricSendPeerRelay = clientmetric.NewAggregateCounter("magicsock_send_peer_relay")
	metricSendDERP      = clientmetric.NewAggregateCounter("magicsock_send_derp")

	// Data packets (non-disco)
	metricSendData                     = clientmetric.NewCounter("magicsock_send_data")
	metricSendDataNetworkDown          = clientmetric.NewCounter("magicsock_send_data_network_down")
	metricRecvDataPacketsDERP          = clientmetric.NewAggregateCounter("magicsock_recv_data_derp")
	metricRecvDataPacketsIPv4          = clientmetric.NewAggregateCounter("magicsock_recv_data_ipv4")
	metricRecvDataPacketsIPv6          = clientmetric.NewAggregateCounter("magicsock_recv_data_ipv6")
	metricRecvDataPacketsPeerRelayIPv4 = clientmetric.NewAggregateCounter("magicsock_recv_data_peer_relay_ipv4")
	metricRecvDataPacketsPeerRelayIPv6 = clientmetric.NewAggregateCounter("magicsock_recv_data_peer_relay_ipv6")
	metricSendDataPacketsDERP          = clientmetric.NewAggregateCounter("magicsock_send_data_derp")
	metricSendDataPacketsIPv4          = clientmetric.NewAggregateCounter("magicsock_send_data_ipv4")
	metricSendDataPacketsIPv6          = clientmetric.NewAggregateCounter("magicsock_send_data_ipv6")
	metricSendDataPacketsPeerRelayIPv4 = clientmetric.NewAggregateCounter("magicsock_send_data_peer_relay_ipv4")
	metricSendDataPacketsPeerRelayIPv6 = clientmetric.NewAggregateCounter("magicsock_send_data_peer_relay_ipv6")

	// Data bytes (non-disco)
	metricRecvDataBytesDERP          = clientmetric.NewAggregateCounter("magicsock_recv_data_bytes_derp")
	metricRecvDataBytesIPv4          = clientmetric.NewAggregateCounter("magicsock_recv_data_bytes_ipv4")
	metricRecvDataBytesIPv6          = clientmetric.NewAggregateCounter("magicsock_recv_data_bytes_ipv6")
	metricRecvDataBytesPeerRelayIPv4 = clientmetric.NewAggregateCounter("magicsock_recv_data_bytes_peer_relay_ipv4")
	metricRecvDataBytesPeerRelayIPv6 = clientmetric.NewAggregateCounter("magicsock_recv_data_bytes_peer_relay_ipv6")
	metricSendDataBytesDERP          = clientmetric.NewAggregateCounter("magicsock_send_data_bytes_derp")
	metricSendDataBytesIPv4          = clientmetric.NewAggregateCounter("magicsock_send_data_bytes_ipv4")
	metricSendDataBytesIPv6          = clientmetric.NewAggregateCounter("magicsock_send_data_bytes_ipv6")
	metricSendDataBytesPeerRelayIPv4 = clientmetric.NewAggregateCounter("magicsock_send_data_bytes_peer_relay_ipv4")
	metricSendDataBytesPeerRelayIPv6 = clientmetric.NewAggregateCounter("magicsock_send_data_bytes_peer_relay_ipv6")

	// Disco packets
	metricSendDiscoUDP                           = clientmetric.NewCounter("magicsock_disco_send_udp")
	metricSendDiscoDERP                          = clientmetric.NewCounter("magicsock_disco_send_derp")
	metricSentDiscoUDP                           = clientmetric.NewCounter("magicsock_disco_sent_udp")
	metricSentDiscoDERP                          = clientmetric.NewCounter("magicsock_disco_sent_derp")
	metricSentDiscoPing                          = clientmetric.NewCounter("magicsock_disco_sent_ping")
	metricSentDiscoPong                          = clientmetric.NewCounter("magicsock_disco_sent_pong")
	metricSentDiscoPeerMTUProbes                 = clientmetric.NewCounter("magicsock_disco_sent_peer_mtu_probes")
	metricSentDiscoPeerMTUProbeBytes             = clientmetric.NewCounter("magicsock_disco_sent_peer_mtu_probe_bytes")
	metricSentDiscoCallMeMaybe                   = clientmetric.NewCounter("magicsock_disco_sent_callmemaybe")
	metricSentDiscoCallMeMaybeVia                = clientmetric.NewCounter("magicsock_disco_sent_callmemaybevia")
	metricSentDiscoBindUDPRelayEndpoint          = clientmetric.NewCounter("magicsock_disco_sent_bind_udp_relay_endpoint")
	metricSentDiscoBindUDPRelayEndpointAnswer    = clientmetric.NewCounter("magicsock_disco_sent_bind_udp_relay_endpoint_answer")
	metricSentDiscoAllocUDPRelayEndpointRequest  = clientmetric.NewCounter("magicsock_disco_sent_alloc_udp_relay_endpoint_request")
	metricLocalDiscoAllocUDPRelayEndpointRequest = clientmetric.NewCounter("magicsock_disco_local_alloc_udp_relay_endpoint_request")
	metricSentDiscoAllocUDPRelayEndpointResponse = clientmetric.NewCounter("magicsock_disco_sent_alloc_udp_relay_endpoint_response")
	metricRecvDiscoBadPeer                       = clientmetric.NewCounter("magicsock_disco_recv_bad_peer")
	metricRecvDiscoBadKey                        = clientmetric.NewCounter("magicsock_disco_recv_bad_key")
	metricRecvDiscoBadParse                      = clientmetric.NewCounter("magicsock_disco_recv_bad_parse")

	metricRecvDiscoUDP                                   = clientmetric.NewCounter("magicsock_disco_recv_udp")
	metricRecvDiscoDERP                                  = clientmetric.NewCounter("magicsock_disco_recv_derp")
	metricRecvDiscoPing                                  = clientmetric.NewCounter("magicsock_disco_recv_ping")
	metricRecvDiscoPong                                  = clientmetric.NewCounter("magicsock_disco_recv_pong")
	metricRecvDiscoCallMeMaybe                           = clientmetric.NewCounter("magicsock_disco_recv_callmemaybe")
	metricRecvDiscoCallMeMaybeVia                        = clientmetric.NewCounter("magicsock_disco_recv_callmemaybevia")
	metricRecvDiscoCallMeMaybeBadNode                    = clientmetric.NewCounter("magicsock_disco_recv_callmemaybe_bad_node")
	metricRecvDiscoCallMeMaybeViaBadNode                 = clientmetric.NewCounter("magicsock_disco_recv_callmemaybevia_bad_node")
	metricRecvDiscoCallMeMaybeBadDisco                   = clientmetric.NewCounter("magicsock_disco_recv_callmemaybe_bad_disco")
	metricRecvDiscoCallMeMaybeViaBadDisco                = clientmetric.NewCounter("magicsock_disco_recv_callmemaybevia_bad_disco")
	metricRecvDiscoBindUDPRelayEndpointChallenge         = clientmetric.NewCounter("magicsock_disco_recv_bind_udp_relay_endpoint_challenge")
	metricRecvDiscoAllocUDPRelayEndpointRequest          = clientmetric.NewCounter("magicsock_disco_recv_alloc_udp_relay_endpoint_request")
	metricRecvDiscoAllocUDPRelayEndpointRequestBadDisco  = clientmetric.NewCounter("magicsock_disco_recv_alloc_udp_relay_endpoint_request_bad_disco")
	metricRecvDiscoAllocUDPRelayEndpointResponseBadDisco = clientmetric.NewCounter("magicsock_disco_recv_alloc_udp_relay_endpoint_response_bad_disco")
	metricRecvDiscoAllocUDPRelayEndpointResponse         = clientmetric.NewCounter("magicsock_disco_recv_alloc_udp_relay_endpoint_response")
	metricLocalDiscoAllocUDPRelayEndpointResponse        = clientmetric.NewCounter("magicsock_disco_local_alloc_udp_relay_endpoint_response")
	metricRecvDiscoDERPPeerNotHere                       = clientmetric.NewCounter("magicsock_disco_recv_derp_peer_not_here")
	metricRecvDiscoDERPPeerGoneUnknown                   = clientmetric.NewCounter("magicsock_disco_recv_derp_peer_gone_unknown")
	// metricDERPHomeChange is how many times our DERP home region DI has
	// changed from non-zero to a different non-zero.
	metricDERPHomeChange = clientmetric.NewCounter("derp_home_change")

	// metricDERPHomeNoChangeNoControl is how many times our DERP home
	// region did not change because we didn't have an active connection to
	// the control server.
	metricDERPHomeNoChangeNoControl = clientmetric.NewCounter("derp_home_no_change_no_control")

	// metricDERPHomeFallback is how many times we picked a DERP fallback.
	metricDERPHomeFallback = clientmetric.NewCounter("derp_home_fallback")

	// metricDERPStaleCleaned is how many times we closed a stale DERP connection.
	metricDERPStaleCleaned = clientmetric.NewCounter("derp_stale_cleaned")

	// Disco packets received bpf read path
	//lint:ignore U1000 used on Linux only
	metricRecvDiscoPacketIPv4 = clientmetric.NewCounter("magicsock_disco_recv_bpf_ipv4")
	//lint:ignore U1000 used on Linux only
	metricRecvDiscoPacketIPv6 = clientmetric.NewCounter("magicsock_disco_recv_bpf_ipv6")

	// metricMaxPeerMTUProbed is the largest peer path MTU we successfully probed.
	metricMaxPeerMTUProbed = clientmetric.NewGauge("magicsock_max_peer_mtu_probed")

	// metricRecvDiscoPeerMTUProbesByMTU collects the number of times we
	// received an peer MTU probe response for a given MTU size.
	// TODO: add proper support for label maps in clientmetrics
	metricRecvDiscoPeerMTUProbesByMTU syncs.Map[string, *clientmetric.Metric]

	// metricUDPLifetime* metrics pertain to UDP lifetime probing, see type
	// probeUDPLifetime. These metrics assume a static/default configuration for
	// probing (defaultProbeUDPLifetimeConfig) until we disseminate
	// ProbeUDPLifetimeConfig from control, and have lifetime management (GC old
	// metrics) of clientmetrics or similar.
	metricUDPLifetimeCliffsScheduled             = newUDPLifetimeCounter("magicsock_udp_lifetime_cliffs_scheduled")
	metricUDPLifetimeCliffsCompleted             = newUDPLifetimeCounter("magicsock_udp_lifetime_cliffs_completed")
	metricUDPLifetimeCliffsMissed                = newUDPLifetimeCounter("magicsock_udp_lifetime_cliffs_missed")
	metricUDPLifetimeCliffsRescheduled           = newUDPLifetimeCounter("magicsock_udp_lifetime_cliffs_rescheduled")
	metricUDPLifetimeCyclesCompleted             = newUDPLifetimeCounter("magicsock_udp_lifetime_cycles_completed")
	metricUDPLifetimeCycleCompleteNoCliffReached = newUDPLifetimeCounter("magicsock_udp_lifetime_cycle_complete_no_cliff_reached")
	metricUDPLifetimeCycleCompleteAt10sCliff     = newUDPLifetimeCounter("magicsock_udp_lifetime_cycle_complete_at_10s_cliff")
	metricUDPLifetimeCycleCompleteAt30sCliff     = newUDPLifetimeCounter("magicsock_udp_lifetime_cycle_complete_at_30s_cliff")
	metricUDPLifetimeCycleCompleteAt60sCliff     = newUDPLifetimeCounter("magicsock_udp_lifetime_cycle_complete_at_60s_cliff")
)

// newUDPLifetimeCounter returns a new *clientmetric.Metric with the provided
// name combined with a suffix representing defaultProbeUDPLifetimeConfig.
func newUDPLifetimeCounter(name string) *clientmetric.Metric {
	var sb strings.Builder
	for _, cliff := range defaultProbeUDPLifetimeConfig.Cliffs {
		sb.WriteString(fmt.Sprintf("%ds", cliff/time.Second))
	}
	sb.WriteString(fmt.Sprintf("_%ds", defaultProbeUDPLifetimeConfig.CycleCanStartEvery/time.Second))
	return clientmetric.NewCounter(fmt.Sprintf("%s_%s", name, sb.String()))
}

func getPeerMTUsProbedMetric(mtu tstun.WireMTU) *clientmetric.Metric {
	key := fmt.Sprintf("magicsock_recv_disco_peer_mtu_probes_by_mtu_%d", mtu)
	mm, _ := metricRecvDiscoPeerMTUProbesByMTU.LoadOrInit(key, func() *clientmetric.Metric { return clientmetric.NewCounter(key) })
	return mm
}

// GetLastNetcheckReport returns the last netcheck report, returning nil if a recent one does not exist.
func (c *Conn) GetLastNetcheckReport(ctx context.Context) *netcheck.Report {
	return c.lastNetCheckReport.Load()
}

// SetLastNetcheckReportForTest sets the magicsock conn's last netcheck report.
// Used for testing purposes.
func (c *Conn) SetLastNetcheckReportForTest(ctx context.Context, report *netcheck.Report) {
	c.lastNetCheckReport.Store(report)
}

// lazyEndpoint is a wireguard [conn.Endpoint] for when magicsock received a
// non-disco (presumably WireGuard) packet from a UDP address from which we
// can't map to a Tailscale peer. But WireGuard most likely can, once it
// decrypts it. So we implement the [conn.InitiationAwareEndpoint] and
// [conn.PeerAwareEndpoint] interfaces, to allow WireGuard to tell us who it is
// later, just-in-time to configure the peer, and set the associated [epAddr]
// in the [peerMap]. Future receives on the associated [epAddr] will then
// resolve directly to an [*endpoint].
//
// We also sometimes (see [Conn.receiveIP]) return a [*lazyEndpoint] to
// wireguard-go to verify an [epAddr] resolves to the [*endpoint] (maybeEP) we
// believe it to be, to resolve [epAddr] collisions across peers. [epAddr]
// collisions have a higher chance of occurrence for packets received over peer
// relays versus direct connections, as peer relay connections do not upsert
// into [peerMap] around disco packet reception, but direct connections do.
type lazyEndpoint struct {
	c       *Conn
	maybeEP *endpoint // or nil if unknown
	src     epAddr
}

var _ conn.InitiationAwareEndpoint = (*lazyEndpoint)(nil)
var _ conn.PeerAwareEndpoint = (*lazyEndpoint)(nil)
var _ conn.Endpoint = (*lazyEndpoint)(nil)

// InitiationMessagePublicKey implements [conn.InitiationAwareEndpoint].
// wireguard-go calls us here if we passed it a [*lazyEndpoint] for an
// initiation message, for which it might not have the relevant peer configured,
// enabling us to just-in-time configure it and note its activity via
// [*endpoint.noteRecvActivity], before it performs peer lookup and attempts
// decryption.
//
// Reception of all other WireGuard message types implies pre-existing knowledge
// of the peer by wireguard-go for it to do useful work. See
// [userspaceEngine.maybeReconfigWireguardLocked] &
// [userspaceEngine.noteRecvActivity] for more details around just-in-time
// wireguard-go peer (de)configuration.
func (le *lazyEndpoint) InitiationMessagePublicKey(peerPublicKey [32]byte) {
	pubKey := key.NodePublicFromRaw32(mem.B(peerPublicKey[:]))
	if le.maybeEP != nil && pubKey.Compare(le.maybeEP.publicKey) == 0 {
		return
	}
	le.c.mu.Lock()
	ep, ok := le.c.peerMap.endpointForNodeKey(pubKey)
	// [Conn.mu] must not be held while [Conn.noteRecvActivity] is called, which
	// [endpoint.noteRecvActivity] can end up calling. See
	// [Options.NoteRecvActivity] docs.
	le.c.mu.Unlock()
	if !ok {
		return
	}
	now := mono.Now()
	ep.lastRecvUDPAny.StoreAtomic(now)
	ep.noteRecvActivity(le.src, now)
	// [ep.noteRecvActivity] may end up JIT configuring the peer, but we don't
	// update [peerMap] as wireguard-go hasn't decrypted the initiation
	// message yet. wireguard-go will call us below in [lazyEndpoint.FromPeer]
	// if it successfully decrypts the message, at which point it's safe to
	// insert le.src into the [peerMap] for ep.
}

func (le *lazyEndpoint) ClearSrc()         {}
func (le *lazyEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// DstIP returns the remote address of the peer.
//
// Note: DstIP is used internally by wireguard-go as part of handshake DoS
// mitigation.
func (le *lazyEndpoint) DstIP() netip.Addr { return le.src.ap.Addr() }

func (le *lazyEndpoint) SrcToString() string { return "" }
func (le *lazyEndpoint) DstToString() string { return le.src.String() }

// DstToBytes returns a binary representation of the remote address of the peer.
//
// Note: DstToBytes is used internally by wireguard-go as part of handshake DoS
// mitigation.
func (le *lazyEndpoint) DstToBytes() []byte {
	b, _ := le.src.ap.MarshalBinary()
	return b
}

// FromPeer implements [conn.PeerAwareEndpoint]. We return a [*lazyEndpoint] in
// [Conn.receiveIP] when we are unable to identify the peer at WireGuard
// packet reception time, pre-decryption, or we want wireguard-go to verify who
// we believe it to be (le.maybeEP). If wireguard-go successfully decrypts the
// packet it calls us here, and we update our [peerMap] to associate le.src with
// peerPublicKey.
func (le *lazyEndpoint) FromPeer(peerPublicKey [32]byte) {
	pubKey := key.NodePublicFromRaw32(mem.B(peerPublicKey[:]))
	if le.maybeEP != nil && pubKey.Compare(le.maybeEP.publicKey) == 0 {
		return
	}
	le.c.mu.Lock()
	defer le.c.mu.Unlock()
	ep, ok := le.c.peerMap.endpointForNodeKey(pubKey)
	if !ok {
		return
	}
	// TODO(jwhited): Consider [lazyEndpoint] effectiveness as a means to make
	//  this the sole call site for setNodeKeyForEpAddr. If this is the sole
	//  call site, and we always update the mapping based on successful
	//  Cryptokey Routing identification events, then we can go ahead and make
	//  [epAddr]s singular per peer (like they are for Geneve-encapsulated ones
	//  already).
	//  See http://go/corp/29422 & http://go/corp/30042
	le.c.peerMap.setNodeKeyForEpAddr(le.src, pubKey)
	le.c.logf("magicsock: lazyEndpoint.FromPeer(%v) setting epAddr(%v) in peerMap for node(%v)", pubKey.ShortString(), le.src, ep.nodeAddr)
}

// PeerRelays returns the current set of candidate peer relays.
func (c *Conn) PeerRelays() set.Set[netip.Addr] {
	candidatePeerRelays := c.relayManager.getServers()
	servers := make(set.Set[netip.Addr], len(candidatePeerRelays))
	c.mu.Lock()
	defer c.mu.Unlock()
	for relay := range candidatePeerRelays {
		pi, ok := c.peerMap.byNodeKey[relay.nodeKey]
		if !ok {
			if c.self.Key().Compare(relay.nodeKey) == 0 {
				if c.self.Addresses().Len() > 0 {
					servers.Add(c.self.Addresses().At(0).Addr())
				}
			}
			continue
		}
		servers.Add(pi.ep.nodeAddr)
	}
	return servers
}
