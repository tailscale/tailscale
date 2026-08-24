// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/mem"
	"tailscale.com/disco"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
	"tailscale.com/net/routemanager"
	"tailscale.com/net/tsaddr"
	"tailscale.com/syncs"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/events"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netlogfunc"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/netstack/gro"
	"tailscale.com/wgengine/wgcfg"
)

// WritePacketStartOffset is the minimal amount of leading space that must exist
// before &packet[offset] in a packet passed to [tun.Device.Write], which includes
// "injected" packet code paths. This leading space is required by [tun.Device]
// implementations.
//
// TODO(jwhited): consider collapsing with and renaming [tun.ReadPacketSpacing]
// for simplicity's sake. Exact math between [tun.Device] implementation and
// direction varies, but we can just pick the maximum value to reduce cognitive
// burden.
const WritePacketStartOffset = device.MessageTransportHeaderSize

// MaxPacketSize is the maximum size (in bytes)
// of a packet that can be injected into a tstun.Wrapper.
const MaxPacketSize = device.MaxContentSize

// TAPDebug is whether super verbose TAP debugging is enabled.
const TAPDebug = false

var (
	// ErrClosed is returned when attempting an operation on a closed Wrapper.
	ErrClosed = errors.New("device closed")
	// ErrFiltered is returned when the acted-on packet is rejected by a filter.
	ErrFiltered = errors.New("packet dropped by filter")
)

var (
	errPacketTooBig   = errors.New("packet too big")
	errOffsetTooBig   = errors.New("offset larger than buffer length")
	errOffsetTooSmall = errors.New("offset smaller than WritePacketStartOffset")
)

// parsedPacketPool holds a pool of Parsed structs for use in filtering.
// This is needed because escape analysis cannot see that parsed packets
// do not escape through {Pre,Post}Filter{In,Out}.
var parsedPacketPool = sync.Pool{New: func() any { return new(packet.Parsed) }}

// FilterFunc is a packet-filtering function with access to the Wrapper device.
// It must not hold onto the packet struct, as its backing storage will be reused.
type FilterFunc func(*packet.Parsed, *Wrapper) filter.Response

// GROFilterFunc is a FilterFunc extended with a *gro.GRO, enabling increased
// throughput where GRO is supported by a packet.Parsed interceptor, e.g.
// netstack/gVisor, and we are handling a vector of packets. Callers must pass a
// nil g for the first packet in a given vector, and continue passing the
// returned *gro.GRO for all remaining packets in said vector. If the returned
// *gro.GRO is non-nil after the last packet for a given vector is passed
// through the GROFilterFunc, the caller must also call Flush() on it to deliver
// any previously Enqueue()'d packets.
type GROFilterFunc func(p *packet.Parsed, w *Wrapper, g *gro.GRO) (filter.Response, *gro.GRO)

// Wrapper augments a tun.Device with packet filtering and injection.
//
// A Wrapper starts in a "corked" mode where Read calls are blocked
// until the Wrapper's Start method is called.
type Wrapper struct {
	logf        logger.Logf
	limitedLogf logger.Logf // aggressively rate-limited logf used for potentially high volume errors
	// tdev is the underlying Wrapper device.
	tdev  tun.Device
	isTAP bool // whether tdev is a TAP device

	started atomic.Bool   // whether Start has been called
	startCh chan struct{} // closed in Start

	closeOnce sync.Once

	// lastActivityAtomic is read/written atomically.
	// On 32 bit systems, if the fields above change,
	// you might need to add an align64 field here.
	lastActivityAtomic mono.Time // time of last send or receive

	discoKey syncs.AtomicValue[key.DiscoPublic]

	// timeNow, if non-nil, will be used to obtain the current time.
	timeNow func() time.Time

	// peerConfig stores the current NAT configuration.
	peerConfig atomic.Pointer[peerConfigTable]

	// startPollingOnce is used to start a [Wrapper.pollVector] goroutine at the
	// first call to [Wrapper.Read].
	startPollingOnce sync.Once
	// bufferConsumedMu protects bufferConsumed from concurrent sends, closes,
	// and send-after-close (by way of bufferConsumedClosed).
	bufferConsumedMu sync.Mutex
	// bufferConsumedClosed is true when bufferConsumed has been closed. This is
	// read by bufferConsumed writers to prevent send-after-close.
	bufferConsumedClosed bool
	// bufferConsumed synchronizes access to packet bufs and descriptors shared
	// by [Wrapper.Read] and [Wrapper.pollVector].
	//
	// Close closes bufferConsumed and sets bufferConsumedClosed to true.
	bufferConsumed chan struct{}

	// closed signals poll (by closing) when the device is closed.
	closed chan struct{}
	// outboundMu protects outbound and vectorOutbound from concurrent sends,
	// closes, and send-after-close (by way of outboundClosed).
	outboundMu sync.Mutex
	// outboundClosed is true when outbound or vectorOutbound have been closed.
	// This is read by outbound and vectorOutbound writers to prevent
	// send-after-close.
	outboundClosed bool
	// vectorOutbound is the queue by which packets leave the TUN device.
	//
	// The directions are relative to the network, not the device:
	// inbound packets arrive via UDP and are written into the TUN device;
	// outbound packets are read from the TUN device and sent out via UDP.
	// This queue is needed because although inbound writes are synchronous,
	// the other direction must wait on a WireGuard goroutine to poll it.
	//
	// Empty reads are skipped by WireGuard, so it is always legal
	// to discard an empty packet instead of sending it through vectorOutbound.
	//
	// Close closes vectorOutbound and sets outboundClosed to true.
	vectorOutbound chan tunVectorReadResult

	// eventsUpDown yields up and down tun.Events that arrive on a Wrapper's events channel.
	eventsUpDown chan tun.Event
	// eventsOther yields non-up-and-down tun.Events that arrive on a Wrapper's events channel.
	eventsOther chan tun.Event

	// filter atomically stores the currently active packet filter
	filter atomic.Pointer[filter.Filter]
	// filterFlags control the verbosity of logging packet drops/accepts.
	filterFlags filter.RunFlags
	// jailedFilter is the packet filter for jailed nodes.
	// Can be nil, which means drop all packets.
	jailedFilter atomic.Pointer[filter.Filter]

	// PreFilterPacketInboundFromWireGuard is the inbound filter function that runs before the main filter
	// and therefore sees the packets that may be later dropped by it.
	PreFilterPacketInboundFromWireGuard FilterFunc
	// PostFilterPacketInboundFromWireGuardAppConnector runs after the filter, but before PostFilterPacketInboundFromWireGuard.
	// Non-app connector traffic is passed along. Invalid app connector traffic is dropped.
	PostFilterPacketInboundFromWireGuardAppConnector FilterFunc
	// PostFilterPacketInboundFromWireGuard is the inbound filter function that runs after the main filter.
	PostFilterPacketInboundFromWireGuard GROFilterFunc
	// PreFilterPacketOutboundToWireGuardNetstackIntercept is a filter function that runs before the main filter
	// for packets from the local system. This filter is populated by netstack to hook
	// packets that should be handled by netstack. If set, this filter runs before
	// PreFilterFromTunToEngine.
	PreFilterPacketOutboundToWireGuardNetstackIntercept GROFilterFunc
	// PreFilterPacketOutboundToWireGuardEngineIntercept is a filter function that runs before the main filter
	// for packets from the local system. This filter is populated by wgengine to hook
	// packets which it handles internally. If both this and PreFilterFromTunToNetstack
	// filter functions are non-nil, this filter runs second.
	PreFilterPacketOutboundToWireGuardEngineIntercept FilterFunc
	// PreFilterPacketOutboundToWireGuardAppConnectorIntercept runs after PreFilterPacketOutboundToWireGuardEngineIntercept
	// for app connector specific traffic. Non-app connector traffic is passed along. Invalid app connector traffic is
	// dropped.
	PreFilterPacketOutboundToWireGuardAppConnectorIntercept FilterFunc
	// PostFilterPacketOutboundToWireGuard is the outbound filter function that runs after the main filter.
	PostFilterPacketOutboundToWireGuard FilterFunc

	// OnTSMPPongReceived, if non-nil, is called whenever a TSMP pong arrives.
	OnTSMPPongReceived func(packet.TSMPPongReply)

	// OnICMPEchoResponseReceived, if non-nil, is called whenever a ICMP echo response
	// arrives. If the packet is to be handled internally this returns true,
	// false otherwise.
	OnICMPEchoResponseReceived func(*packet.Parsed) bool

	// OnUnmappedTransitIPMessage, if non-nil, is called when a TSMP message is
	// received indicating that a packet was rejected by a connector due to a
	// missing transit IP->real IP mapping.
	OnUnmappedTransitIPMessage func(packet.TailscaleRejectedHeader)

	// PeerAPIPort, if non-nil, returns the peerapi port that's
	// running for the given IP address.
	PeerAPIPort func(netip.Addr) (port uint16, ok bool)

	// disableFilter disables all filtering when set. This should only be used in tests.
	disableFilter bool

	// disableTSMPRejected disables TSMP rejected responses. For tests.
	disableTSMPRejected bool

	// connCounter maintains per-connection counters.
	connCounter syncs.AtomicValue[netlogfunc.ConnectionCounter]

	captureHook syncs.AtomicValue[packet.CaptureCallback]

	metrics *metrics

	eventClient              *eventbus.Client
	discoKeyAdvertisementPub *eventbus.Publisher[events.DiscoKeyAdvertisement]

	// tunDevStatsCloser closes TUN device stats polling. It may be nil if
	// [HookPollTUNDevStats] is unset, or the hook func returned an error.
	tunDevStatsCloser io.Closer
}

type metrics struct {
	inboundDroppedPacketsTotal  *usermetric.MultiLabelMap[usermetric.DropLabels]
	outboundDroppedPacketsTotal *usermetric.MultiLabelMap[usermetric.DropLabels]
}

func registerMetrics(reg *usermetric.Registry) *metrics {
	return &metrics{
		inboundDroppedPacketsTotal:  reg.DroppedPacketsInbound(),
		outboundDroppedPacketsTotal: reg.DroppedPacketsOutbound(),
	}
}

// tunInjectedRead is an injected packet pretending to be a tun.Read().
type tunInjectedRead struct {
	// Only one of packet or data should be set, and are read in that order of
	// precedence.
	packet *netstack_PacketBuffer
	data   []byte
}

// tunVectorReadResult is the result of a [tun.Device.Read], or an injected
// packet pretending to be a [tun.Device.Read].
type tunVectorReadResult struct {
	// isInjected indicates if tunVectorReadResult contains a "real" [tun.Device.Read]
	// result, or an injected packet. When true, injected will be set with meaningful
	// data, otherwise real will be set with meaningful data.
	isInjected bool
	// Result consumer ([Wrapper.Read]) must call a non-nil doneHandlingFn when
	// they are done with the result. The consumer must not access [tunVectorReadResult]
	// fields once this func has been called, as it provides synchronization
	// around shared memory.
	doneHandlingFn func()

	real struct {
		err     error
		slab    []byte
		packets []tun.ReadPacket
	}
	injected tunInjectedRead
}

// Start unblocks any Wrapper.Read calls that have already started
// and makes the Wrapper functional.
//
// Start must be called exactly once after the various Tailscale
// subsystems have been wired up to each other.
func (w *Wrapper) Start() {
	w.started.Store(true)
	close(w.startCh)
}

func WrapTAP(logf logger.Logf, tdev tun.Device, m *usermetric.Registry, bus *eventbus.Bus) *Wrapper {
	return wrap(logf, tdev, true, m, bus)
}

func Wrap(logf logger.Logf, tdev tun.Device, m *usermetric.Registry, bus *eventbus.Bus) *Wrapper {
	return wrap(logf, tdev, false, m, bus)
}

func wrap(logf logger.Logf, tdev tun.Device, isTAP bool, m *usermetric.Registry, bus *eventbus.Bus) *Wrapper {
	logf = logger.WithPrefix(logf, "tstun: ")
	w := &Wrapper{
		logf:        logf,
		limitedLogf: logger.RateLimitedFn(logf, 1*time.Minute, 2, 10),
		isTAP:       isTAP,
		tdev:        tdev,
		// bufferConsumed is conceptually a condition variable:
		// a goroutine should not block when setting it, even with no listeners.
		bufferConsumed: make(chan struct{}, 1),
		closed:         make(chan struct{}),
		// vectorOutbound can be unbuffered; the buffer is an optimization.
		vectorOutbound: make(chan tunVectorReadResult, 1),
		eventsUpDown:   make(chan tun.Event),
		eventsOther:    make(chan tun.Event),
		// TODO(dmytro): (highly rate-limited) hexdumps should happen on unknown packets.
		filterFlags: filter.LogAccepts | filter.LogDrops,
		startCh:     make(chan struct{}),
		metrics:     registerMetrics(m),
	}

	if buildfeatures.HasTUNDevStats {
		if f, ok := HookPollTUNDevStats.GetOk(); ok {
			closer, err := f(tdev)
			if err != nil {
				w.logf("error initializing tun dev stats polling: %v", err)
			}
			w.tunDevStatsCloser = closer
		}
	}

	w.eventClient = bus.Client("net.tstun")
	w.discoKeyAdvertisementPub = eventbus.Publish[events.DiscoKeyAdvertisement](w.eventClient)

	go w.pumpEvents()
	// The buffer starts out consumed.
	w.bufferConsumed <- struct{}{}
	w.noteActivity()

	return w
}

// HookPollTUNDevStats is the hook maybe set by feature/tundevstats.
var HookPollTUNDevStats feature.Hook[func(dev tun.Device) (io.Closer, error)]

// now returns the current time, either by calling t.timeNow if set or time.Now
// if not.
func (t *Wrapper) now() time.Time {
	if t.timeNow != nil {
		return t.timeNow()
	}
	return time.Now()
}

// SetDiscoKey sets the current discovery key.
//
// It is only used for filtering out bogus traffic when network
// stack(s) get confused; see Issue 1526.
func (t *Wrapper) SetDiscoKey(k key.DiscoPublic) {
	t.discoKey.Store(k)
}

// isSelfDisco reports whether packet p
// looks like a Disco packet from ourselves.
// See Issue 1526.
func (t *Wrapper) isSelfDisco(p *packet.Parsed) bool {
	if p.IPProto != ipproto.UDP {
		return false
	}
	pkt := p.Payload()
	discobs, ok := disco.Source(pkt)
	if !ok {
		return false
	}
	discoSrc := key.DiscoPublicFromRaw32(mem.B(discobs))
	selfDiscoPub := t.discoKey.Load()
	return selfDiscoPub == discoSrc
}

func (t *Wrapper) Close() error {
	var err error
	t.closeOnce.Do(func() {
		if t.started.CompareAndSwap(false, true) {
			close(t.startCh)
		}
		close(t.closed)
		t.bufferConsumedMu.Lock()
		t.bufferConsumedClosed = true
		close(t.bufferConsumed)
		t.bufferConsumedMu.Unlock()
		t.outboundMu.Lock()
		t.outboundClosed = true
		close(t.vectorOutbound)
		t.outboundMu.Unlock()
		err = t.tdev.Close()
		t.eventClient.Close()
		if t.tunDevStatsCloser != nil {
			t.tunDevStatsCloser.Close()
		}
	})
	return err
}

// isClosed reports whether t is closed.
func (t *Wrapper) isClosed() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}

// pumpEvents copies events from t.tdev to t.eventsUpDown and t.eventsOther.
// pumpEvents exits when t.tdev.events or t.closed is closed.
// pumpEvents closes t.eventsUpDown and t.eventsOther when it exits.
func (t *Wrapper) pumpEvents() {
	defer close(t.eventsUpDown)
	defer close(t.eventsOther)
	src := t.tdev.Events()
	for {
		// Retrieve an event from the TUN device.
		var event tun.Event
		var ok bool
		select {
		case <-t.closed:
			return
		case event, ok = <-src:
			if !ok {
				return
			}
		}

		// Pass along event to the correct recipient.
		// Though event is a bitmask, in practice there is only ever one bit set at a time.
		dst := t.eventsOther
		if event&(tun.EventUp|tun.EventDown) != 0 {
			dst = t.eventsUpDown
		}
		select {
		case <-t.closed:
			return
		case dst <- event:
		}
	}
}

// EventsUpDown returns a TUN event channel that contains all Up and Down events.
func (t *Wrapper) EventsUpDown() chan tun.Event {
	return t.eventsUpDown
}

// Events returns a TUN event channel that contains all non-Up, non-Down events.
// It is named Events because it is the set of events that we want to expose to wireguard-go,
// and Events is the name specified by the wireguard-go tun.Device interface.
func (t *Wrapper) Events() <-chan tun.Event {
	return t.eventsOther
}

func (t *Wrapper) File() *os.File {
	return t.tdev.File()
}

func (t *Wrapper) MTU() (int, error) {
	return t.tdev.MTU()
}

func (t *Wrapper) Name() (string, error) {
	return t.tdev.Name()
}

// pollVector polls [Wrapper.tdev.Read], writing the oldest unconsumed packet
// slab and packet descriptors into the [Wrapper.vectorOutbound] channel.
// slabLen and packetsLen should originate from the first call to [Wrapper.Read],
// and are used for sizing the equivalent arguments pollVector passes to
// [Wrapper.tdev.Read].
//
// [Wrapper.tdev.Read] can block, so we poll tdev in a goroutine independent of
// wireguard-go's calls to [Wrapper.Read], in order to support native tdev reads
// alongside packets we inject.
//
// pollVector returns when [t.bufferConsumed] is closed, or when [Wrapper.isClosed]
// returns true.
func (t *Wrapper) pollVector(slabLen, packetsLen int) {
	slab := make([]byte, slabLen)
	packets := make([]tun.ReadPacket, packetsLen)
	for range t.bufferConsumed {
		var n int
		var err error
		for n == 0 && err == nil {
			if t.isClosed() {
				return
			}
			n, err = t.tdev.Read(slab, packets)
			if t.isTAP && TAPDebug {
				s := fmt.Sprintf("% x", slab)
				for strings.HasSuffix(s, " 00") {
					s = strings.TrimSuffix(s, " 00")
				}
				t.logf("TAP read %v, %v: %s", n, err, s)
			}
		}
		t.sendVectorOutbound(tunVectorReadResult{
			isInjected:     false,
			doneHandlingFn: t.sendBufferConsumed,
			real: struct {
				err     error
				slab    []byte
				packets []tun.ReadPacket
			}{err: err, slab: slab, packets: packets[:n]},
		})
	}
}

// sendBufferConsumed does t.bufferConsumed <- struct{}{}.
func (t *Wrapper) sendBufferConsumed() {
	t.bufferConsumedMu.Lock()
	defer t.bufferConsumedMu.Unlock()
	if t.bufferConsumedClosed {
		return
	}
	t.bufferConsumed <- struct{}{}
}

// injectOutbound does t.vectorOutbound <- r
func (t *Wrapper) injectOutbound(r tunInjectedRead) {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	if t.outboundClosed {
		return
	}
	select {
	case t.vectorOutbound <- tunVectorReadResult{injected: r, isInjected: true}:
	case <-t.closed:
	}
}

// sendVectorOutbound does t.vectorOutbound <- r.
func (t *Wrapper) sendVectorOutbound(r tunVectorReadResult) {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	if t.outboundClosed {
		return
	}
	select {
	case t.vectorOutbound <- r:
	case <-t.closed:
	}
}

// snat does SNAT on p if the destination address requires a different source address.
// snat never mutates packet length or IP address family.
func (pc *peerConfigTable) snat(p *packet.Parsed) {
	oldSrc := p.Src.Addr()
	newSrc := pc.selectSrcIP(oldSrc, p.Dst.Addr())
	if oldSrc != newSrc {
		checksum.UpdateSrcAddr(p, newSrc)
	}
}

// dnat does destination NAT on p. dnat never mutates packet length or IP address
// family.
func (pc *peerConfigTable) dnat(p *packet.Parsed) {
	oldDst := p.Dst.Addr()
	newDst := pc.mapDstIP(p.Src.Addr(), oldDst)
	if newDst != oldDst {
		checksum.UpdateDstAddr(p, newDst)
	}
}

// peerConfigTable contains the per-peer route attributes and related
// information necessary to perform peer-specific operations. It should
// be treated as immutable.
//
// The nil value is a valid configuration.
type peerConfigTable struct {
	// nativeAddr4 and nativeAddr6 are the IPv4/IPv6 Tailscale Addresses of
	// the current node.
	//
	// These are implicitly used as the address to rewrite to in the DNAT
	// path (as configured by listenAddrs, below). The IPv4 address will be
	// used if the inbound packet is IPv4, and the IPv6 address if the
	// inbound packet is IPv6.
	nativeAddr4, nativeAddr6 netip.Addr

	// byIP maps a peer's IP addresses and routed prefixes to the
	// peer's route attributes. It is a shared immutable snapshot
	// from [routemanager.RouteManager.Outbound].
	byIP *bart.Table[*routemanager.PeerRoute]
}

func (c *peerConfigTable) String() string {
	if c == nil {
		return "peerConfigTable(nil)"
	}
	return fmt.Sprintf("peerConfigTable{nativeAddr4: %v, nativeAddr6: %v}", c.nativeAddr4, c.nativeAddr6)
}

// mapDstIP returns the destination IP to use for a packet to dst.
// If dst is not one of the listen addresses, it is returned as-is,
// otherwise the native address is returned.
func (pc *peerConfigTable) mapDstIP(src, oldDst netip.Addr) netip.Addr {
	if pc == nil {
		return oldDst
	}

	// The packet we're processing is inbound from WireGuard, received from
	// a peer. The 'src' of the packet is the remote peer's IP address,
	// possibly the masqueraded address (if the peer is shared/etc.).
	//
	// The 'dst' of the packet is the address for this local node. It could
	// be a masquerade address that we told other nodes to use, or one of
	// our local node's Addresses.
	c, ok := pc.byIP.Lookup(src)
	if !ok {
		return oldDst
	}

	if oldDst.Is4() && pc.nativeAddr4.IsValid() && c.MasqAddr4 == oldDst {
		return pc.nativeAddr4
	}
	if oldDst.Is6() && pc.nativeAddr6.IsValid() && c.MasqAddr6 == oldDst {
		return pc.nativeAddr6
	}
	return oldDst
}

// selectSrcIP returns the source IP to use for a packet to dst.
// If the packet is not from the native address, it is returned as-is.
func (pc *peerConfigTable) selectSrcIP(oldSrc, dst netip.Addr) netip.Addr {
	if pc == nil {
		return oldSrc
	}

	// If this packet doesn't originate from this Tailscale node, don't
	// SNAT it (e.g. if we're a subnet router).
	if oldSrc.Is4() && oldSrc != pc.nativeAddr4 {
		return oldSrc
	}
	if oldSrc.Is6() && oldSrc != pc.nativeAddr6 {
		return oldSrc
	}

	// Look up the configuration for the destination
	c, ok := pc.byIP.Lookup(dst)
	if !ok {
		return oldSrc
	}

	// Perform SNAT based on the address family and whether we have a valid
	// addr.
	if oldSrc.Is4() && c.MasqAddr4.IsValid() {
		return c.MasqAddr4
	}
	if oldSrc.Is6() && c.MasqAddr6.IsValid() {
		return c.MasqAddr6
	}

	// No SNAT; use old src
	return oldSrc
}

func (pc *peerConfigTable) inboundPacketIsJailed(p *packet.Parsed) bool {
	if pc == nil {
		return false
	}
	c, ok := pc.byIP.Lookup(p.Src.Addr())
	if !ok {
		return false
	}
	return c.Jailed
}

func (pc *peerConfigTable) outboundPacketIsJailed(p *packet.Parsed) bool {
	if pc == nil {
		return false
	}
	c, ok := pc.byIP.Lookup(p.Dst.Addr())
	if !ok {
		return false
	}
	return c.Jailed
}

// SetIPer is the interface expected to be implemented by the TAP implementation
// of tun.Device.
type SetIPer interface {
	// SetIP sets the IP addresses of the TAP device.
	SetIP(ipV4, ipV6 netip.Addr) error
}

// SetWGConfig is called when a new NetworkMap is received. Its only
// remaining job is updating the TAP device's IP addresses; the
// per-peer route attributes arrive via [Wrapper.SetPeerRoutes].
func (t *Wrapper) SetWGConfig(wcfg *wgcfg.Config) {
	if t.isTAP {
		if sip, ok := t.tdev.(SetIPer); ok {
			sip.SetIP(tsaddr.FirstTailscaleAddrs(slices.All(wcfg.Addresses)))
		}
	}
}

// SetPeerRoutes is called whenever this node's Tailscale addresses or
// the route manager's outbound table change. native4 and native6 are
// this node's own Tailscale addresses, and routes maps each peer's
// addresses and routed prefixes to its route attributes.
//
// A nil routes table disables all per-packet peer processing (NAT
// rewrites and jailed-filter selection); callers pass nil when no
// current peer has any such attributes, which keeps the common
// per-packet path to a nil check.
//
// Unchanged values are a cheap no-op, so callers can call it
// unconditionally whenever the inputs might have changed: the routes
// table is an immutable snapshot whose pointer identity means its
// contents are unchanged.
func (t *Wrapper) SetPeerRoutes(native4, native6 netip.Addr, routes *bart.Table[*routemanager.PeerRoute]) {
	var cfg *peerConfigTable
	if routes != nil && (native4.IsValid() || native6.IsValid()) {
		if old := t.peerConfig.Load(); old != nil &&
			old.byIP == routes && old.nativeAddr4 == native4 && old.nativeAddr6 == native6 {
			return
		}
		cfg = &peerConfigTable{
			nativeAddr4: native4,
			nativeAddr6: native6,
			byIP:        routes,
		}
	} else if t.peerConfig.Load() == nil {
		// Uninstalling (cfg stays nil) over an already-nil config;
		// skip the Swap and its transition logging below.
		return
	}
	old := t.peerConfig.Swap(cfg)
	// Log only on nil-ness or native address transitions; the routes
	// table changes with every routing update and is too chatty to log.
	if (old == nil) != (cfg == nil) ||
		(old != nil && (old.nativeAddr4 != cfg.nativeAddr4 || old.nativeAddr6 != cfg.nativeAddr6)) {
		t.logf("peer config: %v", cfg)
	}
}

var (
	magicDNSIPPort   = netip.AddrPortFrom(tsaddr.TailscaleServiceIP(), 0) // 100.100.100.100:0
	magicDNSIPPortv6 = netip.AddrPortFrom(tsaddr.TailscaleServiceIPv6(), 0)
)

func (t *Wrapper) filterPacketOutboundToWireGuard(p *packet.Parsed, pc *peerConfigTable, gro *gro.GRO) (filter.Response, *gro.GRO) {
	// Fake ICMP echo responses to MagicDNS (100.100.100.100).
	if p.IsEchoRequest() {
		switch p.Dst {
		case magicDNSIPPort:
			header := p.ICMP4Header()
			header.ToResponse()
			outp := packet.Generate(&header, p.Payload())
			t.InjectInboundCopy(outp)
			return filter.DropSilently, gro // don't pass on to OS; already handled
		case magicDNSIPPortv6:
			header := p.ICMP6Header()
			header.ToResponse()
			outp := packet.Generate(&header, p.Payload())
			t.InjectInboundCopy(outp)
			return filter.DropSilently, gro // don't pass on to OS; already handled
		}
	}

	// TSMP traffic should only originate from tailscaled, not from the host
	// itself.
	if p.IPProto == ipproto.TSMP {
		t.limitedLogf("[unexpected] received TSMP out packet over tstun; dropping")
		metricPacketOutDropTSMP.Add(1)
		return filter.DropSilently, gro
	}

	// Issue 1526 workaround: if we sent disco packets over
	// Tailscale from ourselves, then drop them, as that shouldn't
	// happen unless a networking stack is confused, as it seems
	// macOS in Network Extension mode might be.
	if p.IPProto == ipproto.UDP && // disco is over UDP; avoid isSelfDisco call for TCP/etc
		t.isSelfDisco(p) {
		t.limitedLogf("[unexpected] received self disco out packet over tstun; dropping")
		metricPacketOutDropSelfDisco.Add(1)
		return filter.DropSilently, gro
	}

	if t.PreFilterPacketOutboundToWireGuardNetstackIntercept != nil {
		var res filter.Response
		res, gro = t.PreFilterPacketOutboundToWireGuardNetstackIntercept(p, t, gro)
		if res.IsDrop() {
			// Handled by netstack.Impl.handleLocalPackets (quad-100 DNS primarily)
			return res, gro
		}
	}
	if t.PreFilterPacketOutboundToWireGuardEngineIntercept != nil {
		if res := t.PreFilterPacketOutboundToWireGuardEngineIntercept(p, t); res.IsDrop() {
			// Handled by userspaceEngine.handleLocalPackets (primarily handles
			// quad-100 if netstack is not installed).
			return res, gro
		}
	}
	if t.PreFilterPacketOutboundToWireGuardAppConnectorIntercept != nil {
		if res := t.PreFilterPacketOutboundToWireGuardAppConnectorIntercept(p, t); res.IsDrop() {
			// Handled by userspaceEngine's configured hook for Connectors 2025 app connectors.
			return res, gro
		}
	}

	// If the outbound packet is to a jailed peer, use our jailed peer
	// packet filter.
	var filt *filter.Filter
	if pc.outboundPacketIsJailed(p) {
		filt = t.jailedFilter.Load()
	} else {
		filt = t.filter.Load()
	}
	if filt == nil {
		return filter.Drop, gro
	}

	if resp, reason := filt.RunOut(p, t.filterFlags); resp != filter.Accept {
		metricPacketOutDropFilter.Add(1)
		if reason != "" {
			t.metrics.outboundDroppedPacketsTotal.Add(usermetric.DropLabels{
				Reason: reason,
			}, 1)
		}
		return filter.Drop, gro
	}

	if t.PostFilterPacketOutboundToWireGuard != nil {
		if res := t.PostFilterPacketOutboundToWireGuard(p, t); res.IsDrop() {
			return res, gro
		}
	}
	return filter.Accept, gro
}

// noteActivity records that there was a read or write at the current time.
func (t *Wrapper) noteActivity() {
	t.lastActivityAtomic.StoreAtomic(mono.Now())
}

// IdleDuration reports how long it's been since the last read or write to this device.
//
// Its value should only be presumed accurate to roughly 10ms granularity.
// If there's never been activity, the duration is since the wrapper was created.
func (t *Wrapper) IdleDuration() time.Duration {
	return mono.Since(t.lastActivityAtomic.LoadAtomic())
}

// ProbeLocks acquires and releases Wrapper's internal mutexes.
func (t *Wrapper) ProbeLocks() {
	t.bufferConsumedMu.Lock()
	t.bufferConsumedMu.Unlock()

	t.outboundMu.Lock()
	t.outboundMu.Unlock()
}

func (t *Wrapper) awaitStart() {
	for {
		select {
		case <-t.startCh:
			return
		case <-time.After(1 * time.Second):
			// Multiple times while remixing tailscaled I (Brad) have forgotten
			// to call Start and then wasted far too much time debugging.
			// I do not wish that debugging on anyone else. Hopefully this'll help:
			t.logf("tstun: awaiting Wrapper.Start call")
		}
	}
}

// Read implements [tun.Device.Read].
func (t *Wrapper) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if !t.started.Load() {
		t.awaitStart()
	}
	t.startPollingOnce.Do(func() {
		go t.pollVector(len(slab), len(packets))
	})
	// packet from OS read and sent to WG
	res, ok := <-t.vectorOutbound
	if !ok {
		return 0, io.EOF
	}
	defer func() {
		if res.doneHandlingFn != nil {
			res.doneHandlingFn()
		}
	}()
	if res.isInjected {
		return t.injectedRead(res.injected, slab, packets, tun.ReadPacketSpacing)
	}
	if res.real.err != nil && len(res.real.packets) == 0 {
		return 0, res.real.err
	}

	metricPacketOut.Add(int64(len(res.real.packets)))

	var numPackets int
	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	captHook := t.captureHook.Load()
	pc := t.peerConfig.Load()
	var buffsGRO *gro.GRO
	for _, meta := range res.real.packets {
		data := res.real.slab[meta.Offset : meta.Offset+meta.Size]
		p.Decode(data)

		if buildfeatures.HasCapture && captHook != nil {
			captHook(packet.FromLocal, t.now(), p.Buffer(), p.CaptureMeta)
		}
		if !t.disableFilter {
			var response filter.Response
			response, buffsGRO = t.filterPacketOutboundToWireGuard(p, pc, buffsGRO)
			if response != filter.Accept {
				metricPacketOutDrop.Add(1)
				continue
			}
		}
		if buildfeatures.HasNetLog {
			if update := t.connCounter.Load(); update != nil {
				updateConnCounter(update, p.Buffer(), false)
			}
		}

		// Make sure to do SNAT after filtering, so that any flow tracking in
		// the filter sees the original source address. See #12133.
		pc.snat(p)
		n := copy(slab[meta.Offset:meta.Offset+meta.Size], p.Buffer())
		if n != len(data) {
			panic(fmt.Sprintf("short copy: %d != %d", n, len(data)))
		}
		packets[numPackets] = meta
		numPackets++
	}
	if buffsGRO != nil {
		buffsGRO.Flush()
	}

	t.noteActivity()
	return numPackets, res.real.err
}

const (
	minTCPHeaderSize = 20
)

func stackGSOToTunGSO(pkt []byte, gso netstack_GSO) (tun.GSOOptions, error) {
	if !buildfeatures.HasNetstack {
		panic("unreachable")
	}
	options := tun.GSOOptions{
		CsumStart:  gso.L3HdrLen,
		CsumOffset: gso.CsumOffset,
		GSOSize:    gso.MSS,
		NeedsCsum:  gso.NeedsCsum,
	}
	switch gso.Type {
	case netstack_GSONone:
		options.GSOType = tun.GSONone
		return options, nil
	case netstack_GSOTCPv4:
		options.GSOType = tun.GSOTCPv4
	case netstack_GSOTCPv6:
		options.GSOType = tun.GSOTCPv6
	default:
		return tun.GSOOptions{}, fmt.Errorf("unsupported gVisor GSOType: %v", gso.Type)
	}
	// options.HdrLen is both layer 3 and 4 together, whereas gVisor only
	// gives us layer 3 length. We have to gather TCP header length
	// ourselves.
	if len(pkt) < int(gso.L3HdrLen)+minTCPHeaderSize {
		return tun.GSOOptions{}, errors.New("gVisor GSOTCP packet length too short")
	}
	tcphLen := uint16(pkt[int(gso.L3HdrLen)+12] >> 4 * 4)
	options.HdrLen = gso.L3HdrLen + tcphLen
	return options, nil
}

// invertGSOChecksum inverts the transport layer checksum in pkt if gVisor
// handed us a segment with a partial checksum. A partial checksum is not a
// ones' complement of the sum, and incremental checksum updating is not yet
// partial checksum aware. This may be called twice for a single packet,
// both before and after partial checksum updates where later checksum
// offloading still expects a partial checksum.
// TODO(jwhited): plumb partial checksum awareness into net/packet/checksum.
func invertGSOChecksum(pkt []byte, gso netstack_GSO) {
	if !buildfeatures.HasNetstack {
		panic("unreachable")
	}
	if gso.NeedsCsum != true {
		return
	}
	at := int(gso.L3HdrLen + gso.CsumOffset)
	if at+1 > len(pkt)-1 {
		return
	}
	pkt[at] = ^pkt[at]
	pkt[at+1] = ^pkt[at+1]
}

// injectedRead handles injected reads. Injected packets bypass the outbound
// filter rules, but UDP/SCTP flow state is still recorded via
// [filter.Filter.UpdateOutboundFlowState] so inbound replies are admitted by
// [filter.Filter.RunIn].
func (t *Wrapper) injectedRead(res tunInjectedRead, slab []byte, packets []tun.ReadPacket, spacing int) (n int, err error) {
	var gso netstack_GSO

	pkt := slab[spacing : len(slab)-spacing]
	if res.packet != nil {
		if !buildfeatures.HasNetstack {
			panic("unreachable")
		}
		bufN := copy(pkt, res.packet.NetworkHeader().Slice())
		bufN += copy(pkt[bufN:], res.packet.TransportHeader().Slice())
		bufN += copy(pkt[bufN:], res.packet.Data().AsRange().ToSlice())
		gso = res.packet.GSOOptions
		pkt = pkt[:bufN]
		defer res.packet.DecRef() // defer DecRef so we may continue to reference it
	} else {
		packets[0] = tun.ReadPacket{
			Offset: spacing,
			Size:   copy(pkt, res.data),
		}
		pkt = pkt[:packets[0].Size]
		n = 1
	}

	pc := t.peerConfig.Load()

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	p.Decode(pkt)

	// Record reverse-flow connection-tracking state for this outbound packet so
	// that inbound replies are admitted by the filter. Injected packets bypass
	// the regular RunOut path that records this state for UDP/SCTP flows; doing
	// it here keeps userspace-networking and tsnet UDP replies from being
	// dropped as "no matching rule". This must run before SNAT so the tracked
	// tuple matches what RunIn sees after DNAT on the inbound side. Select
	// between the normal and jailed filters the same way
	// filterPacketOutboundToWireGuard does, so jailed peers (e.g. Mullvad exit
	// nodes) record state on the filter that will run on the reply. See #14229
	// and #20064.
	if !t.disableFilter {
		var filt *filter.Filter
		if pc.outboundPacketIsJailed(p) {
			filt = t.jailedFilter.Load()
		} else {
			filt = t.filter.Load()
		}
		if filt != nil {
			filt.UpdateOutboundFlowState(p)
		}
	}

	invertGSOChecksum(pkt, gso)
	// Check if this is a packet for conn25-style app connectors,
	// and perform the necessary NAT. The main case that requires
	// NAT from netstack toward WireGuard is an SNAT on return traffic
	// from the target application on the internet, translating
	// the original server's source IP to the TransitIP.
	// The hook can also perform DNAT for client-originated traffic,
	// translating the destination MagicIP to a TransitIP, and rejects
	// MagicIPs that have not been approved for the client.
	//
	// Normal non-connector traffic is forwarded unmodified.
	//
	// Cross-tailnet conn25 app connector connections are not supported,
	// so at most one of this hook and the following pc.snat should modify the packet.
	if t.PreFilterPacketOutboundToWireGuardAppConnectorIntercept != nil {
		if r := t.PreFilterPacketOutboundToWireGuardAppConnectorIntercept(p, t); r.IsDrop() {
			metricPacketOut.Add(1)
			metricPacketOutDrop.Add(1)
			return 0, nil
		}
	}
	pc.snat(p)
	invertGSOChecksum(pkt, gso)

	if res.packet != nil {
		var gsoOptions tun.GSOOptions
		gsoOptions, err = stackGSOToTunGSO(pkt, gso)
		if err != nil {
			return 0, err
		}
		n, err = tun.GSOSplit(pkt, gsoOptions, slab, packets, spacing)
	}

	if buildfeatures.HasNetLog {
		if update := t.connCounter.Load(); update != nil {
			for i := 0; i < n; i++ {
				start := packets[i].Offset
				end := packets[i].Offset + packets[i].Size
				updateConnCounter(update, slab[start:end], false)
			}
		}
	}

	t.noteActivity()
	metricPacketOut.Add(int64(n))
	return n, err
}

func (t *Wrapper) filterPacketInboundFromWireGuard(p *packet.Parsed, captHook packet.CaptureCallback, pc *peerConfigTable, gro *gro.GRO) (filter.Response, *gro.GRO) {
	if captHook != nil {
		captHook(packet.FromPeer, t.now(), p.Buffer(), p.CaptureMeta)
	}

	if p.IPProto == ipproto.TSMP {
		if pingReq, ok := p.AsTSMPPing(); ok {
			t.noteActivity()
			t.injectOutboundPong(p, pingReq)
			return filter.DropSilently, gro
		} else if discoKeyAdvert, ok := p.AsTSMPDiscoAdvertisement(); ok {
			if !discoKeyAdvert.Key.IsZero() {
				t.discoKeyAdvertisementPub.Publish(events.DiscoKeyAdvertisement{
					Src: discoKeyAdvert.Src,
					Key: discoKeyAdvert.Key,
				})
			}
			return filter.DropSilently, gro
		} else if data, ok := p.AsTSMPPong(); ok {
			if f := t.OnTSMPPongReceived; f != nil {
				f(data)
			}
		} else if data, ok := p.AsTailscaleRejectedHeader(); ok {
			if data.Reason == packet.RejectedDueToUnknownAppConnectorTransitIP {
				if f := t.OnUnmappedTransitIPMessage; f != nil {
					f(data)
				}
			}
		}
	}

	if p.IsEchoResponse() {
		if f := t.OnICMPEchoResponseReceived; f != nil && f(p) {
			// Note: this looks dropped in metrics, even though it was
			// handled internally.
			return filter.DropSilently, gro
		}
	}

	// Issue 1526 workaround: if we see disco packets over
	// Tailscale from ourselves, then drop them, as that shouldn't
	// happen unless a networking stack is confused, as it seems
	// macOS in Network Extension mode might be.
	if p.IPProto == ipproto.UDP && // disco is over UDP; avoid isSelfDisco call for TCP/etc
		t.isSelfDisco(p) {
		t.limitedLogf("[unexpected] received self disco in packet over tstun; dropping")
		metricPacketInDropSelfDisco.Add(1)
		return filter.DropSilently, gro
	}

	if t.PreFilterPacketInboundFromWireGuard != nil {
		if res := t.PreFilterPacketInboundFromWireGuard(p, t); res.IsDrop() {
			return res, gro
		}
	}

	var filt *filter.Filter
	if pc.inboundPacketIsJailed(p) {
		filt = t.jailedFilter.Load()
	} else {
		filt = t.filter.Load()
	}
	if filt == nil {
		return filter.Drop, gro
	}
	outcome := filt.RunIn(p, t.filterFlags)

	// Let peerapi through the filter; its ACLs are handled at L7,
	// not at the packet level.
	if outcome != filter.Accept &&
		p.IPProto == ipproto.TCP &&
		p.TCPFlags&packet.TCPSyn != 0 &&
		t.PeerAPIPort != nil {
		if port, ok := t.PeerAPIPort(p.Dst.Addr()); ok && port == p.Dst.Port() {
			outcome = filter.Accept
		}
	}

	if outcome != filter.Accept {
		metricPacketInDropFilter.Add(1)
		t.metrics.inboundDroppedPacketsTotal.Add(usermetric.DropLabels{
			Reason: usermetric.ReasonACL,
		}, 1)

		// Tell them, via TSMP, we're dropping them due to the ACL.
		// Their host networking stack can translate this into ICMP
		// or whatnot as required. But notably, their GUI or tailscale CLI
		// can show them a rejection history with reasons.
		if p.IPVersion == 4 && p.IPProto == ipproto.TCP && p.TCPFlags&packet.TCPSyn != 0 && !t.disableTSMPRejected {
			rj := packet.TailscaleRejectedHeader{
				IPSrc:  p.Dst.Addr(),
				IPDst:  p.Src.Addr(),
				Src:    p.Src,
				Dst:    p.Dst,
				Proto:  p.IPProto,
				Reason: packet.RejectedDueToACLs,
			}
			if filt.ShieldsUp() {
				rj.Reason = packet.RejectedDueToShieldsUp
			}
			pkt := packet.Generate(rj, nil)
			t.InjectOutbound(pkt)

			// TODO(bradfitz): also send a TCP RST, after the TSMP message.
		}

		return filter.Drop, gro
	}

	if t.PostFilterPacketInboundFromWireGuardAppConnector != nil {
		if res := t.PostFilterPacketInboundFromWireGuardAppConnector(p, t); res.IsDrop() {
			// Handled by userspaceEngine's configured hook for Connectors 2025 app connectors.
			return res, gro
		}
	}

	if t.PostFilterPacketInboundFromWireGuard != nil {
		var res filter.Response
		res, gro = t.PostFilterPacketInboundFromWireGuard(p, t, gro)
		if res.IsDrop() {
			return res, gro
		}
	}

	return filter.Accept, gro
}

// Write accepts incoming packets. The packets begin at buffs[:][offset:],
// like wireguard-go/tun.Device.Write. Write is called per-peer via
// wireguard-go/device.Peer.RoutineSequentialReceiver, so it MUST be
// thread-safe.
func (t *Wrapper) Write(buffs [][]byte, offset int) (int, error) {
	metricPacketIn.Add(int64(len(buffs)))
	i := 0
	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	captHook := t.captureHook.Load()
	pc := t.peerConfig.Load()
	var buffsGRO *gro.GRO
	for _, buff := range buffs {
		p.Decode(buff[offset:])
		pc.dnat(p)
		if !t.disableFilter {
			var res filter.Response
			// TODO(jwhited): name and document this filter code path
			//  appropriately. It is not only responsible for filtering, it
			//  also routes packets towards gVisor/netstack.
			res, buffsGRO = t.filterPacketInboundFromWireGuard(p, captHook, pc, buffsGRO)
			if res != filter.Accept {
				metricPacketInDrop.Add(1)
			} else {
				buffs[i] = buff
				i++
			}
		}
	}
	if buffsGRO != nil {
		buffsGRO.Flush()
	}
	if t.disableFilter {
		i = len(buffs)
	}
	buffs = buffs[:i]

	if len(buffs) > 0 {
		t.noteActivity()
		_, err := t.tdevWrite(buffs, offset)
		if err != nil {
			t.metrics.inboundDroppedPacketsTotal.Add(usermetric.DropLabels{
				Reason: usermetric.ReasonError,
			}, int64(len(buffs)))
		}
		return len(buffs), err
	}
	return 0, nil
}

func (t *Wrapper) tdevWrite(buffs [][]byte, offset int) (int, error) {
	if buildfeatures.HasNetLog {
		if update := t.connCounter.Load(); update != nil {
			for i := range buffs {
				updateConnCounter(update, buffs[i][offset:], true)
			}
		}
	}
	return t.tdev.Write(buffs, offset)
}

func (t *Wrapper) GetFilter() *filter.Filter {
	return t.filter.Load()
}

func (t *Wrapper) SetFilter(filt *filter.Filter) {
	t.filter.Store(filt)
}

func (t *Wrapper) GetJailedFilter() *filter.Filter {
	return t.jailedFilter.Load()
}

func (t *Wrapper) SetJailedFilter(filt *filter.Filter) {
	t.jailedFilter.Store(filt)
}

// InjectInboundPacketBuffer makes the [Wrapper] device behave as if a packet
// (pkt) with the given contents was received from the network.
// It takes ownership of one reference count on pkt. The injected
// packet will not pass through inbound filters.
//
// pkt will be copied into slab, and potentially GSO split, before writing to
// the underlying [tun.Device]. Therefore, callers must allocate and pass a slab
// slice that is sized for holding:
//
//	pkt.Data.Size() +
//	(N * network headers len) +
//	((N+1) * [WritePacketStartOffset])
//
// N is 1 when the originating netstack does not support GSO, otherwise N should
// be [conn.IdealBatchSize]. Similarly, callers must pass packets and writeBufs
// sized to N.
//
// [tun.ReadPacket] is the shape required by [tun.GSOSplit], but is
// admittedly confusing in the context of the direction of our eventual
// i/o op, [tun.Device.Write]. This is purely historical, as [tun.GSOSplit]
// was initially only used post-[tun.Device.Read] heading out to the network,
// but we are using it in the opposite direction here.
//
// This path is typically used to deliver synthesized packets to the
// host networking stack.
func (t *Wrapper) InjectInboundPacketBuffer(pkt *netstack_PacketBuffer, slab []byte, packets []tun.ReadPacket, writeBufs [][]byte) error {
	if !buildfeatures.HasNetstack {
		panic("unreachable")
	}
	buf := slab[WritePacketStartOffset:]

	bufN := copy(buf, pkt.NetworkHeader().Slice())
	bufN += copy(buf[bufN:], pkt.TransportHeader().Slice())
	bufN += copy(buf[bufN:], pkt.Data().AsRange().ToSlice())
	if bufN != pkt.Size() {
		panic("unexpected packet size after copy")
	}
	buf = buf[:bufN]
	defer pkt.DecRef()

	pc := t.peerConfig.Load()

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	p.Decode(buf)
	captHook := t.captureHook.Load()
	if captHook != nil {
		captHook(packet.SynthesizedToLocal, t.now(), p.Buffer(), p.CaptureMeta)
	}

	invertGSOChecksum(buf, pkt.GSOOptions)
	pc.dnat(p)
	invertGSOChecksum(buf, pkt.GSOOptions)

	gso, err := stackGSOToTunGSO(buf, pkt.GSOOptions)
	if err != nil {
		return err
	}

	// TODO(jwhited): support GSO passthrough to t.tdev. If t.tdev supports
	//  GSO we don't need to split here and coalesce inside wireguard-go,
	//  we can pass a coalesced segment all the way through.
	n, err := tun.GSOSplit(buf, gso, slab, packets, WritePacketStartOffset)
	if err != nil {
		if errors.Is(err, tun.ErrTooManySegments) {
			t.limitedLogf("InjectInboundPacketBuffer: GSO split overflows buffs")
		} else {
			return err
		}
	}
	for i, meta := range packets[:n] {
		writeBufs[i] = slab[meta.Offset-WritePacketStartOffset : meta.Offset+meta.Size]
	}
	_, err = t.tdevWrite(writeBufs[:n], WritePacketStartOffset)
	return err
}

// InjectInboundDirect makes the Wrapper device behave as if a packet
// with the given contents was received from the network.
// It blocks and does not take ownership of the packet.
// The injected packet will not pass through inbound filters.
//
// The packet contents are to start at &buf[offset].
// offset must be greater or equal to WritePacketStartOffset.
// The space before &buf[offset] will be used by WireGuard.
func (t *Wrapper) InjectInboundDirect(buf []byte, offset int) error {
	if len(buf) > MaxPacketSize {
		return errPacketTooBig
	}
	if len(buf) < offset {
		return errOffsetTooBig
	}
	if offset < WritePacketStartOffset {
		return errOffsetTooSmall
	}

	// Write to the underlying device to skip filters.
	_, err := t.tdevWrite([][]byte{buf}, offset) // TODO(jwhited): alloc?
	return err
}

// InjectInboundCopy takes a packet without leading space,
// reallocates it to conform to the InjectInboundDirect interface
// and calls InjectInboundDirect on it. Injecting a nil packet is a no-op.
func (t *Wrapper) InjectInboundCopy(packet []byte) error {
	// We duplicate this check from InjectInboundDirect here
	// to avoid wasting an allocation on an oversized packet.
	if len(packet) > MaxPacketSize {
		return errPacketTooBig
	}
	if len(packet) == 0 {
		return nil
	}

	buf := make([]byte, WritePacketStartOffset+len(packet))
	copy(buf[WritePacketStartOffset:], packet)

	return t.InjectInboundDirect(buf, WritePacketStartOffset)
}

func (t *Wrapper) injectOutboundPong(pp *packet.Parsed, req packet.TSMPPingRequest) {
	pong := packet.TSMPPongReply{
		Data: req.Data,
	}
	if t.PeerAPIPort != nil {
		pong.PeerAPIPort, _ = t.PeerAPIPort(pp.Dst.Addr())
	}
	switch pp.IPVersion {
	case 4:
		h4 := pp.IP4Header()
		h4.ToResponse()
		pong.IPHeader = h4
	case 6:
		h6 := pp.IP6Header()
		h6.ToResponse()
		pong.IPHeader = h6
	default:
		return
	}

	t.InjectOutbound(packet.Generate(pong, nil))
}

// InjectOutbound makes the Wrapper device behave as if a packet
// with the given contents was sent to the network.
// It does not block, but takes ownership of the packet.
// The injected packet will not pass through outbound filter rules,
// but UDP/SCTP flow state is recorded so inbound replies are admitted.
// Injecting an empty packet is a no-op.
func (t *Wrapper) InjectOutbound(pkt []byte) error {
	if len(pkt) > MaxPacketSize {
		return errPacketTooBig
	}
	if len(pkt) == 0 {
		return nil
	}
	t.injectOutbound(tunInjectedRead{data: pkt})
	return nil
}

// InjectOutboundPacketBuffer logically behaves as InjectOutbound. It takes ownership of one
// reference count on the packet, and the packet may be mutated. The packet refcount will be
// decremented after the injected buffer has been read.
func (t *Wrapper) InjectOutboundPacketBuffer(pkt *netstack_PacketBuffer) error {
	if !buildfeatures.HasNetstack {
		panic("unreachable")
	}
	size := pkt.Size()
	if size > MaxPacketSize {
		pkt.DecRef()
		return errPacketTooBig
	}
	if size == 0 {
		pkt.DecRef()
		return nil
	}
	if capt := t.captureHook.Load(); capt != nil {
		b := pkt.ToBuffer()
		capt(packet.SynthesizedToPeer, t.now(), b.Flatten(), packet.CaptureMeta{})
	}

	t.injectOutbound(tunInjectedRead{packet: pkt})
	return nil
}

func (t *Wrapper) BatchSize() int {
	if runtime.GOOS == "linux" {
		// Always setup Linux to handle vectors, even in the very rare case that
		// the underlying t.tdev returns 1. gVisor GSO is always enabled for
		// Linux, and we cannot make a determination on gVisor usage at
		// wireguard-go.Device startup, which is when this value matters for
		// packet memory init.
		return conn.IdealBatchSize
	}
	return t.tdev.BatchSize()
}

// Unwrap returns the underlying tun.Device.
func (t *Wrapper) Unwrap() tun.Device {
	return t.tdev
}

// SetConnectionCounter specifies a per-connection statistics aggregator.
// Nil may be specified to disable statistics gathering.
func (t *Wrapper) SetConnectionCounter(fn netlogfunc.ConnectionCounter) {
	if buildfeatures.HasNetLog {
		t.connCounter.Store(fn)
	}
}

var (
	metricPacketIn              = clientmetric.NewCounter("tstun_in_from_wg")
	metricPacketInDrop          = clientmetric.NewCounter("tstun_in_from_wg_drop")
	metricPacketInDropFilter    = clientmetric.NewCounter("tstun_in_from_wg_drop_filter")
	metricPacketInDropSelfDisco = clientmetric.NewCounter("tstun_in_from_wg_drop_self_disco")

	metricPacketOut              = clientmetric.NewCounter("tstun_out_to_wg")
	metricPacketOutDrop          = clientmetric.NewCounter("tstun_out_to_wg_drop")
	metricPacketOutDropFilter    = clientmetric.NewCounter("tstun_out_to_wg_drop_filter")
	metricPacketOutDropSelfDisco = clientmetric.NewCounter("tstun_out_to_wg_drop_self_disco")
	metricPacketOutDropTSMP      = clientmetric.NewCounter("tstun_out_to_wg_drop_tsmp")
)

func (t *Wrapper) InstallCaptureHook(cb packet.CaptureCallback) {
	if !buildfeatures.HasCapture {
		return
	}
	t.captureHook.Store(cb)
}

func updateConnCounter(update netlogfunc.ConnectionCounter, b []byte, receive bool) {
	var p packet.Parsed
	p.Decode(b)
	if receive {
		update(p.IPProto, p.Dst, p.Src, 1, len(b), true)
	} else {
		update(p.IPProto, p.Src, p.Dst, 1, len(b), false)
	}
}
