// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tstun provides a TUN struct implementing the tun.Device interface
// with additional features as required by wgengine.
package tstun

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/mem"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/disco"
	"tailscale.com/net/connstats"
	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
	"tailscale.com/net/tsaddr"
	"tailscale.com/syncs"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/capture"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/wgcfg"
)

const maxBufferSize = device.MaxMessageSize

// PacketStartOffset is the minimal amount of leading space that must exist
// before &packet[offset] in a packet passed to Read, Write, or InjectInboundDirect.
// This is necessary to avoid reallocation in wireguard-go internals.
const PacketStartOffset = device.MessageTransportHeaderSize

// MaxPacketSize is the maximum size (in bytes)
// of a packet that can be injected into a tstun.Wrapper.
const MaxPacketSize = device.MaxContentSize

const tapDebug = false // for super verbose TAP debugging

var (
	// ErrClosed is returned when attempting an operation on a closed Wrapper.
	ErrClosed = errors.New("device closed")
	// ErrFiltered is returned when the acted-on packet is rejected by a filter.
	ErrFiltered = errors.New("packet dropped by filter")
)

var (
	errPacketTooBig   = errors.New("packet too big")
	errOffsetTooBig   = errors.New("offset larger than buffer length")
	errOffsetTooSmall = errors.New("offset smaller than PacketStartOffset")
)

// parsedPacketPool holds a pool of Parsed structs for use in filtering.
// This is needed because escape analysis cannot see that parsed packets
// do not escape through {Pre,Post}Filter{In,Out}.
var parsedPacketPool = sync.Pool{New: func() any { return new(packet.Parsed) }}

// FilterFunc is a packet-filtering function with access to the Wrapper device.
// It must not hold onto the packet struct, as its backing storage will be reused.
type FilterFunc func(*packet.Parsed, *Wrapper) filter.Response

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

	destIPActivity syncs.AtomicValue[map[netip.Addr]func()]
	//lint:ignore U1000 used in tap_linux.go
	destMACAtomic syncs.AtomicValue[[6]byte]
	discoKey      syncs.AtomicValue[key.DiscoPublic]

	// timeNow, if non-nil, will be used to obtain the current time.
	timeNow func() time.Time

	// natConfig stores the current NAT configuration.
	natConfig atomic.Pointer[natConfig]

	// vectorBuffer stores the oldest unconsumed packet vector from tdev. It is
	// allocated in wrap() and the underlying arrays should never grow.
	vectorBuffer [][]byte
	// bufferConsumedMu protects bufferConsumed from concurrent sends, closes,
	// and send-after-close (by way of bufferConsumedClosed).
	bufferConsumedMu sync.Mutex
	// bufferConsumedClosed is true when bufferConsumed has been closed. This is
	// read by bufferConsumed writers to prevent send-after-close.
	bufferConsumedClosed bool
	// bufferConsumed synchronizes access to vectorBuffer (shared by Read() and
	// pollVector()).
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

	// PreFilterPacketInboundFromWireGuard is the inbound filter function that runs before the main filter
	// and therefore sees the packets that may be later dropped by it.
	PreFilterPacketInboundFromWireGuard FilterFunc
	// PostFilterPacketInboundFromWireGuard is the inbound filter function that runs after the main filter.
	PostFilterPacketInboundFromWireGuard FilterFunc
	// PreFilterPacketOutboundToWireGuardNetstackIntercept is a filter function that runs before the main filter
	// for packets from the local system. This filter is populated by netstack to hook
	// packets that should be handled by netstack. If set, this filter runs before
	// PreFilterFromTunToEngine.
	PreFilterPacketOutboundToWireGuardNetstackIntercept FilterFunc
	// PreFilterPacketOutboundToWireGuardEngineIntercept is a filter function that runs before the main filter
	// for packets from the local system. This filter is populated by wgengine to hook
	// packets which it handles internally. If both this and PreFilterFromTunToNetstack
	// filter functions are non-nil, this filter runs second.
	PreFilterPacketOutboundToWireGuardEngineIntercept FilterFunc
	// PostFilterPacketOutboundToWireGuard is the outbound filter function that runs after the main filter.
	PostFilterPacketOutboundToWireGuard FilterFunc

	// OnTSMPPongReceived, if non-nil, is called whenever a TSMP pong arrives.
	OnTSMPPongReceived func(packet.TSMPPongReply)

	// OnICMPEchoResponseReceived, if non-nil, is called whenever a ICMP echo response
	// arrives. If the packet is to be handled internally this returns true,
	// false otherwise.
	OnICMPEchoResponseReceived func(*packet.Parsed) bool

	// PeerAPIPort, if non-nil, returns the peerapi port that's
	// running for the given IP address.
	PeerAPIPort func(netip.Addr) (port uint16, ok bool)

	// disableFilter disables all filtering when set. This should only be used in tests.
	disableFilter bool

	// disableTSMPRejected disables TSMP rejected responses. For tests.
	disableTSMPRejected bool

	// stats maintains per-connection counters.
	stats atomic.Pointer[connstats.Statistics]

	captureHook syncs.AtomicValue[capture.Callback]
}

// tunInjectedRead is an injected packet pretending to be a tun.Read().
type tunInjectedRead struct {
	// Only one of packet or data should be set, and are read in that order of
	// precedence.
	packet *stack.PacketBuffer
	data   []byte
}

// tunVectorReadResult is the result of a tun.Read(), or an injected packet
// pretending to be a tun.Read().
type tunVectorReadResult struct {
	// When err AND data are nil, injected will be set with meaningful data
	// (injected packet). If either err OR data is non-nil, injected should be
	// ignored (a "real" tun.Read).
	err      error
	data     [][]byte
	injected tunInjectedRead

	dataOffset int
}

type setWrapperer interface {
	// setWrapper enables the underlying TUN/TAP to have access to the Wrapper.
	// It MUST be called only once during initialization, other usage is unsafe.
	setWrapper(*Wrapper)
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

func WrapTAP(logf logger.Logf, tdev tun.Device) *Wrapper {
	return wrap(logf, tdev, true)
}

func Wrap(logf logger.Logf, tdev tun.Device) *Wrapper {
	return wrap(logf, tdev, false)
}

func wrap(logf logger.Logf, tdev tun.Device, isTAP bool) *Wrapper {
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
	}

	w.vectorBuffer = make([][]byte, tdev.BatchSize())
	for i := range w.vectorBuffer {
		w.vectorBuffer[i] = make([]byte, maxBufferSize)
	}
	go w.pollVector()

	go w.pumpEvents()
	// The buffer starts out consumed.
	w.bufferConsumed <- struct{}{}
	w.noteActivity()

	if sw, ok := w.tdev.(setWrapperer); ok {
		sw.setWrapper(w)
	}

	return w
}

// now returns the current time, either by calling t.timeNow if set or time.Now
// if not.
func (t *Wrapper) now() time.Time {
	if t.timeNow != nil {
		return t.timeNow()
	}
	return time.Now()
}

// SetDestIPActivityFuncs sets a map of funcs to run per packet
// destination (the map keys).
//
// The map ownership passes to the Wrapper. It must be non-nil.
func (t *Wrapper) SetDestIPActivityFuncs(m map[netip.Addr]func()) {
	t.destIPActivity.Store(m)
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

const ethernetFrameSize = 14 // 2 six byte MACs, 2 bytes ethertype

// pollVector polls t.tdev.Read(), placing the oldest unconsumed packet vector
// into t.vectorBuffer. This is needed because t.tdev.Read() in general may
// block (it does on Windows), so packets may be stuck in t.vectorOutbound if
// t.Read() called t.tdev.Read() directly.
func (t *Wrapper) pollVector() {
	sizes := make([]int, len(t.vectorBuffer))
	readOffset := PacketStartOffset
	if t.isTAP {
		readOffset = PacketStartOffset - ethernetFrameSize
	}

	for range t.bufferConsumed {
	DoRead:
		for i := range t.vectorBuffer {
			t.vectorBuffer[i] = t.vectorBuffer[i][:cap(t.vectorBuffer[i])]
		}
		var n int
		var err error
		for n == 0 && err == nil {
			if t.isClosed() {
				return
			}
			n, err = t.tdev.Read(t.vectorBuffer[:], sizes, readOffset)
			if t.isTAP && tapDebug {
				s := fmt.Sprintf("% x", t.vectorBuffer[0][:])
				for strings.HasSuffix(s, " 00") {
					s = strings.TrimSuffix(s, " 00")
				}
				t.logf("TAP read %v, %v: %s", n, err, s)
			}
		}
		for i := range sizes[:n] {
			t.vectorBuffer[i] = t.vectorBuffer[i][:readOffset+sizes[i]]
		}
		if t.isTAP {
			if err == nil {
				ethernetFrame := t.vectorBuffer[0][readOffset:]
				if t.handleTAPFrame(ethernetFrame) {
					goto DoRead
				}
			}
			// Fall through. We got an IP packet.
			if sizes[0] >= ethernetFrameSize {
				t.vectorBuffer[0] = t.vectorBuffer[0][:readOffset+sizes[0]-ethernetFrameSize]
			}
			if tapDebug {
				t.logf("tap regular frame: %x", t.vectorBuffer[0][PacketStartOffset:PacketStartOffset+sizes[0]])
			}
		}
		t.sendVectorOutbound(tunVectorReadResult{
			data:       t.vectorBuffer[:n],
			dataOffset: PacketStartOffset,
			err:        err,
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
	t.vectorOutbound <- tunVectorReadResult{
		injected: r,
	}
}

// sendVectorOutbound does t.vectorOutbound <- r.
func (t *Wrapper) sendVectorOutbound(r tunVectorReadResult) {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	if t.outboundClosed {
		return
	}
	t.vectorOutbound <- r
}

// snat does SNAT on p if the destination address requires a different source address.
func (t *Wrapper) snat(p *packet.Parsed) {
	nc := t.natConfig.Load()
	oldSrc := p.Src.Addr()
	newSrc := nc.selectSrcIP(oldSrc, p.Dst.Addr())
	if oldSrc != newSrc {
		checksum.UpdateSrcAddr(p, newSrc)
	}
}

// dnat does destination NAT on p.
func (t *Wrapper) dnat(p *packet.Parsed) {
	nc := t.natConfig.Load()
	oldDst := p.Dst.Addr()
	newDst := nc.mapDstIP(oldDst)
	if newDst != oldDst {
		checksum.UpdateDstAddr(p, newDst)
	}
}

// findV4 returns the first Tailscale IPv4 address in addrs.
func findV4(addrs []netip.Prefix) netip.Addr {
	for _, ap := range addrs {
		a := ap.Addr()
		if a.Is4() && tsaddr.IsTailscaleIP(a) {
			return a
		}
	}
	return netip.Addr{}
}

// findV6 returns the first Tailscale IPv6 address in addrs.
func findV6(addrs []netip.Prefix) netip.Addr {
	for _, ap := range addrs {
		a := ap.Addr()
		if a.Is6() && tsaddr.IsTailscaleIP(a) {
			return a
		}
	}
	return netip.Addr{}
}

// natConfig is the configuration for NAT.
// It should be treated as immutable.
//
// The nil value is a valid configuration.
type natConfig struct {
	v4, v6 *natFamilyConfig
}

func (c *natConfig) String() string {
	if c == nil {
		return "<nil>"
	}

	var b strings.Builder
	b.WriteString("natConfig{")
	fmt.Fprintf(&b, "v4: %v, ", c.v4)
	fmt.Fprintf(&b, "v6: %v", c.v6)
	b.WriteString("}")
	return b.String()
}

// mapDstIP returns the destination IP to use for a packet to dst.
// If dst is not one of the listen addresses, it is returned as-is,
// otherwise the native address is returned.
func (c *natConfig) mapDstIP(oldDst netip.Addr) netip.Addr {
	if c == nil {
		return oldDst
	}
	if oldDst.Is4() {
		return c.v4.mapDstIP(oldDst)
	}
	if oldDst.Is6() {
		return c.v6.mapDstIP(oldDst)
	}
	return oldDst
}

// selectSrcIP returns the source IP to use for a packet to dst.
// If the packet is not from the native address, it is returned as-is.
func (c *natConfig) selectSrcIP(oldSrc, dst netip.Addr) netip.Addr {
	if c == nil {
		return oldSrc
	}
	if oldSrc.Is4() {
		return c.v4.selectSrcIP(oldSrc, dst)
	}
	if oldSrc.Is6() {
		return c.v6.selectSrcIP(oldSrc, dst)
	}
	return oldSrc
}

// natFamilyConfig is the NAT configuration for a particular
// address family.
// It should be treated as immutable.
//
// The nil value is a valid configuration.
type natFamilyConfig struct {
	// nativeAddr is the Tailscale Address of the current node.
	nativeAddr netip.Addr

	// listenAddrs is the set of addresses that should be
	// mapped to the native address. These are the addresses that
	// peers will use to connect to this node.
	listenAddrs views.Map[netip.Addr, struct{}] // masqAddr -> struct{}

	// dstMasqAddrs is the routing table used to map a given dst IP to the
	// respective MasqueradeAsIP address. The MasqueradeAsIP address is the
	// address that should be used as the source address for packets to dst.
	dstMasqAddrs *bart.Table[netip.Addr]

	// masqAddrCounts is a count of peers by MasqueradeAsIP.
	masqAddrCounts map[netip.Addr]int
}

func (c *natFamilyConfig) String() string {
	if c == nil {
		return "natFamilyConfig(nil)"
	}
	var b strings.Builder
	b.WriteString("natFamilyConfig{")
	fmt.Fprintf(&b, "nativeAddr: %v, ", c.nativeAddr)
	fmt.Fprint(&b, "listenAddrs: [")

	i := 0
	c.listenAddrs.Range(func(k netip.Addr, _ struct{}) bool {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(k.String())
		i++
		return true
	})

	i = 0
	b.WriteString("], dstMasqAddrs: [")
	for k, v := range c.masqAddrCounts {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%v: %v peers", k, v)
		i++
	}
	b.WriteString("]}")

	return b.String()
}

// mapDstIP returns the destination IP to use for a packet to dst.
// If dst is not one of the listen addresses, it is returned as-is,
// otherwise the native address is returned.
func (c *natFamilyConfig) mapDstIP(oldDst netip.Addr) netip.Addr {
	if c == nil {
		return oldDst
	}
	if _, ok := c.listenAddrs.GetOk(oldDst); ok {
		return c.nativeAddr
	}
	return oldDst
}

// selectSrcIP returns the source IP to use for a packet to dst.
// If the packet is not from the native address, it is returned as-is.
func (c *natFamilyConfig) selectSrcIP(oldSrc, dst netip.Addr) netip.Addr {
	if c == nil {
		return oldSrc
	}
	if oldSrc != c.nativeAddr {
		return oldSrc
	}
	eip, ok := c.dstMasqAddrs.Get(dst)
	if !ok {
		return oldSrc
	}
	return eip
}

// natConfigFromWGConfig generates a natFamilyConfig from nm,
// for the indicated address family.
// If NAT is not required for that address family, it returns nil.
func natConfigFromWGConfig(wcfg *wgcfg.Config, addrFam ipproto.Version) *natFamilyConfig {
	if wcfg == nil {
		return nil
	}

	var nativeAddr netip.Addr
	switch addrFam {
	case ipproto.Version4:
		nativeAddr = findV4(wcfg.Addresses)
	case ipproto.Version6:
		nativeAddr = findV6(wcfg.Addresses)
	}
	if !nativeAddr.IsValid() {
		return nil
	}

	var (
		rt             bart.Table[netip.Addr]
		masqAddrCounts = map[netip.Addr]int{}
		listenAddrs    set.Set[netip.Addr]
	)

	// When using an exit node that requires masquerading, we need to
	// fill out the routing table with all peers not just the ones that
	// require masquerading.
	exitNodeRequiresMasq := false // true if using an exit node and it requires masquerading
	for _, p := range wcfg.Peers {
		isExitNode := slices.Contains(p.AllowedIPs, tsaddr.AllIPv4()) || slices.Contains(p.AllowedIPs, tsaddr.AllIPv6())
		if isExitNode {
			hasMasqAddrsForFamily := false ||
				(addrFam == ipproto.Version4 && p.V4MasqAddr != nil && p.V4MasqAddr.IsValid()) ||
				(addrFam == ipproto.Version6 && p.V6MasqAddr != nil && p.V6MasqAddr.IsValid())
			if hasMasqAddrsForFamily {
				exitNodeRequiresMasq = true
			}
			break
		}
	}
	for i := range wcfg.Peers {
		p := &wcfg.Peers[i]
		var addrToUse netip.Addr
		if addrFam == ipproto.Version4 && p.V4MasqAddr != nil && p.V4MasqAddr.IsValid() {
			addrToUse = *p.V4MasqAddr
			mak.Set(&listenAddrs, addrToUse, struct{}{})
		} else if addrFam == ipproto.Version6 && p.V6MasqAddr != nil && p.V6MasqAddr.IsValid() {
			addrToUse = *p.V6MasqAddr
			mak.Set(&listenAddrs, addrToUse, struct{}{})
		} else if exitNodeRequiresMasq {
			addrToUse = nativeAddr
		} else {
			continue
		}

		masqAddrCounts[addrToUse]++
		for _, ip := range p.AllowedIPs {
			rt.Insert(ip, addrToUse)
		}
	}
	if len(listenAddrs) == 0 && len(masqAddrCounts) == 0 {
		return nil
	}
	return &natFamilyConfig{
		nativeAddr:     nativeAddr,
		listenAddrs:    views.MapOf(listenAddrs),
		dstMasqAddrs:   &rt,
		masqAddrCounts: masqAddrCounts,
	}
}

// SetNetMap is called when a new NetworkMap is received.
func (t *Wrapper) SetWGConfig(wcfg *wgcfg.Config) {
	v4, v6 := natConfigFromWGConfig(wcfg, ipproto.Version4), natConfigFromWGConfig(wcfg, ipproto.Version6)
	var cfg *natConfig
	if v4 != nil || v6 != nil {
		cfg = &natConfig{v4: v4, v6: v6}
	}

	old := t.natConfig.Swap(cfg)
	if !reflect.DeepEqual(old, cfg) {
		t.logf("nat config: %v", cfg)
	}
}

var (
	magicDNSIPPort   = netip.AddrPortFrom(tsaddr.TailscaleServiceIP(), 0) // 100.100.100.100:0
	magicDNSIPPortv6 = netip.AddrPortFrom(tsaddr.TailscaleServiceIPv6(), 0)
)

func (t *Wrapper) filterPacketOutboundToWireGuard(p *packet.Parsed) filter.Response {
	// Fake ICMP echo responses to MagicDNS (100.100.100.100).
	if p.IsEchoRequest() {
		switch p.Dst {
		case magicDNSIPPort:
			header := p.ICMP4Header()
			header.ToResponse()
			outp := packet.Generate(&header, p.Payload())
			t.InjectInboundCopy(outp)
			return filter.DropSilently // don't pass on to OS; already handled
		case magicDNSIPPortv6:
			header := p.ICMP6Header()
			header.ToResponse()
			outp := packet.Generate(&header, p.Payload())
			t.InjectInboundCopy(outp)
			return filter.DropSilently // don't pass on to OS; already handled
		}
	}

	// Issue 1526 workaround: if we sent disco packets over
	// Tailscale from ourselves, then drop them, as that shouldn't
	// happen unless a networking stack is confused, as it seems
	// macOS in Network Extension mode might be.
	if p.IPProto == ipproto.UDP && // disco is over UDP; avoid isSelfDisco call for TCP/etc
		t.isSelfDisco(p) {
		t.limitedLogf("[unexpected] received self disco out packet over tstun; dropping")
		metricPacketOutDropSelfDisco.Add(1)
		return filter.DropSilently
	}

	if t.PreFilterPacketOutboundToWireGuardNetstackIntercept != nil {
		if res := t.PreFilterPacketOutboundToWireGuardNetstackIntercept(p, t); res.IsDrop() {
			// Handled by netstack.Impl.handleLocalPackets (quad-100 DNS primarily)
			return res
		}
	}
	if t.PreFilterPacketOutboundToWireGuardEngineIntercept != nil {
		if res := t.PreFilterPacketOutboundToWireGuardEngineIntercept(p, t); res.IsDrop() {
			// Handled by userspaceEngine.handleLocalPackets (primarily handles
			// quad-100 if netstack is not installed).
			return res
		}
	}

	filt := t.filter.Load()
	if filt == nil {
		return filter.Drop
	}

	if filt.RunOut(p, t.filterFlags) != filter.Accept {
		metricPacketOutDropFilter.Add(1)
		return filter.Drop
	}

	if t.PostFilterPacketOutboundToWireGuard != nil {
		if res := t.PostFilterPacketOutboundToWireGuard(p, t); res.IsDrop() {
			return res
		}
	}

	return filter.Accept
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

func (t *Wrapper) Read(buffs [][]byte, sizes []int, offset int) (int, error) {
	if !t.started.Load() {
		<-t.startCh
	}
	// packet from OS read and sent to WG
	res, ok := <-t.vectorOutbound
	if !ok {
		return 0, io.EOF
	}
	if res.err != nil && len(res.data) == 0 {
		return 0, res.err
	}
	if res.data == nil {
		n, err := t.injectedRead(res.injected, buffs[0], offset)
		sizes[0] = n
		if err != nil && n == 0 {
			return 0, err
		}

		return 1, err
	}

	metricPacketOut.Add(int64(len(res.data)))

	var buffsPos int
	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	captHook := t.captureHook.Load()
	for _, data := range res.data {
		p.Decode(data[res.dataOffset:])

		t.snat(p)
		if m := t.destIPActivity.Load(); m != nil {
			if fn := m[p.Dst.Addr()]; fn != nil {
				fn()
			}
		}
		if captHook != nil {
			captHook(capture.FromLocal, t.now(), p.Buffer(), p.CaptureMeta)
		}
		if !t.disableFilter {
			response := t.filterPacketOutboundToWireGuard(p)
			if response != filter.Accept {
				metricPacketOutDrop.Add(1)
				continue
			}
		}
		n := copy(buffs[buffsPos][offset:], p.Buffer())
		if n != len(data)-res.dataOffset {
			panic(fmt.Sprintf("short copy: %d != %d", n, len(data)-res.dataOffset))
		}
		sizes[buffsPos] = n
		if stats := t.stats.Load(); stats != nil {
			stats.UpdateTxVirtual(p.Buffer())
		}
		buffsPos++
	}

	// t.vectorBuffer has a fixed location in memory.
	// TODO(raggi): add an explicit field and possibly method to the tunVectorReadResult
	// to signal when sendBufferConsumed should be called.
	if &res.data[0] == &t.vectorBuffer[0] {
		// We are done with t.buffer. Let poll() re-use it.
		t.sendBufferConsumed()
	}

	t.noteActivity()
	return buffsPos, res.err
}

// injectedRead handles injected reads, which bypass filters.
func (t *Wrapper) injectedRead(res tunInjectedRead, buf []byte, offset int) (int, error) {
	metricPacketOut.Add(1)

	var n int
	if !res.packet.IsNil() {

		n = copy(buf[offset:], res.packet.NetworkHeader().Slice())
		n += copy(buf[offset+n:], res.packet.TransportHeader().Slice())
		n += copy(buf[offset+n:], res.packet.Data().AsRange().ToSlice())
		res.packet.DecRef()
	} else {
		n = copy(buf[offset:], res.data)
	}

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	p.Decode(buf[offset : offset+n])
	t.snat(p)

	if m := t.destIPActivity.Load(); m != nil {
		if fn := m[p.Dst.Addr()]; fn != nil {
			fn()
		}
	}

	if stats := t.stats.Load(); stats != nil {
		stats.UpdateTxVirtual(buf[offset:][:n])
	}
	t.noteActivity()
	return n, nil
}

func (t *Wrapper) filterPacketInboundFromWireGuard(p *packet.Parsed, captHook capture.Callback) filter.Response {
	if captHook != nil {
		captHook(capture.FromPeer, t.now(), p.Buffer(), p.CaptureMeta)
	}

	if p.IPProto == ipproto.TSMP {
		if pingReq, ok := p.AsTSMPPing(); ok {
			t.noteActivity()
			t.injectOutboundPong(p, pingReq)
			return filter.DropSilently
		} else if data, ok := p.AsTSMPPong(); ok {
			if f := t.OnTSMPPongReceived; f != nil {
				f(data)
			}
		}
	}

	if p.IsEchoResponse() {
		if f := t.OnICMPEchoResponseReceived; f != nil && f(p) {
			// Note: this looks dropped in metrics, even though it was
			// handled internally.
			return filter.DropSilently
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
		return filter.DropSilently
	}

	if t.PreFilterPacketInboundFromWireGuard != nil {
		if res := t.PreFilterPacketInboundFromWireGuard(p, t); res.IsDrop() {
			return res
		}
	}

	filt := t.filter.Load()
	if filt == nil {
		return filter.Drop
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

		return filter.Drop
	}

	if t.PostFilterPacketInboundFromWireGuard != nil {
		if res := t.PostFilterPacketInboundFromWireGuard(p, t); res.IsDrop() {
			return res
		}
	}

	return filter.Accept
}

// Write accepts incoming packets. The packets begins at buffs[:][offset:],
// like wireguard-go/tun.Device.Write.
func (t *Wrapper) Write(buffs [][]byte, offset int) (int, error) {
	metricPacketIn.Add(int64(len(buffs)))
	i := 0
	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	captHook := t.captureHook.Load()
	for _, buff := range buffs {
		p.Decode(buff[offset:])
		t.dnat(p)
		if !t.disableFilter {
			if t.filterPacketInboundFromWireGuard(p, captHook) != filter.Accept {
				metricPacketInDrop.Add(1)
			} else {
				buffs[i] = buff
				i++
			}
		}
	}
	if t.disableFilter {
		i = len(buffs)
	}
	buffs = buffs[:i]

	if len(buffs) > 0 {
		t.noteActivity()
		_, err := t.tdevWrite(buffs, offset)
		return len(buffs), err
	}
	return 0, nil
}

func (t *Wrapper) tdevWrite(buffs [][]byte, offset int) (int, error) {
	if stats := t.stats.Load(); stats != nil {
		for i := range buffs {
			stats.UpdateRxVirtual((buffs)[i][offset:])
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

// InjectInboundPacketBuffer makes the Wrapper device behave as if a packet
// with the given contents was received from the network.
// It takes ownership of one reference count on the packet. The injected
// packet will not pass through inbound filters.
//
// This path is typically used to deliver synthesized packets to the
// host networking stack.
func (t *Wrapper) InjectInboundPacketBuffer(pkt *stack.PacketBuffer) error {
	buf := make([]byte, PacketStartOffset+pkt.Size())

	n := copy(buf[PacketStartOffset:], pkt.NetworkHeader().Slice())
	n += copy(buf[PacketStartOffset+n:], pkt.TransportHeader().Slice())
	n += copy(buf[PacketStartOffset+n:], pkt.Data().AsRange().ToSlice())
	if n != pkt.Size() {
		panic("unexpected packet size after copy")
	}
	pkt.DecRef()

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	p.Decode(buf[PacketStartOffset:])
	captHook := t.captureHook.Load()
	if captHook != nil {
		captHook(capture.SynthesizedToLocal, t.now(), p.Buffer(), p.CaptureMeta)
	}
	t.dnat(p)

	return t.InjectInboundDirect(buf, PacketStartOffset)
}

// InjectInboundDirect makes the Wrapper device behave as if a packet
// with the given contents was received from the network.
// It blocks and does not take ownership of the packet.
// The injected packet will not pass through inbound filters.
//
// The packet contents are to start at &buf[offset].
// offset must be greater or equal to PacketStartOffset.
// The space before &buf[offset] will be used by WireGuard.
func (t *Wrapper) InjectInboundDirect(buf []byte, offset int) error {
	if len(buf) > MaxPacketSize {
		return errPacketTooBig
	}
	if len(buf) < offset {
		return errOffsetTooBig
	}
	if offset < PacketStartOffset {
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

	buf := make([]byte, PacketStartOffset+len(packet))
	copy(buf[PacketStartOffset:], packet)

	return t.InjectInboundDirect(buf, PacketStartOffset)
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
// The injected packet will not pass through outbound filters.
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
func (t *Wrapper) InjectOutboundPacketBuffer(pkt *stack.PacketBuffer) error {
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
		capt(capture.SynthesizedToPeer, t.now(), b.Flatten(), packet.CaptureMeta{})
	}

	t.injectOutbound(tunInjectedRead{packet: pkt})
	return nil
}

func (t *Wrapper) BatchSize() int {
	return t.tdev.BatchSize()
}

// Unwrap returns the underlying tun.Device.
func (t *Wrapper) Unwrap() tun.Device {
	return t.tdev
}

// SetStatistics specifies a per-connection statistics aggregator.
// Nil may be specified to disable statistics gathering.
func (t *Wrapper) SetStatistics(stats *connstats.Statistics) {
	t.stats.Store(stats)
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
)

func (t *Wrapper) InstallCaptureHook(cb capture.Callback) {
	t.captureHook.Store(cb)
}
