// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tstun provides a TUN struct implementing the tun.Device interface
// with additional features as required by wgengine.
package tstun

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go4.org/mem"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/disco"
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tunstats"
	"tailscale.com/syncs"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/wgengine/filter"
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
type Wrapper struct {
	logf        logger.Logf
	limitedLogf logger.Logf // aggressively rate-limited logf used for potentially high volume errors
	// tdev is the underlying Wrapper device.
	tdev  tun.Device
	isTAP bool // whether tdev is a TAP device

	closeOnce sync.Once

	// lastActivityAtomic is read/written atomically.
	// On 32 bit systems, if the fields above change,
	// you might need to add a pad32.Four field here.
	lastActivityAtomic mono.Time // time of last send or receive

	destIPActivity syncs.AtomicValue[map[netip.Addr]func()]
	destMACAtomic  syncs.AtomicValue[[6]byte]
	discoKey       syncs.AtomicValue[key.DiscoPublic]

	// buffer stores the oldest unconsumed packet from tdev.
	// It is made a static buffer in order to avoid allocations.
	buffer [maxBufferSize]byte
	// bufferConsumedMu protects bufferConsumed from concurrent sends and closes.
	// It does not prevent send-after-close, only data races.
	bufferConsumedMu sync.Mutex
	// bufferConsumed synchronizes access to buffer (shared by Read and poll).
	//
	// Close closes bufferConsumed. There may be outstanding sends to bufferConsumed
	// when that happens; we catch any resulting panics.
	// This lets us avoid expensive multi-case selects.
	bufferConsumed chan struct{}

	// closed signals poll (by closing) when the device is closed.
	closed chan struct{}
	// outboundMu protects outbound from concurrent sends and closes.
	// It does not prevent send-after-close, only data races.
	outboundMu sync.Mutex
	// outbound is the queue by which packets leave the TUN device.
	//
	// The directions are relative to the network, not the device:
	// inbound packets arrive via UDP and are written into the TUN device;
	// outbound packets are read from the TUN device and sent out via UDP.
	// This queue is needed because although inbound writes are synchronous,
	// the other direction must wait on a WireGuard goroutine to poll it.
	//
	// Empty reads are skipped by WireGuard, so it is always legal
	// to discard an empty packet instead of sending it through t.outbound.
	//
	// Close closes outbound. There may be outstanding sends to outbound
	// when that happens; we catch any resulting panics.
	// This lets us avoid expensive multi-case selects.
	outbound chan tunReadResult

	// eventsUpDown yields up and down tun.Events that arrive on a Wrapper's events channel.
	eventsUpDown chan tun.Event
	// eventsOther yields non-up-and-down tun.Events that arrive on a Wrapper's events channel.
	eventsOther chan tun.Event

	// filter atomically stores the currently active packet filter
	filter atomic.Pointer[filter.Filter]
	// filterFlags control the verbosity of logging packet drops/accepts.
	filterFlags filter.RunFlags

	// PreFilterIn is the inbound filter function that runs before the main filter
	// and therefore sees the packets that may be later dropped by it.
	PreFilterIn FilterFunc
	// PostFilterIn is the inbound filter function that runs after the main filter.
	PostFilterIn FilterFunc
	// PreFilterFromTunToNetstack is a filter function that runs before the main filter
	// for packets from the local system. This filter is populated by netstack to hook
	// packets that should be handled by netstack. If set, this filter runs before
	// PreFilterFromTunToEngine.
	PreFilterFromTunToNetstack FilterFunc
	// PreFilterFromTunToEngine is a filter function that runs before the main filter
	// for packets from the local system. This filter is populated by wgengine to hook
	// packets which it handles internally. If both this and PreFilterFromTunToNetstack
	// filter functions are non-nil, this filter runs second.
	PreFilterFromTunToEngine FilterFunc
	// PostFilterOut is the outbound filter function that runs after the main filter.
	PostFilterOut FilterFunc

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
	stats struct {
		enabled atomic.Bool
		tunstats.Statistics
	}
}

// tunReadResult is the result of a TUN read, or an injected result pretending to be a TUN read.
// The data is not interpreted in the usual way for a Read method.
// See the comment in the middle of Wrap.Read.
type tunReadResult struct {
	// Only one of err, packet or data should be set, and are read in that order
	// of precedence.
	err    error
	packet *stack.PacketBuffer
	data   []byte

	// injected is set if the read result was generated internally, and contained packets should not
	// pass through filters.
	injected bool
}

func WrapTAP(logf logger.Logf, tdev tun.Device) *Wrapper {
	return wrap(logf, tdev, true)
}

func Wrap(logf logger.Logf, tdev tun.Device) *Wrapper {
	return wrap(logf, tdev, false)
}

func wrap(logf logger.Logf, tdev tun.Device, isTAP bool) *Wrapper {
	logf = logger.WithPrefix(logf, "tstun: ")
	tun := &Wrapper{
		logf:        logf,
		limitedLogf: logger.RateLimitedFn(logf, 1*time.Minute, 2, 10),
		isTAP:       isTAP,
		tdev:        tdev,
		// bufferConsumed is conceptually a condition variable:
		// a goroutine should not block when setting it, even with no listeners.
		bufferConsumed: make(chan struct{}, 1),
		closed:         make(chan struct{}),
		// outbound can be unbuffered; the buffer is an optimization.
		outbound:     make(chan tunReadResult, 1),
		eventsUpDown: make(chan tun.Event),
		eventsOther:  make(chan tun.Event),
		// TODO(dmytro): (highly rate-limited) hexdumps should happen on unknown packets.
		filterFlags: filter.LogAccepts | filter.LogDrops,
	}

	go tun.poll()
	go tun.pumpEvents()
	// The buffer starts out consumed.
	tun.bufferConsumed <- struct{}{}
	tun.noteActivity()

	return tun
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
		close(t.closed)
		t.bufferConsumedMu.Lock()
		close(t.bufferConsumed)
		t.bufferConsumedMu.Unlock()
		t.outboundMu.Lock()
		close(t.outbound)
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
func (t *Wrapper) Events() chan tun.Event {
	return t.eventsOther
}

func (t *Wrapper) File() *os.File {
	return t.tdev.File()
}

func (t *Wrapper) Flush() error {
	return t.tdev.Flush()
}

func (t *Wrapper) MTU() (int, error) {
	return t.tdev.MTU()
}

func (t *Wrapper) Name() (string, error) {
	return t.tdev.Name()
}

// allowSendOnClosedChannel suppresses panics due to sending on a closed channel.
// This allows us to avoid synchronization between poll and Close.
// Such synchronization (particularly multi-case selects) is too expensive
// for code like poll or Read that is on the hot path of every packet.
// If this makes you sad or angry, you may want to join our
// weekly Go Performance Delinquents Anonymous meetings on Monday nights.
func allowSendOnClosedChannel() {
	r := recover()
	if r == nil {
		return
	}
	e, _ := r.(error)
	if e != nil && e.Error() == "send on closed channel" {
		return
	}
	panic(r)
}

const ethernetFrameSize = 14 // 2 six byte MACs, 2 bytes ethertype

// poll polls t.tdev.Read, placing the oldest unconsumed packet into t.buffer.
// This is needed because t.tdev.Read in general may block (it does on Windows),
// so packets may be stuck in t.outbound if t.Read called t.tdev.Read directly.
func (t *Wrapper) poll() {
	for range t.bufferConsumed {
	DoRead:
		var n int
		var err error
		// Read may use memory in t.buffer before PacketStartOffset for mandatory headers.
		// This is the rationale behind the tun.Wrapper.{Read,Write} interfaces
		// and the reason t.buffer has size MaxMessageSize and not MaxContentSize.
		// In principle, read errors are not fatal (but wireguard-go disagrees).
		// We loop here until we get a non-empty (or failed) read.
		// We don't need this loop for correctness,
		// but wireguard-go will skip an empty read,
		// so we might as well avoid the send through t.outbound.
		for n == 0 && err == nil {
			if t.isClosed() {
				return
			}
			if t.isTAP {
				n, err = t.tdev.Read(t.buffer[:], PacketStartOffset-ethernetFrameSize)
				if tapDebug {
					s := fmt.Sprintf("% x", t.buffer[:])
					for strings.HasSuffix(s, " 00") {
						s = strings.TrimSuffix(s, " 00")
					}
					t.logf("TAP read %v, %v: %s", n, err, s)
				}
			} else {
				n, err = t.tdev.Read(t.buffer[:], PacketStartOffset)
			}
		}
		if t.isTAP {
			if err == nil {
				ethernetFrame := t.buffer[PacketStartOffset-ethernetFrameSize:][:n]
				if t.handleTAPFrame(ethernetFrame) {
					goto DoRead
				}
			}
			// Fall through. We got an IP packet.
			if n >= ethernetFrameSize {
				n -= ethernetFrameSize
			}
			if tapDebug {
				t.logf("tap regular frame: %x", t.buffer[PacketStartOffset:PacketStartOffset+n])
			}
		}
		t.sendOutbound(tunReadResult{data: t.buffer[PacketStartOffset : PacketStartOffset+n], err: err})
	}
}

// sendBufferConsumed does t.bufferConsumed <- struct{}{}.
// It protects against any panics or data races that that send could cause.
func (t *Wrapper) sendBufferConsumed() {
	defer allowSendOnClosedChannel()
	t.bufferConsumedMu.Lock()
	defer t.bufferConsumedMu.Unlock()
	t.bufferConsumed <- struct{}{}
}

// sendOutbound does t.outboundMu <- r.
// It protects against any panics or data races that that send could cause.
func (t *Wrapper) sendOutbound(r tunReadResult) {
	defer allowSendOnClosedChannel()
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	t.outbound <- r
}

var (
	magicDNSIPPort   = netip.AddrPortFrom(tsaddr.TailscaleServiceIP(), 0) // 100.100.100.100:0
	magicDNSIPPortv6 = netip.AddrPortFrom(tsaddr.TailscaleServiceIPv6(), 0)
)

func (t *Wrapper) filterOut(p *packet.Parsed) filter.Response {
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

	if t.PreFilterFromTunToNetstack != nil {
		if res := t.PreFilterFromTunToNetstack(p, t); res.IsDrop() {
			// Handled by netstack.Impl.handleLocalPackets (quad-100 DNS primarily)
			return res
		}
	}
	if t.PreFilterFromTunToEngine != nil {
		if res := t.PreFilterFromTunToEngine(p, t); res.IsDrop() {
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

	if t.PostFilterOut != nil {
		if res := t.PostFilterOut(p, t); res.IsDrop() {
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

func (t *Wrapper) Read(buf []byte, offset int) (int, error) {
	res, ok := <-t.outbound
	if !ok {
		// Wrapper is closed.
		return 0, io.EOF
	}
	if res.err != nil {
		return 0, res.err
	}

	metricPacketOut.Add(1)

	var n int
	if res.packet != nil {

		n = copy(buf[offset:], res.packet.NetworkHeader().Slice())
		n += copy(buf[offset+n:], res.packet.TransportHeader().Slice())
		n += copy(buf[offset+n:], res.packet.Data().AsRange().ToSlice())

		res.packet.DecRef()
	} else {
		n = copy(buf[offset:], res.data)

		// t.buffer has a fixed location in memory.
		if &res.data[0] == &t.buffer[PacketStartOffset] {
			// We are done with t.buffer. Let poll re-use it.
			t.sendBufferConsumed()
		}
	}

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	p.Decode(buf[offset : offset+n])

	if m := t.destIPActivity.Load(); m != nil {
		if fn := m[p.Dst.Addr()]; fn != nil {
			fn()
		}
	}

	// Do not filter injected packets.
	if !res.injected && !t.disableFilter {
		response := t.filterOut(p)
		if response != filter.Accept {
			metricPacketOutDrop.Add(1)
			// WireGuard considers read errors fatal; pretend nothing was read
			return 0, nil
		}
	}

	if t.stats.enabled.Load() {
		t.stats.UpdateTx(buf[offset:][:n])
	}
	t.noteActivity()
	return n, nil
}

func (t *Wrapper) filterIn(buf []byte) filter.Response {
	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	p.Decode(buf)

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

	if t.PreFilterIn != nil {
		if res := t.PreFilterIn(p, t); res.IsDrop() {
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

	if t.PostFilterIn != nil {
		if res := t.PostFilterIn(p, t); res.IsDrop() {
			return res
		}
	}

	return filter.Accept
}

// Write accepts an incoming packet. The packet begins at buf[offset:],
// like wireguard-go/tun.Device.Write.
func (t *Wrapper) Write(buf []byte, offset int) (int, error) {
	metricPacketIn.Add(1)
	if !t.disableFilter {
		if t.filterIn(buf[offset:]) != filter.Accept {
			metricPacketInDrop.Add(1)
			// If we're not accepting the packet, lie to wireguard-go and pretend
			// that everything is okay with a nil error, so wireguard-go
			// doesn't log about this Write "failure".
			//
			// We return len(buf), but the ill-defined wireguard-go/tun.Device.Write
			// method doesn't specify how the offset affects the return value.
			// In fact, the Linux implementation does one of two different things depending
			// on how the /dev/net/tun was created. But fortunately the wireguard-go
			// code ignores the int return and only looks at the error:
			//
			//     device/receive.go: _, err = device.tun.device.Write(....)
			//
			// TODO(bradfitz): fix upstream interface docs, implementation.
			return len(buf), nil
		}
	}

	t.noteActivity()
	return t.tdevWrite(buf, offset)
}

func (t *Wrapper) tdevWrite(buf []byte, offset int) (int, error) {
	if t.stats.enabled.Load() {
		t.stats.UpdateRx(buf[offset:])
	}
	if t.isTAP {
		return t.tapWrite(buf, offset)
	}
	return t.tdev.Write(buf, offset)
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
	_, err := t.tdevWrite(buf, offset)
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
func (t *Wrapper) InjectOutbound(packet []byte) error {
	if len(packet) > MaxPacketSize {
		return errPacketTooBig
	}
	if len(packet) == 0 {
		return nil
	}
	t.sendOutbound(tunReadResult{data: packet, injected: true})
	return nil
}

// InjectOutboundPacketBuffer logically behaves as InjectOutbound. It takes ownership of one
// reference count on the packet, and the packet may be mutated. The packet refcount will be
// decremented after the injected buffer has been read.
func (t *Wrapper) InjectOutboundPacketBuffer(packet *stack.PacketBuffer) error {
	size := packet.Size()
	if size > MaxPacketSize {
		packet.DecRef()
		return errPacketTooBig
	}
	if size == 0 {
		packet.DecRef()
		return nil
	}
	t.sendOutbound(tunReadResult{packet: packet, injected: true})
	return nil
}

// Unwrap returns the underlying tun.Device.
func (t *Wrapper) Unwrap() tun.Device {
	return t.tdev
}

// SetStatisticsEnabled enables per-connections packet counters.
// ExtractStatistics must be called periodically to avoid unbounded memory use.
func (t *Wrapper) SetStatisticsEnabled(enable bool) {
	t.stats.enabled.Store(enable)
}

// ExtractStatistics extracts and resets the counters for all active connections.
// It must be called periodically otherwise the memory used is unbounded.
func (t *Wrapper) ExtractStatistics() map[flowtrack.Tuple]tunstats.Counts {
	return t.stats.Extract()
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
