// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package filter is a stateful packet filter.
package filter

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"go4.org/netipx"
	"tailscale.com/envknob"
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/rate"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

// Filter is a stateful packet filter.
type Filter struct {
	logf logger.Logf
	// local is the set of IPs prefixes that we know to be "local" to
	// this node. All packets coming in over tailscale must have a
	// destination within local, regardless of the policy filter
	// below.
	local *netipx.IPSet

	// logIPs is the set of IPs that are allowed to appear in flow
	// logs. If a packet is to or from an IP not in logIPs, it will
	// never be logged.
	logIPs *netipx.IPSet

	// matches4 and matches6 are lists of match->action rules
	// applied to all packets arriving over tailscale
	// tunnels. Matches are checked in order, and processing stops
	// at the first matching rule. The default policy if no rules
	// match is to drop the packet.
	matches4 matches
	matches6 matches

	// cap4 and cap6 are the subsets of the matches that are about
	// capability grants, partitioned by source IP address family.
	cap4, cap6 matches

	// state is the connection tracking state attached to this
	// filter. It is used to allow incoming traffic that is a response
	// to an outbound connection that this node made, even if those
	// incoming packets don't get accepted by matches above.
	state *filterState

	shieldsUp bool
}

// filterState is a state cache of past seen packets.
type filterState struct {
	mu  sync.Mutex
	lru *flowtrack.Cache[struct{}] // from flowtrack.Tuple -> struct{}
}

// lruMax is the size of the LRU cache in filterState.
const lruMax = 512

// Response is a verdict from the packet filter.
type Response int

const (
	Drop         Response = iota // do not continue processing packet.
	DropSilently                 // do not continue processing packet, but also don't log
	Accept                       // continue processing packet.
	noVerdict                    // no verdict yet, continue running filter
)

func (r Response) String() string {
	switch r {
	case Drop:
		return "Drop"
	case DropSilently:
		return "DropSilently"
	case Accept:
		return "Accept"
	case noVerdict:
		return "noVerdict"
	default:
		return "???"
	}
}

func (r Response) IsDrop() bool {
	return r == Drop || r == DropSilently
}

// RunFlags controls the filter's debug log verbosity at runtime.
type RunFlags int

const (
	LogDrops       RunFlags = 1 << iota // write dropped packet info to logf
	LogAccepts                          // write accepted packet info to logf
	HexdumpDrops                        // print packet hexdump when logging drops
	HexdumpAccepts                      // print packet hexdump when logging accepts
)

// NewAllowAllForTest returns a packet filter that accepts
// everything. Use in tests only, as it permits some kinds of spoofing
// attacks to reach the OS network stack.
func NewAllowAllForTest(logf logger.Logf) *Filter {
	any4 := netip.PrefixFrom(netaddr.IPv4(0, 0, 0, 0), 0)
	any6 := netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0)
	ms := []Match{
		{
			IPProto: []ipproto.Proto{ipproto.TCP, ipproto.UDP, ipproto.ICMPv4},
			Srcs:    []netip.Prefix{any4},
			Dsts: []NetPortRange{
				{
					Net: any4,
					Ports: PortRange{
						First: 0,
						Last:  65535,
					},
				},
			},
		},
		{
			IPProto: []ipproto.Proto{ipproto.TCP, ipproto.UDP, ipproto.ICMPv6},
			Srcs:    []netip.Prefix{any6},
			Dsts: []NetPortRange{
				{
					Net: any6,
					Ports: PortRange{
						First: 0,
						Last:  65535,
					},
				},
			},
		},
	}

	var sb netipx.IPSetBuilder
	sb.AddPrefix(any4)
	sb.AddPrefix(any6)
	ipSet, _ := sb.IPSet()
	return New(ms, ipSet, ipSet, nil, logf)
}

// NewAllowNone returns a packet filter that rejects everything.
func NewAllowNone(logf logger.Logf, logIPs *netipx.IPSet) *Filter {
	return New(nil, &netipx.IPSet{}, logIPs, nil, logf)
}

// NewShieldsUpFilter returns a packet filter that rejects incoming connections.
//
// If shareStateWith is non-nil, the returned filter shares state with the previous one,
// as long as the previous one was also a shields up filter.
func NewShieldsUpFilter(localNets *netipx.IPSet, logIPs *netipx.IPSet, shareStateWith *Filter, logf logger.Logf) *Filter {
	// Don't permit sharing state with a prior filter that wasn't a shields-up filter.
	if shareStateWith != nil && !shareStateWith.shieldsUp {
		shareStateWith = nil
	}
	f := New(nil, localNets, logIPs, shareStateWith, logf)
	f.shieldsUp = true
	return f
}

// New creates a new packet filter. The filter enforces that incoming
// packets must be destined to an IP in localNets, and must be allowed
// by matches. If shareStateWith is non-nil, the returned filter
// shares state with the previous one, to enable changing rules at
// runtime without breaking existing stateful flows.
func New(matches []Match, localNets *netipx.IPSet, logIPs *netipx.IPSet, shareStateWith *Filter, logf logger.Logf) *Filter {
	var state *filterState
	if shareStateWith != nil {
		state = shareStateWith.state
	} else {
		state = &filterState{
			lru: &flowtrack.Cache[struct{}]{MaxEntries: lruMax},
		}
	}
	f := &Filter{
		logf:     logf,
		matches4: matchesFamily(matches, netip.Addr.Is4),
		matches6: matchesFamily(matches, netip.Addr.Is6),
		cap4:     capMatchesFunc(matches, netip.Addr.Is4),
		cap6:     capMatchesFunc(matches, netip.Addr.Is6),
		local:    localNets,
		logIPs:   logIPs,
		state:    state,
	}
	return f
}

// matchesFamily returns the subset of ms for which keep(srcNet.IP)
// and keep(dstNet.IP) are both true.
func matchesFamily(ms matches, keep func(netip.Addr) bool) matches {
	var ret matches
	for _, m := range ms {
		var retm Match
		retm.IPProto = m.IPProto
		for _, src := range m.Srcs {
			if keep(src.Addr()) {
				retm.Srcs = append(retm.Srcs, src)
			}
		}
		for _, dst := range m.Dsts {
			if keep(dst.Net.Addr()) {
				retm.Dsts = append(retm.Dsts, dst)
			}
		}
		if len(retm.Srcs) > 0 && len(retm.Dsts) > 0 {
			ret = append(ret, retm)
		}
	}
	return ret
}

// capMatchesFunc returns a copy of the subset of ms for which keep(srcNet.IP)
// and the match is a capability grant.
func capMatchesFunc(ms matches, keep func(netip.Addr) bool) matches {
	var ret matches
	for _, m := range ms {
		if len(m.Caps) == 0 {
			continue
		}
		retm := Match{Caps: m.Caps}
		for _, src := range m.Srcs {
			if keep(src.Addr()) {
				retm.Srcs = append(retm.Srcs, src)
			}
		}
		if len(retm.Srcs) > 0 {
			ret = append(ret, retm)
		}
	}
	return ret
}

func maybeHexdump(flag RunFlags, b []byte) string {
	if flag == 0 {
		return ""
	}
	return packet.Hexdump(b) + "\n"
}

// TODO(apenwarr): use a bigger bucket for specifically TCP SYN accept logging?
// Logging is a quick way to record every newly opened TCP connection, but
// we have to be cautious about flooding the logs vs letting people use
// flood protection to hide their traffic. We could use a rate limiter in
// the actual *filter* for SYN accepts, perhaps.
var acceptBucket = rate.NewLimiter(rate.Every(10*time.Second), 3)
var dropBucket = rate.NewLimiter(rate.Every(5*time.Second), 10)

// NOTE(Xe): This func init is used to detect
// TS_DEBUG_FILTER_RATE_LIMIT_LOGS=all, and if it matches, to
// effectively disable the limits on the log rate by setting the limit
// to 1 millisecond. This should capture everything.
func init() {
	if envknob.String("TS_DEBUG_FILTER_RATE_LIMIT_LOGS") != "all" {
		return
	}

	acceptBucket = rate.NewLimiter(rate.Every(time.Millisecond), 10)
	dropBucket = rate.NewLimiter(rate.Every(time.Millisecond), 10)
}

func (f *Filter) logRateLimit(runflags RunFlags, q *packet.Parsed, dir direction, r Response, why string) {
	if !f.loggingAllowed(q) {
		return
	}

	if r == Drop && omitDropLogging(q, dir) {
		return
	}

	var verdict string
	if r == Drop && (runflags&LogDrops) != 0 && dropBucket.Allow() {
		verdict = "Drop"
		runflags &= HexdumpDrops
	} else if r == Accept && (runflags&LogAccepts) != 0 && acceptBucket.Allow() {
		verdict = "Accept"
		runflags &= HexdumpAccepts
	}

	// Note: it is crucial that q.String() be called only if {accept,drop}Bucket.Allow() passes,
	// since it causes an allocation.
	if verdict != "" {
		b := q.Buffer()
		f.logf("%s: %s %d %s\n%s", verdict, q.String(), len(b), why, maybeHexdump(runflags, b))
	}
}

// dummyPacket is a 20-byte slice of garbage, to pass the filter
// pre-check when evaluating synthesized packets.
var dummyPacket = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// Check determines whether traffic from srcIP to dstIP:dstPort is allowed
// using protocol proto.
func (f *Filter) Check(srcIP, dstIP netip.Addr, dstPort uint16, proto ipproto.Proto) Response {
	pkt := &packet.Parsed{}
	pkt.Decode(dummyPacket) // initialize private fields
	switch {
	case (srcIP.Is4() && dstIP.Is6()) || (srcIP.Is6() && srcIP.Is4()):
		// Mismatched address families, no filters will
		// match.
		return Drop
	case srcIP.Is4():
		pkt.IPVersion = 4
	case srcIP.Is6():
		pkt.IPVersion = 6
	default:
		panic("unreachable")
	}
	pkt.Src = netip.AddrPortFrom(srcIP, 0)
	pkt.Dst = netip.AddrPortFrom(dstIP, dstPort)
	pkt.IPProto = proto
	if proto == ipproto.TCP {
		pkt.TCPFlags = packet.TCPSyn
	}

	return f.RunIn(pkt, 0)
}

// CheckTCP determines whether TCP traffic from srcIP to dstIP:dstPort
// is allowed.
func (f *Filter) CheckTCP(srcIP, dstIP netip.Addr, dstPort uint16) Response {
	return f.Check(srcIP, dstIP, dstPort, ipproto.TCP)
}

// CapsWithValues appends to base the capabilities that srcIP has talking
// to dstIP.
func (f *Filter) CapsWithValues(srcIP, dstIP netip.Addr) tailcfg.PeerCapMap {
	var mm matches
	switch {
	case srcIP.Is4():
		mm = f.cap4
	case srcIP.Is6():
		mm = f.cap6
	}
	var out tailcfg.PeerCapMap
	for _, m := range mm {
		if !ipInList(srcIP, m.Srcs) {
			continue
		}
		for _, cm := range m.Caps {
			if cm.Cap != "" && cm.Dst.Contains(dstIP) {
				prev, ok := out[cm.Cap]
				if !ok {
					mak.Set(&out, cm.Cap, slices.Clone(cm.Values))
					continue
				}
				out[cm.Cap] = append(prev, cm.Values...)
			}
		}
	}
	return out
}

// ShieldsUp reports whether this is a "shields up" (block everything
// incoming) filter.
func (f *Filter) ShieldsUp() bool { return f.shieldsUp }

// RunIn determines whether this node is allowed to receive q from a
// Tailscale peer.
func (f *Filter) RunIn(q *packet.Parsed, rf RunFlags) Response {
	dir := in
	r := f.pre(q, rf, dir)
	if r == Accept || r == Drop {
		// already logged
		return r
	}

	var why string
	switch q.IPVersion {
	case 4:
		r, why = f.runIn4(q)
	case 6:
		r, why = f.runIn6(q)
	default:
		r, why = Drop, "not-ip"
	}
	f.logRateLimit(rf, q, dir, r, why)
	return r
}

// RunOut determines whether this node is allowed to send q to a
// Tailscale peer.
func (f *Filter) RunOut(q *packet.Parsed, rf RunFlags) Response {
	dir := out
	r := f.pre(q, rf, dir)
	if r == Accept || r == Drop {
		// already logged
		return r
	}
	r, why := f.runOut(q)
	f.logRateLimit(rf, q, dir, r, why)
	return r
}

var unknownProtoStringCache sync.Map // ipproto.Proto -> string

func unknownProtoString(proto ipproto.Proto) string {
	if v, ok := unknownProtoStringCache.Load(proto); ok {
		return v.(string)
	}
	s := fmt.Sprintf("unknown-protocol-%d", proto)
	unknownProtoStringCache.Store(proto, s)
	return s
}

func (f *Filter) runIn4(q *packet.Parsed) (r Response, why string) {
	// A compromised peer could try to send us packets for
	// destinations we didn't explicitly advertise. This check is to
	// prevent that.
	if !f.local.Contains(q.Dst.Addr()) {
		return Drop, "destination not allowed"
	}

	switch q.IPProto {
	case ipproto.ICMPv4:
		if q.IsEchoResponse() || q.IsError() {
			// ICMP responses are allowed.
			// TODO(apenwarr): consider using conntrack state.
			//  We could choose to reject all packets that aren't
			//  related to an existing ICMP-Echo, TCP, or UDP
			//  session.
			return Accept, "icmp response ok"
		} else if f.matches4.matchIPsOnly(q) {
			// If any port is open to an IP, allow ICMP to it.
			return Accept, "icmp ok"
		}
	case ipproto.TCP:
		// For TCP, we want to allow *outgoing* connections,
		// which means we want to allow return packets on those
		// connections. To make this restriction work, we need to
		// allow non-SYN packets (continuation of an existing session)
		// to arrive. This should be okay since a new incoming session
		// can't be initiated without first sending a SYN.
		// It happens to also be much faster.
		// TODO(apenwarr): Skip the rest of decoding in this path?
		if !q.IsTCPSyn() {
			return Accept, "tcp non-syn"
		}
		if f.matches4.match(q) {
			return Accept, "tcp ok"
		}
	case ipproto.UDP, ipproto.SCTP:
		t := flowtrack.Tuple{Proto: q.IPProto, Src: q.Src, Dst: q.Dst}

		f.state.mu.Lock()
		_, ok := f.state.lru.Get(t)
		f.state.mu.Unlock()

		if ok {
			return Accept, "cached"
		}
		if f.matches4.match(q) {
			return Accept, "ok"
		}
	case ipproto.TSMP:
		return Accept, "tsmp ok"
	default:
		if f.matches4.matchProtoAndIPsOnlyIfAllPorts(q) {
			return Accept, "other-portless ok"
		}
		return Drop, unknownProtoString(q.IPProto)
	}
	return Drop, "no rules matched"
}

func (f *Filter) runIn6(q *packet.Parsed) (r Response, why string) {
	// A compromised peer could try to send us packets for
	// destinations we didn't explicitly advertise. This check is to
	// prevent that.
	if !f.local.Contains(q.Dst.Addr()) {
		return Drop, "destination not allowed"
	}

	switch q.IPProto {
	case ipproto.ICMPv6:
		if q.IsEchoResponse() || q.IsError() {
			// ICMP responses are allowed.
			// TODO(apenwarr): consider using conntrack state.
			//  We could choose to reject all packets that aren't
			//  related to an existing ICMP-Echo, TCP, or UDP
			//  session.
			return Accept, "icmp response ok"
		} else if f.matches6.matchIPsOnly(q) {
			// If any port is open to an IP, allow ICMP to it.
			return Accept, "icmp ok"
		}
	case ipproto.TCP:
		// For TCP, we want to allow *outgoing* connections,
		// which means we want to allow return packets on those
		// connections. To make this restriction work, we need to
		// allow non-SYN packets (continuation of an existing session)
		// to arrive. This should be okay since a new incoming session
		// can't be initiated without first sending a SYN.
		// It happens to also be much faster.
		// TODO(apenwarr): Skip the rest of decoding in this path?
		if q.IPProto == ipproto.TCP && !q.IsTCPSyn() {
			return Accept, "tcp non-syn"
		}
		if f.matches6.match(q) {
			return Accept, "tcp ok"
		}
	case ipproto.UDP, ipproto.SCTP:
		t := flowtrack.Tuple{Proto: q.IPProto, Src: q.Src, Dst: q.Dst}

		f.state.mu.Lock()
		_, ok := f.state.lru.Get(t)
		f.state.mu.Unlock()

		if ok {
			return Accept, "cached"
		}
		if f.matches6.match(q) {
			return Accept, "ok"
		}
	case ipproto.TSMP:
		return Accept, "tsmp ok"
	default:
		if f.matches6.matchProtoAndIPsOnlyIfAllPorts(q) {
			return Accept, "other-portless ok"
		}
		return Drop, unknownProtoString(q.IPProto)
	}
	return Drop, "no rules matched"
}

// runIn runs the output-specific part of the filter logic.
func (f *Filter) runOut(q *packet.Parsed) (r Response, why string) {
	switch q.IPProto {
	case ipproto.UDP, ipproto.SCTP:
		tuple := flowtrack.Tuple{
			Proto: q.IPProto,
			Src:   q.Dst, Dst: q.Src, // src/dst reversed
		}
		f.state.mu.Lock()
		f.state.lru.Add(tuple, struct{}{})
		f.state.mu.Unlock()
	}
	return Accept, "ok out"
}

// direction is whether a packet was flowing into this machine, or
// flowing out.
type direction int

const (
	in  direction = iota // from Tailscale peer to local machine
	out                  // from local machine to Tailscale peer
)

func (d direction) String() string {
	switch d {
	case in:
		return "in"
	case out:
		return "out"
	default:
		return fmt.Sprintf("[??dir=%d]", int(d))
	}
}

var gcpDNSAddr = netaddr.IPv4(169, 254, 169, 254)

// pre runs the direction-agnostic filter logic. dir is only used for
// logging.
func (f *Filter) pre(q *packet.Parsed, rf RunFlags, dir direction) Response {
	if len(q.Buffer()) == 0 {
		// wireguard keepalive packet, always permit.
		return Accept
	}
	if len(q.Buffer()) < 20 {
		f.logRateLimit(rf, q, dir, Drop, "too short")
		return Drop
	}

	if q.Dst.Addr().IsMulticast() {
		f.logRateLimit(rf, q, dir, Drop, "multicast")
		return Drop
	}
	if q.Dst.Addr().IsLinkLocalUnicast() && q.Dst.Addr() != gcpDNSAddr {
		f.logRateLimit(rf, q, dir, Drop, "link-local-unicast")
		return Drop
	}

	if q.IPProto == ipproto.Fragment {
		// Fragments after the first always need to be passed through.
		// Very small fragments are considered Junk by Parsed.
		f.logRateLimit(rf, q, dir, Accept, "fragment")
		return Accept
	}

	return noVerdict
}

// loggingAllowed reports whether p can appear in logs at all.
func (f *Filter) loggingAllowed(p *packet.Parsed) bool {
	return f.logIPs.Contains(p.Src.Addr()) && f.logIPs.Contains(p.Dst.Addr())
}

// omitDropLogging reports whether packet p, which has already been
// deemed a packet to Drop, should bypass the [rate-limited] logging.
// We don't want to log scary & spammy reject warnings for packets
// that are totally normal, like IPv6 route announcements.
func omitDropLogging(p *packet.Parsed, dir direction) bool {
	if dir != out {
		return false
	}

	return p.Dst.Addr().IsMulticast() || (p.Dst.Addr().IsLinkLocalUnicast() && p.Dst.Addr() != gcpDNSAddr) || p.IPProto == ipproto.IGMP
}
