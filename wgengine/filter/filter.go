// Copyright (c) Tailscale Inc & contributors
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
	"tailscale.com/net/ipset"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/rate"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/mak"
	"tailscale.com/util/slicesx"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/filter/filtertype"
)

// Filter is a stateful packet filter.
type Filter struct {
	logf logger.Logf
	// local4 and local6 report whether an IP is "local" to this node, for the
	// respective address family. Inbound packets that pass the direction-agnostic
	// pre-checks and are not accepted by [Filter.IngressAllowHooks] must have a destination
	// within local to be considered by the policy filter.
	local4 func(netip.Addr) bool
	local6 func(netip.Addr) bool

	// logIPs is the set of IPs that are allowed to appear in flow
	// logs. If a packet is to or from an IP not in logIPs, it will
	// never be logged.
	logIPs4 func(netip.Addr) bool
	logIPs6 func(netip.Addr) bool

	// srcIPHasCap optionally specifies a function that reports
	// whether a given source IP address has a given capability.
	srcIPHasCap CapTestFunc

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

	// IngressAllowHooks are hooks that allow extensions to accept inbound
	// packets beyond the standard filter rules. Packets that are not dropped
	// by the direction-agnostic pre-check, but would be not accepted by the
	// main filter rules, including the check for destinations in the node's
	// local IP set, will be accepted if they match one of these hooks.
	// As of 2026-02-24, the ingress filter does not implement explicit drop
	// rules, but if it does, an explicitly dropped packet will be dropped,
	// and these hooks will not be evaluated.
	//
	// Processing of hooks stop after the first one that returns true.
	// The returned why string of the first match is used in logging.
	// Returning false does not drop the packet.
	// See also [filter.Filter.IngressAllowHooks].
	IngressAllowHooks []PacketMatch

	// LinkLocalAllowHooks are hooks that provide exceptions to the default
	// policy of dropping link-local unicast packets. They run inside the
	// direction-agnostic pre-checks for both ingress and egress.
	//
	// A hook can allow a link-local packet to pass the link-local check,
	// but the packet is still subject to all other filter rules, and could be
	// dropped elsewhere. Matching link-local packets are not logged.
	// See also [filter.Filter.LinkLocalAllowHooks].
	LinkLocalAllowHooks []PacketMatch
}

// PacketMatch is a function that inspects a packet and reports whether it
// matches a custom filter criterion. If match is true, why should be a short
// human-readable reason for the match, used in filter logging (e.g. "corp-dns ok").
type PacketMatch func(packet.Parsed) (match bool, why string)

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

type (
	Match        = filtertype.Match
	NetPortRange = filtertype.NetPortRange
	PortRange    = filtertype.PortRange
	CapMatch     = filtertype.CapMatch
)

// NewAllowAllForTest returns a packet filter that accepts
// everything. Use in tests only, as it permits some kinds of spoofing
// attacks to reach the OS network stack.
func NewAllowAllForTest(logf logger.Logf) *Filter {
	any4 := netip.PrefixFrom(netaddr.IPv4(0, 0, 0, 0), 0)
	any6 := netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0)
	ms := []Match{
		{
			IPProto: views.SliceOf([]ipproto.Proto{ipproto.TCP, ipproto.UDP, ipproto.ICMPv4}),
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
			IPProto: views.SliceOf([]ipproto.Proto{ipproto.TCP, ipproto.UDP, ipproto.ICMPv6}),
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
	return New(ms, nil, ipSet, ipSet, nil, logf)
}

// NewAllowNone returns a packet filter that rejects everything.
func NewAllowNone(logf logger.Logf, logIPs *netipx.IPSet) *Filter {
	return New(nil, nil, &netipx.IPSet{}, logIPs, nil, logf)
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
	f := New(nil, nil, localNets, logIPs, shareStateWith, logf)
	f.shieldsUp = true
	return f
}

// New creates a new packet filter. The filter enforces that incoming packets
// must be destined to an IP in localNets, and must be allowed by matches.
// The optional capTest func is used to evaluate a Match that uses capabilities.
// If nil, such matches will always fail.
//
// If shareStateWith is non-nil, the returned filter shares state with the
// previous one, to enable changing rules at runtime without breaking existing
// stateful flows.
func New(matches []Match, capTest CapTestFunc, localNets, logIPs *netipx.IPSet, shareStateWith *Filter, logf logger.Logf) *Filter {
	var state *filterState
	if shareStateWith != nil {
		state = shareStateWith.state
	} else {
		state = &filterState{
			lru: &flowtrack.Cache[struct{}]{MaxEntries: lruMax},
		}
	}

	f := &Filter{
		logf:        logf,
		matches4:    matchesFamily(matches, netip.Addr.Is4),
		matches6:    matchesFamily(matches, netip.Addr.Is6),
		cap4:        capMatchesFunc(matches, netip.Addr.Is4),
		cap6:        capMatchesFunc(matches, netip.Addr.Is6),
		local4:      ipset.FalseContainsIPFunc(),
		local6:      ipset.FalseContainsIPFunc(),
		logIPs4:     ipset.FalseContainsIPFunc(),
		logIPs6:     ipset.FalseContainsIPFunc(),
		state:       state,
		srcIPHasCap: capTest,
	}
	if localNets != nil {
		p := localNets.Prefixes()
		p4, p6 := slicesx.Partition(p, func(p netip.Prefix) bool { return p.Addr().Is4() })
		f.local4 = ipset.NewContainsIPFunc(views.SliceOf(p4))
		f.local6 = ipset.NewContainsIPFunc(views.SliceOf(p6))
	}
	if logIPs != nil {
		p := logIPs.Prefixes()
		p4, p6 := slicesx.Partition(p, func(p netip.Prefix) bool { return p.Addr().Is4() })
		f.logIPs4 = ipset.NewContainsIPFunc(views.SliceOf(p4))
		f.logIPs6 = ipset.NewContainsIPFunc(views.SliceOf(p6))
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
		retm.SrcCaps = m.SrcCaps
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
		if (len(retm.Srcs) > 0 || len(retm.SrcCaps) > 0) && len(retm.Dsts) > 0 {
			retm.SrcsContains = ipset.NewContainsIPFunc(views.SliceOf(retm.Srcs))
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
			retm.SrcsContains = ipset.NewContainsIPFunc(views.SliceOf(retm.Srcs))
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
	if runflags == 0 || !f.loggingAllowed(q) {
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
		verdict = "[v1] Accept"
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
		if !m.SrcsContains(srcIP) {
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
	r, _ := f.pre(q, rf, dir)
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

	if r == noVerdict {
		for _, pm := range f.IngressAllowHooks {
			if match, why := pm(*q); match {
				f.logRateLimit(rf, q, dir, Accept, why)
				return Accept
			}
		}
		r = Drop
	}
	f.logRateLimit(rf, q, dir, r, why)
	return r
}

// RunOut determines whether this node is allowed to send q to a
// Tailscale peer.
func (f *Filter) RunOut(q *packet.Parsed, rf RunFlags) (Response, usermetric.DropReason) {
	dir := out
	r, reason := f.pre(q, rf, dir)
	if r == Accept || r == Drop {
		// already logged
		return r, reason
	}

	r, why := f.runOut(q)
	f.logRateLimit(rf, q, dir, r, why)
	return r, ""
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

// runIn4 returns noVerdict for unaccepted packets that may ultimately
// be accepted through [Filter.IngressAllowHooks].
func (f *Filter) runIn4(q *packet.Parsed) (r Response, why string) {
	// A compromised peer could try to send us packets for
	// destinations we didn't explicitly advertise. This check is to
	// prevent that.
	if !f.local4(q.Dst.Addr()) {
		return noVerdict, "destination not allowed"
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
		} else if f.matches4.matchIPsOnly(q, f.srcIPHasCap) {
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
		if f.matches4.match(q, f.srcIPHasCap) {
			return Accept, "tcp ok"
		}
	case ipproto.UDP, ipproto.SCTP:
		t := flowtrack.MakeTuple(q.IPProto, q.Src, q.Dst)

		f.state.mu.Lock()
		_, ok := f.state.lru.Get(t)
		f.state.mu.Unlock()

		if ok {
			return Accept, "cached"
		}
		if f.matches4.match(q, f.srcIPHasCap) {
			return Accept, "ok"
		}
	case ipproto.TSMP:
		return Accept, "tsmp ok"
	default:
		if f.matches4.matchProtoAndIPsOnlyIfAllPorts(q) {
			return Accept, "other-portless ok"
		}
		return noVerdict, unknownProtoString(q.IPProto)
	}
	return noVerdict, "no rules matched"
}

// runIn6 returns noVerdict for unaccepted packets that may ultimately
// be accepted through [Filter.IngressAllowHooks].
func (f *Filter) runIn6(q *packet.Parsed) (r Response, why string) {
	// A compromised peer could try to send us packets for
	// destinations we didn't explicitly advertise. This check is to
	// prevent that.
	if !f.local6(q.Dst.Addr()) {
		return noVerdict, "destination not allowed"
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
		} else if f.matches6.matchIPsOnly(q, f.srcIPHasCap) {
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
		if f.matches6.match(q, f.srcIPHasCap) {
			return Accept, "tcp ok"
		}
	case ipproto.UDP, ipproto.SCTP:
		t := flowtrack.MakeTuple(q.IPProto, q.Src, q.Dst)

		f.state.mu.Lock()
		_, ok := f.state.lru.Get(t)
		f.state.mu.Unlock()

		if ok {
			return Accept, "cached"
		}
		if f.matches6.match(q, f.srcIPHasCap) {
			return Accept, "ok"
		}
	case ipproto.TSMP:
		return Accept, "tsmp ok"
	default:
		if f.matches6.matchProtoAndIPsOnlyIfAllPorts(q) {
			return Accept, "other-portless ok"
		}
		return noVerdict, unknownProtoString(q.IPProto)
	}
	return noVerdict, "no rules matched"
}

// runIn runs the output-specific part of the filter logic.
func (f *Filter) runOut(q *packet.Parsed) (r Response, why string) {
	switch q.IPProto {
	case ipproto.UDP, ipproto.SCTP:
		tuple := flowtrack.MakeTuple(q.IPProto, q.Dst, q.Src) // src/dst reversed
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

func (f *Filter) isAllowedLinkLocal(q *packet.Parsed) bool {
	if q.Dst.Addr() == gcpDNSAddr {
		return true
	}
	for _, pm := range f.LinkLocalAllowHooks {
		if match, _ := pm(*q); match {
			return true
		}
	}
	return false
}

// pre runs the direction-agnostic filter logic. dir is only used for
// logging.
func (f *Filter) pre(q *packet.Parsed, rf RunFlags, dir direction) (Response, usermetric.DropReason) {
	if len(q.Buffer()) == 0 {
		// wireguard keepalive packet, always permit.
		return Accept, ""
	}
	if len(q.Buffer()) < 20 {
		f.logRateLimit(rf, q, dir, Drop, "too short")
		return Drop, usermetric.ReasonTooShort
	}

	if q.IPProto == ipproto.Unknown {
		f.logRateLimit(rf, q, dir, Drop, "unknown proto")
		return Drop, usermetric.ReasonUnknownProtocol
	}

	if q.Dst.Addr().IsMulticast() {
		f.logRateLimit(rf, q, dir, Drop, "multicast")
		return Drop, usermetric.ReasonMulticast
	}
	if q.Dst.Addr().IsLinkLocalUnicast() && !f.isAllowedLinkLocal(q) {
		f.logRateLimit(rf, q, dir, Drop, "link-local-unicast")
		return Drop, usermetric.ReasonLinkLocalUnicast
	}

	if q.IPProto == ipproto.Fragment {
		// Fragments after the first always need to be passed through.
		// Very small fragments are considered Junk by Parsed.
		f.logRateLimit(rf, q, dir, Accept, "fragment")
		return Accept, ""
	}

	return noVerdict, ""
}

// loggingAllowed reports whether p can appear in logs at all.
func (f *Filter) loggingAllowed(p *packet.Parsed) bool {
	switch p.IPVersion {
	case 4:
		return f.logIPs4(p.Src.Addr()) && f.logIPs4(p.Dst.Addr())
	case 6:
		return f.logIPs6(p.Src.Addr()) && f.logIPs6(p.Dst.Addr())
	}
	return false
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
