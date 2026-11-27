// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
)

// Reasons accompanying an allow verdict from the conn25 packet filter hooks.
const (
	// clientEgressReason is returned for a packet the client is sending to a
	// transit IP that has been assigned to it.
	clientEgressReason = "app connector egress to transit IP"

	// connectorTransitIPReason is returned for a packet addressed to a transit
	// IP in one of this connector's pools, exempting it from the filter's
	// blanket drop of link-local destinations.
	connectorTransitIPReason = "app connector transit IP"

	// connectorUnmappedReason is returned for a packet addressed to a transit
	// IP the peer has no mapping registered for. See [connector.ingressAllow]
	// for why those are admitted.
	connectorUnmappedReason = "app connector unregistered transit IP"

	// The remaining reasons are returned by [protoPortRangesAllow], and are
	// named after the [tailscale.com/wgengine/filter.Filter.RunIn] verdicts
	// they correspond to.
	connectorICMPResponseReason = "app connector icmp response ok"
	connectorICMPReason         = "app connector icmp ok"
	connectorTCPReason          = "app connector tcp ok"
	connectorPortReason         = "app connector ok"
	connectorPortlessReason     = "app connector other-portless ok"
)

// protoPortRangesAllow reports whether ranges, the protocol and port combinations a peer was granted
// for an app, permit p, and if so the reason to log alongside the allow verdict.
// It is modelled on [tailscale.com/wgengine/filter.Filter.RunIn].
func protoPortRangesAllow(ranges views.Slice[tailcfg.ProtoPortRange], p packet.Parsed) (bool, string) {
	switch p.IPProto {
	case ipproto.ICMPv4, ipproto.ICMPv6:
		var want ipproto.Proto
		switch p.IPVersion {
		case 4:
			want = ipproto.ICMPv4
		case 6:
			want = ipproto.ICMPv6
		}
		if p.IPProto != want {
			// A diversion from RunIn, which has a separate switch per IP
			// version and so lets an ICMP type that does not match the
			// packet's IP version fall through to its default case. Refusing
			// it outright seems unlikely to matter in practice.
			return false, ""
		}
		if p.IsEchoResponse() || p.IsError() {
			// ICMP responses are allowed.
			return true, connectorICMPResponseReason
		}
		if ranges.Len() > 0 {
			// If any port is open to an IP, allow ICMP to it.
			return true, connectorICMPReason
		}
	case ipproto.TCP:
		// A diversion from RunIn, which admits any packet that is not a lone
		// SYN so that return traffic for connections this node opened still
		// arrives. A connector never opens a connection towards its own
		// transit pool, so there is no return traffic to make room for here:
		// every TCP packet this hook sees travels peer -> transit IP, and the
		// datapath rewrites only addresses, never ports, so its destination
		// port is the app's port for the whole session rather than just at
		// the SYN. Holding every packet to the grant therefore costs nothing.
		// Exempting non-SYNs, on the other hand, would let a peer reach a
		// port the grant does not name, since what is admitted here is then
		// DNATed on to the app: an ACK scan of it, with a flow installed.
		for _, ppr := range ranges.All() {
			if (ppr.Proto == 0 || ppr.Proto == int(ipproto.TCP)) &&
				ppr.Ports.Contains(p.Dst.Port()) {
				return true, connectorTCPReason
			}
		}
	case ipproto.UDP, ipproto.SCTP:
		// A range naming no protocol covers UDP but not SCTP, matching the set
		// the packet filter uses for a [tailcfg.FilterRule] that names none.
		allowProtoless := p.IPProto == ipproto.UDP
		for _, ppr := range ranges.All() {
			if ((allowProtoless && ppr.Proto == 0) || ppr.Proto == int(p.IPProto)) &&
				ppr.Ports.Contains(p.Dst.Port()) {
				return true, connectorPortReason
			}
		}
	case ipproto.TSMP:
		// A diversion from RunIn, which allows TSMP unconditionally. It can,
		// because by then the packet has passed its local4/local6 check and
		// so is addressed to this node: tailnet signalling to us. Nothing
		// reaching here is. A transit IP stands in for an address out on the
		// app's network rather than for a node, so TSMP sent to one is not
		// signalling to anybody, and no grant should be able to make it so.
		//
		// Refusing it also suppresses no signalling, because tstun consumes
		// TSMP before the filter runs: pings and disco advertisements are
		// answered there and dropped silently without ever reaching here,
		// and pongs and rejection headers have already run their handlers by
		// the time we see them. Accepting would only hand the host stack a
		// packet addressed to something it has no route for.
		return false, ""
	default:
		// Protocols that carry no port have to be granted in full.
		for _, ppr := range ranges.All() {
			if ppr.Proto == int(p.IPProto) && ppr.Ports == tailcfg.PortRangeAny {
				return true, connectorPortlessReason
			}
		}
	}
	return false, ""
}

// appProtoPortRanges returns the protocol and port combinations peerCaps
// permits the peer to reach through app, as granted by the "ip" field of the
// grant that produced the peer's [peercap.Conn25Prefix] capability for it.
//
// It reports hasCap false if the peer holds no capability for app at all. A
// capability that is present but carries no values permits no traffic, and
// comes back as an empty slice with hasCap true: the app stays resolvable and
// registrable, which keeps the misconfiguration diagnosable, but
// [connector.ingressAllow] lets nothing through.
func appProtoPortRanges(peerCaps tailcfg.PeerCapMap, app string) (
	ranges views.Slice[tailcfg.ProtoPortRange],
	hasCap bool,
	err error,
) {
	appCap := peercap.Conn25Prefix.ToAttribute(app)
	if !peerCaps.HasCapability(appCap) {
		return ranges, false, nil
	}
	rs, err := tailcfg.UnmarshalCapJSON[tailcfg.ProtoPortRange](peerCaps, appCap)
	if err != nil {
		return ranges, true, err
	}
	return views.SliceOf(rs), true, nil
}
