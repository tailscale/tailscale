// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netlog && !ts_omit_logtail

package netlog

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"tailscale.com/tailcfg"
	"tailscale.com/types/bools"
	"tailscale.com/types/netlogtype"
	"tailscale.com/util/set"
)

// maxLogSize is the maximum number of bytes for a log message.
const maxLogSize = 256 << 10

// record is the in-memory representation of a [netlogtype.Message].
// It uses maps to efficiently look-up addresses and connections.
// In contrast, [netlogtype.Message] is designed to be JSON serializable,
// where complex keys types are not well support in JSON objects.
type record struct {
	selfNode nodeUser

	start time.Time
	end   time.Time

	seenNodes map[netip.Addr]nodeUser

	virtConns map[netlogtype.Connection]countsType
	physConns map[netlogtype.Connection]netlogtype.Counts
}

// nodeUser is a node with additional user profile information.
type nodeUser struct {
	tailcfg.NodeView
	user tailcfg.UserProfileView // UserProfileView for NodeView.User
}

// countsType is a counts with classification information about the connection.
type countsType struct {
	netlogtype.Counts
	connType connType
}

type connType uint8

const (
	unknownTraffic connType = iota
	virtualTraffic
	subnetTraffic
	exitTraffic
)

// toMessage converts a [record] into a [netlogtype.Message].
func (r record) toMessage(excludeNodeInfo, anonymizeExitTraffic bool) netlogtype.Message {
	if !r.selfNode.Valid() {
		return netlogtype.Message{}
	}

	m := netlogtype.Message{
		NodeID: r.selfNode.StableID(),
		Start:  r.start.UTC(),
		End:    r.end.UTC(),
	}

	// Convert node fields.
	if !excludeNodeInfo {
		m.SrcNode = r.selfNode.toNode()
		seenIDs := set.Of(r.selfNode.ID())
		for _, node := range r.seenNodes {
			if _, ok := seenIDs[node.ID()]; !ok && node.Valid() {
				m.DstNodes = append(m.DstNodes, node.toNode())
				seenIDs.Add(node.ID())
			}
		}
		slices.SortFunc(m.DstNodes, func(x, y netlogtype.Node) int {
			return cmp.Compare(x.NodeID, y.NodeID)
		})
	}

	// Converter traffic fields.
	anonymizedExitTraffic := make(map[netlogtype.Connection]netlogtype.Counts)
	for conn, cnts := range r.virtConns {
		switch cnts.connType {
		case virtualTraffic:
			m.VirtualTraffic = append(m.VirtualTraffic, netlogtype.ConnectionCounts{Connection: conn, Counts: cnts.Counts})
		case subnetTraffic:
			m.SubnetTraffic = append(m.SubnetTraffic, netlogtype.ConnectionCounts{Connection: conn, Counts: cnts.Counts})
		default:
			if anonymizeExitTraffic {
				conn = netlogtype.Connection{ // scrub the IP protocol type
					Src: netip.AddrPortFrom(conn.Src.Addr(), 0), // scrub the port number
					Dst: netip.AddrPortFrom(conn.Dst.Addr(), 0), // scrub the port number
				}
				if !r.seenNodes[conn.Src.Addr()].Valid() {
					conn.Src = netip.AddrPort{} // not a Tailscale node, so scrub the address
				}
				if !r.seenNodes[conn.Dst.Addr()].Valid() {
					conn.Dst = netip.AddrPort{} // not a Tailscale node, so scrub the address
				}
				anonymizedExitTraffic[conn] = anonymizedExitTraffic[conn].Add(cnts.Counts)
				continue
			}
			m.ExitTraffic = append(m.ExitTraffic, netlogtype.ConnectionCounts{Connection: conn, Counts: cnts.Counts})
		}
	}
	for conn, cnts := range anonymizedExitTraffic {
		m.ExitTraffic = append(m.ExitTraffic, netlogtype.ConnectionCounts{Connection: conn, Counts: cnts})
	}
	for conn, cnts := range r.physConns {
		m.PhysicalTraffic = append(m.PhysicalTraffic, netlogtype.ConnectionCounts{Connection: conn, Counts: cnts})
	}

	// Sort the connections for deterministic results.
	slices.SortFunc(m.VirtualTraffic, compareConnCnts)
	slices.SortFunc(m.SubnetTraffic, compareConnCnts)
	slices.SortFunc(m.ExitTraffic, compareConnCnts)
	slices.SortFunc(m.PhysicalTraffic, compareConnCnts)

	return m
}

func compareConnCnts(x, y netlogtype.ConnectionCounts) int {
	return cmp.Or(
		netip.AddrPort.Compare(x.Src, y.Src),
		netip.AddrPort.Compare(x.Dst, y.Dst),
		cmp.Compare(x.Proto, y.Proto))
}

// jsonLen computes an upper-bound on the size of the JSON representation.
func (nu nodeUser) jsonLen() (n int) {
	if !nu.Valid() {
		return len(`{"nodeId":""}`)
	}
	n += len(`{}`)
	n += len(`"nodeId":`) + jsonQuotedLen(string(nu.StableID())) + len(`,`)
	if len(nu.Name()) > 0 {
		n += len(`"name":`) + jsonQuotedLen(nu.Name()) + len(`,`)
	}
	if nu.Addresses().Len() > 0 {
		n += len(`"addresses":[]`)
		for _, addr := range nu.Addresses().All() {
			n += bools.IfElse(addr.Addr().Is4(), len(`"255.255.255.255"`), len(`"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"`)) + len(",")
		}
	}
	if nu.Hostinfo().Valid() && len(nu.Hostinfo().OS()) > 0 {
		n += len(`"os":`) + jsonQuotedLen(nu.Hostinfo().OS()) + len(`,`)
	}
	if nu.Tags().Len() > 0 {
		n += len(`"tags":[]`)
		for _, tag := range nu.Tags().All() {
			n += jsonQuotedLen(tag) + len(",")
		}
	} else if nu.user.Valid() && nu.user.ID() == nu.User() && len(nu.user.LoginName()) > 0 {
		n += len(`"user":`) + jsonQuotedLen(nu.user.LoginName()) + len(",")
	}
	return n
}

// toNode converts the [nodeUser] into a [netlogtype.Node].
func (nu nodeUser) toNode() netlogtype.Node {
	if !nu.Valid() {
		return netlogtype.Node{}
	}
	n := netlogtype.Node{
		NodeID: nu.StableID(),
		Name:   strings.TrimSuffix(nu.Name(), "."),
	}
	var ipv4, ipv6 netip.Addr
	for _, addr := range nu.Addresses().All() {
		switch {
		case addr.IsSingleIP() && addr.Addr().Is4():
			ipv4 = addr.Addr()
		case addr.IsSingleIP() && addr.Addr().Is6():
			ipv6 = addr.Addr()
		}
	}
	n.Addresses = []netip.Addr{ipv4, ipv6}
	n.Addresses = slices.DeleteFunc(n.Addresses, func(a netip.Addr) bool { return !a.IsValid() })
	if nu.Hostinfo().Valid() {
		n.OS = nu.Hostinfo().OS()
	}
	if nu.Tags().Len() > 0 {
		n.Tags = nu.Tags().AsSlice()
		slices.Sort(n.Tags)
		n.Tags = slices.Compact(n.Tags)
	} else if nu.user.Valid() && nu.user.ID() == nu.User() {
		n.User = nu.user.LoginName()
	}
	return n
}

// jsonQuotedLen computes the length of the JSON serialization of s
// according to [jsontext.AppendQuote].
func jsonQuotedLen(s string) int {
	n := len(`"`) + len(s) + len(`"`)
	for i, r := range s {
		switch {
		case r == '\b', r == '\t', r == '\n', r == '\f', r == '\r', r == '"', r == '\\':
			n += len(`\X`) - 1
		case r < ' ':
			n += len(`\uXXXX`) - 1
		case r == utf8.RuneError:
			if _, m := utf8.DecodeRuneInString(s[i:]); m == 1 { // exactly an invalid byte
				n += len("�") - 1
			}
		}
	}
	return n
}
