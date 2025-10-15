// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netlogtype defines types for network logging.
package netlogtype

import (
	"maps"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
)

// Message is the log message that captures network traffic.
type Message struct {
	NodeID tailcfg.StableNodeID `json:"nodeId"` // e.g., "n123456CNTRL"

	Start time.Time `json:"start"` // inclusive
	End   time.Time `json:"end"`   // inclusive

	VirtualTraffic  []ConnectionCounts `json:"virtualTraffic,omitempty"`
	SubnetTraffic   []ConnectionCounts `json:"subnetTraffic,omitempty"`
	ExitTraffic     []ConnectionCounts `json:"exitTraffic,omitempty"`
	PhysicalTraffic []ConnectionCounts `json:"physicalTraffic,omitempty"`
}

const (
	messageJSON      = `{"nodeId":"n0123456789abcdefCNTRL",` + maxJSONTimeRange + `,` + minJSONTraffic + `}`
	maxJSONTimeRange = `"start":` + maxJSONRFC3339 + `,"end":` + maxJSONRFC3339
	maxJSONRFC3339   = `"0001-01-01T00:00:00.000000000Z"`
	minJSONTraffic   = `"virtualTraffic":{},"subnetTraffic":{},"exitTraffic":{},"physicalTraffic":{}`

	// MaxMessageJSONSize is the overhead size of Message when it is
	// serialized as JSON assuming that each traffic map is populated.
	MaxMessageJSONSize = len(messageJSON)

	maxJSONConnCounts = `{` + maxJSONConn + `,` + maxJSONCounts + `}`
	maxJSONConn       = `"proto":` + maxJSONProto + `,"src":` + maxJSONAddrPort + `,"dst":` + maxJSONAddrPort
	maxJSONProto      = `255`
	maxJSONAddrPort   = `"[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"`
	maxJSONCounts     = `"txPkts":` + maxJSONCount + `,"txBytes":` + maxJSONCount + `,"rxPkts":` + maxJSONCount + `,"rxBytes":` + maxJSONCount
	maxJSONCount      = `18446744073709551615`

	// MaxConnectionCountsJSONSize is the maximum size of a ConnectionCounts
	// when it is serialized as JSON, assuming no superfluous whitespace.
	// It does not include the trailing comma that often appears when
	// this object is nested within an array.
	// It assumes that netip.Addr never has IPv6 zones.
	MaxConnectionCountsJSONSize = len(maxJSONConnCounts)
)

// ConnectionCounts is a flattened struct of both a connection and counts.
type ConnectionCounts struct {
	Connection
	Counts
}

// Connection is a 5-tuple of proto, source and destination IP and port.
type Connection struct {
	Proto ipproto.Proto  `json:"proto,omitzero"`
	Src   netip.AddrPort `json:"src,omitzero"`
	Dst   netip.AddrPort `json:"dst,omitzero"`
}

func (c Connection) IsZero() bool { return c == Connection{} }

// Counts are statistics about a particular connection.
type Counts struct {
	TxPackets uint64 `json:"txPkts,omitzero"`
	TxBytes   uint64 `json:"txBytes,omitzero"`
	RxPackets uint64 `json:"rxPkts,omitzero"`
	RxBytes   uint64 `json:"rxBytes,omitzero"`
}

func (c Counts) IsZero() bool { return c == Counts{} }

// Add adds the counts from both c1 and c2.
func (c1 Counts) Add(c2 Counts) Counts {
	c1.TxPackets += c2.TxPackets
	c1.TxBytes += c2.TxBytes
	c1.RxPackets += c2.RxPackets
	c1.RxBytes += c2.RxBytes
	return c1
}

// CountsByConnection is a count of packets and bytes for each connection.
// All methods are safe for concurrent calls.
type CountsByConnection struct {
	mu sync.Mutex
	m  map[Connection]Counts
}

// Add adds packets and bytes for the specified connection.
func (c *CountsByConnection) Add(proto ipproto.Proto, src, dst netip.AddrPort, packets, bytes int, recv bool) {
	conn := Connection{Proto: proto, Src: src, Dst: dst}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[Connection]Counts)
	}
	cnts := c.m[conn]
	if recv {
		cnts.RxPackets += uint64(packets)
		cnts.RxBytes += uint64(bytes)
	} else {
		cnts.TxPackets += uint64(packets)
		cnts.TxBytes += uint64(bytes)
	}
	c.m[conn] = cnts
}

// Clone deep copies the map.
func (c *CountsByConnection) Clone() map[Connection]Counts {
	c.mu.Lock()
	defer c.mu.Unlock()
	return maps.Clone(c.m)
}

// Reset clear the map.
func (c *CountsByConnection) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.m)
}
