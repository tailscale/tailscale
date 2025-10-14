// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netlogtype defines types for network logging.
package netlogtype

import (
	"net/netip"
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
