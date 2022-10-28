// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netlogtype defines types for network logging.
package netlogtype

import (
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
)

// TODO(joetsai): Remove "omitempty" if "omitzero" is ever supported in both
// the v1 and v2 "json" packages.

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

// ConnectionCounts is a flattened struct of both a connection and counts.
type ConnectionCounts struct {
	Connection
	Counts
}

// Connection is a 5-tuple of proto, source and destination IP and port.
type Connection struct {
	Proto ipproto.Proto  `json:"proto,omitzero,omitempty"`
	Src   netip.AddrPort `json:"src,omitzero"`
	Dst   netip.AddrPort `json:"dst,omitzero"`
}

func (c Connection) IsZero() bool { return c == Connection{} }

// Counts are statistics about a particular connection.
type Counts struct {
	TxPackets uint64 `json:"txPkts,omitzero,omitempty"`
	TxBytes   uint64 `json:"txBytes,omitzero,omitempty"`
	RxPackets uint64 `json:"rxPkts,omitzero,omitempty"`
	RxBytes   uint64 `json:"rxBytes,omitzero,omitempty"`
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
