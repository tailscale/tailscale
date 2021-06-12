// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"tailscale.com/types/ipproto"
)

// greHeaderLength is the size of the GRE packet header, not including
// the outer IP header.
const greHeaderLength = 4

// GRE4Header is an IPv4 header.
type GRE4Header struct {
	IP4Header
}

// Len implements Header.
func (h GRE4Header) Len() int {
	return h.IP4Header.Len() // + greHeaderLength // Treats GRE header as a part of data
}

// Marshal implements Header.
func (h GRE4Header) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	// The caller does not need to set this.
	h.IPProto = ipproto.GRE

	h.IP4Header.Marshal(buf)

	return nil
}

// ToResponse implements Header.
func (h *GRE4Header) ToResponse() {
	h.IP4Header.ToResponse()
}
