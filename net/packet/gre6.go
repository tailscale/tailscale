// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"tailscale.com/types/ipproto"
)

// GRE6Header is an IPv6 header.
type GRE6Header struct {
	IP6Header
}

// Len implements Header.
func (h GRE6Header) Len() int {
	return h.IP6Header.Len() // + greHeaderLength  // Treats GRE header as a part of data
}

// Marshal implements Header.
func (h GRE6Header) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	// The caller does not need to set this.
	h.IPProto = ipproto.GRE

	h.IP6Header.Marshal(buf)

	return nil
}

// ToResponse implements Header.
func (h *GRE6Header) ToResponse() {
	h.IP6Header.ToResponse()
}
