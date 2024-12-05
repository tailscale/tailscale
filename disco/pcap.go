// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package disco

import (
	"bytes"
	"encoding/binary"
	"net/netip"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// ToPCAPFrame marshals the bytes for a pcap record that describe a disco frame.
//
// Warning: Alloc garbage. Acceptable while capturing.
func ToPCAPFrame(src netip.AddrPort, derpNodeSrc key.NodePublic, payload []byte) []byte {
	var (
		b    bytes.Buffer
		flag uint8
	)
	b.Grow(128) // Most disco frames will probably be smaller than this.

	if src.Addr() == tailcfg.DerpMagicIPAddr {
		flag |= 0x01
	}
	b.WriteByte(flag) // 1b: flag

	derpSrc := derpNodeSrc.Raw32()
	b.Write(derpSrc[:])                                       // 32b: derp public key
	binary.Write(&b, binary.LittleEndian, uint16(src.Port())) // 2b: port
	addr, _ := src.Addr().MarshalBinary()
	binary.Write(&b, binary.LittleEndian, uint16(len(addr)))    // 2b: len(addr)
	b.Write(addr)                                               // Xb: addr
	binary.Write(&b, binary.LittleEndian, uint16(len(payload))) // 2b: len(payload)
	b.Write(payload)                                            // Xb: payload

	return b.Bytes()
}
