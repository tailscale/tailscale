// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"crypto/rand"
	"encoding/binary"

	"inet.af/netaddr"
)

// References:
//
// https://www.rfc-editor.org/rfc/pdfrfc/rfc6887.txt.pdf
// https://tools.ietf.org/html/rfc6887

// PCP constants
const (
	pcpVersion = 2
	pcpPort    = 5351

	pcpMapLifetimeSec = 7200 // TODO does the RFC recommend anything? This is taken from PMP.

	pcpCodeOK            = 0
	pcpCodeNotAuthorized = 2

	pcpOpReply    = 0x80 // OR'd into request's op code on response
	pcpOpAnnounce = 0
	pcpOpMap      = 1

	pcpUDPMapping = 17 // portmap UDP
	pcpTCPMapping = 6  // portmap TCP
)

// pcpMapRequest generates a PCP packet with a MAP opcode.
func pcpMapRequest(myIP netaddr.IP, mapToLocalPort int, delete bool) []byte {
	const udpProtoNumber = 17
	lifetimeSeconds := uint32(1)
	if delete {
		lifetimeSeconds = 0
	}
	const opMap = 1

	// 24 byte header + 36 byte map opcode
	pkt := make([]byte, (32+32+128)/8+(96+8+24+16+16+128)/8)

	// The header (https://tools.ietf.org/html/rfc6887#section-7.1)
	pkt[0] = 2 // version
	pkt[1] = opMap
	binary.BigEndian.PutUint32(pkt[4:8], lifetimeSeconds)
	myIP16 := myIP.As16()
	copy(pkt[8:], myIP16[:])

	// The map opcode body (https://tools.ietf.org/html/rfc6887#section-11.1)
	mapOp := pkt[24:]
	rand.Read(mapOp[:12]) // 96 bit mappping nonce
	mapOp[12] = udpProtoNumber
	binary.BigEndian.PutUint16(mapOp[16:], uint16(mapToLocalPort))
	v4unspec := netaddr.MustParseIP("0.0.0.0")
	v4unspec16 := v4unspec.As16()
	copy(mapOp[20:], v4unspec16[:])
	return pkt
}

// pcpAnnounceRequest generates a PCP packet with an ANNOUNCE opcode.
func pcpAnnounceRequest(myIP netaddr.IP) []byte {
	// See https://tools.ietf.org/html/rfc6887#section-7.1
	pkt := make([]byte, 24)
	pkt[0] = pcpVersion // version
	pkt[1] = pcpOpAnnounce
	myIP16 := myIP.As16()
	copy(pkt[8:], myIP16[:])
	return pkt
}

type pcpResponse struct {
	OpCode     uint8
	ResultCode uint8
	Lifetime   uint32
	Epoch      uint32
}

func parsePCPResponse(b []byte) (res pcpResponse, ok bool) {
	if len(b) < 24 || b[0] != pcpVersion {
		return
	}
	res.OpCode = b[1]
	res.ResultCode = b[3]
	res.Lifetime = binary.BigEndian.Uint32(b[4:])
	res.Epoch = binary.BigEndian.Uint32(b[8:])
	return res, true
}
