// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"inet.af/netaddr"
	"tailscale.com/net/netns"
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

type pcpMapping struct {
	gw       netaddr.IP
	internal netaddr.IPPort
	external netaddr.IPPort

	renewAfter time.Time
	goodUntil  time.Time
}

func (p *pcpMapping) GoodUntil() time.Time     { return p.goodUntil }
func (p *pcpMapping) RenewAfter() time.Time    { return p.renewAfter }
func (p *pcpMapping) External() netaddr.IPPort { return p.external }
func (p *pcpMapping) Release(ctx context.Context) {
	uc, err := netns.Listener().ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return
	}
	defer uc.Close()
	pkt := buildPCPRequestMappingPacket(p.internal.IP(), p.internal.Port(), p.external.Port(), 0)
	uc.WriteTo(pkt, netaddr.IPPortFrom(p.gw, pcpPort).UDPAddr())
}

// buildPCPRequestMappingPacket generates a PCP packet with a MAP opcode.
// To create a packet which deletes a mapping, lifetimeSec should be set to 0.
// If prevPort is not known, it should be set to 0.
func buildPCPRequestMappingPacket(myIP netaddr.IP, localPort, prevPort uint16, lifetimeSec uint32) (pkt []byte) {
	// note: lifetimeSec = 0 implies delete the mapping, should that be special-cased here?

	// 24 byte common PCP header + 36 bytes of MAP-specific fields
	pkt = make([]byte, 24+36)
	pkt[0] = pcpVersion
	pkt[1] = pcpOpMap
	binary.BigEndian.PutUint32(pkt[4:8], lifetimeSec)
	myIP16 := myIP.As16()
	copy(pkt[8:24], myIP16[:])

	mapOp := pkt[24:]
	rand.Read(mapOp[:12]) // 96 bit mapping nonce

	// TODO should this be a UDP mapping? It looks like it supports "all protocols" with 0, but
	// also doesn't support a local port then.
	mapOp[12] = pcpUDPMapping
	binary.BigEndian.PutUint16(mapOp[16:18], localPort)
	binary.BigEndian.PutUint16(mapOp[18:20], prevPort)

	v4unspec := netaddr.MustParseIP("0.0.0.0")
	v4unspec16 := v4unspec.As16()
	copy(mapOp[20:], v4unspec16[:])
	return pkt
}

func parsePCPMapResponse(resp []byte) (*pcpMapping, error) {
	if len(resp) < 60 {
		return nil, fmt.Errorf("Does not appear to be PCP MAP response")
	}
	res, ok := parsePCPResponse(resp[:24])
	if !ok {
		return nil, fmt.Errorf("Invalid PCP common header")
	}
	if res.ResultCode != pcpCodeOK {
		return nil, fmt.Errorf("PCP response not ok, code %d", res.ResultCode)
	}
	// TODO don't ignore the nonce and make sure it's the same?
	externalPort := binary.BigEndian.Uint16(resp[42:44])
	externalIPBytes := [16]byte{}
	copy(externalIPBytes[:], resp[44:])
	externalIP := netaddr.IPFrom16(externalIPBytes)

	external := netaddr.IPPortFrom(externalIP, externalPort)

	lifetime := time.Second * time.Duration(res.Lifetime)
	now := time.Now()
	mapping := &pcpMapping{
		external:   external,
		renewAfter: now.Add(lifetime / 2),
		goodUntil:  now.Add(lifetime),
	}

	return mapping, nil
}

// pcpAnnounceRequest generates a PCP packet with an ANNOUNCE opcode.
func pcpAnnounceRequest(myIP netaddr.IP) []byte {
	// See https://tools.ietf.org/html/rfc6887#section-7.1
	pkt := make([]byte, 24)
	pkt[0] = pcpVersion
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
