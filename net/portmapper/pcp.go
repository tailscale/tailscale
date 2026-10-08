// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package portmapper

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// References:
//
// https://www.rfc-editor.org/rfc/pdfrfc/rfc6887.txt.pdf
// https://tools.ietf.org/html/rfc6887

//go:generate go run tailscale.com/cmd/addlicense -file pcpresultcode_string.go go run golang.org/x/tools/cmd/stringer -type=pcpResultCode -trimprefix=pcpCode

type pcpResultCode uint8

// PCP constants
const (
	pcpVersion     = 2
	pcpDefaultPort = 5351

	// Use the same lifetime as NAT-PMP given that we don't know how long
	// the IP assignment is valid for.
	pcpMapLifetimeSec = 7200

	pcpCodeOK            pcpResultCode = 0
	pcpCodeNotAuthorized pcpResultCode = 2
	// From RFC 6887:
	// ADDRESS_MISMATCH: The source IP address of the request packet does
	// not match the contents of the PCP Client's IP Address field, due
	// to an unexpected NAT on the path between the PCP client and the
	// PCP-controlled NAT or firewall.
	pcpCodeAddressMismatch pcpResultCode = 12

	pcpOpReply    = 0x80 // OR'd into request's op code on response
	pcpOpAnnounce = 0
	pcpOpMap      = 1

	pcpUDPMapping = 17 // portmap UDP
	pcpTCPMapping = 6  // portmap TCP
)

// A pcpNonce is a cookie assigned by the router when issuing a mapping, that
// the client retains in order to release or update the mapping later.
type pcpNonce [12]byte

type pcpMapping struct {
	c        *Client
	gw       netip.AddrPort
	internal netip.AddrPort
	external netip.AddrPort

	renewAfter time.Time
	goodUntil  time.Time

	epoch uint32
	nonce pcpNonce
}

func (p *pcpMapping) MappingType() string      { return "pcp" }
func (p *pcpMapping) GoodUntil() time.Time     { return p.goodUntil }
func (p *pcpMapping) RenewAfter() time.Time    { return p.renewAfter }
func (p *pcpMapping) External() netip.AddrPort { return p.external }
func (p *pcpMapping) MappingDebug() string {
	return fmt.Sprintf("pcpMapping{gw:%v, external:%v, internal:%v, renewAfter:%d, goodUntil:%d, nonce:%x}",
		p.gw, p.external, p.internal,
		p.renewAfter.Unix(), p.goodUntil.Unix(), p.nonce)
}

func (p *pcpMapping) Release(ctx context.Context) {
	uc, err := p.c.listenPacket(ctx, "udp4", ":0")
	if err != nil {
		return
	}
	defer uc.Close()
	// Per RFC 6887 section 15.1 (with Errata ID 3621), a mapping-delete
	// request (lifetime 0) MUST set the Suggested External Port to zero and
	// the Suggested External Address to the all-zeros address of the family
	// being deleted: ::ffff:0.0.0.0 for IPv4, :: for IPv6.
	zeroExtAddr := netip.IPv4Unspecified()
	if p.external.Addr().Is6() {
		zeroExtAddr = netip.IPv6Unspecified()
	}
	pkt := buildPCPRequestMappingPacket(p.internal.Addr(), p.internal.Port(), 0, 0, zeroExtAddr, p.nonce)
	uc.WriteToUDPAddrPort(pkt, p.gw)
}

// buildPCPRequestMappingPacket generates a PCP packet with a MAP opcode.
// To create a packet which deletes a mapping, lifetimeSec, prevPort and prevExternalIP should be set to 0.
// If prevPort is not known, it should be set to 0.
// If prevExternalIP is not known, it should be set to 0.0.0.0.
// Renewing or deleting a mapping must reuse the nonce from the original response.
func buildPCPRequestMappingPacket(
	myIP netip.Addr,
	localPort, prevPort uint16,
	lifetimeSec uint32,
	prevExternalIP netip.Addr,
	nonce pcpNonce,
) (pkt []byte) {
	// 24 byte common PCP header + 36 bytes of MAP-specific fields
	pkt = make([]byte, 24+36)
	pkt[0] = pcpVersion
	pkt[1] = pcpOpMap
	binary.BigEndian.PutUint32(pkt[4:8], lifetimeSec)
	myIP16 := myIP.As16()
	copy(pkt[8:24], myIP16[:])

	mapOp := pkt[24:]
	copy(mapOp[:12], nonce[:])

	mapOp[12] = pcpUDPMapping
	binary.BigEndian.PutUint16(mapOp[16:18], localPort)
	binary.BigEndian.PutUint16(mapOp[18:20], prevPort)

	prevExternalIP16 := prevExternalIP.As16()
	copy(mapOp[20:], prevExternalIP16[:])
	return pkt
}

// parsePCPMapResponse parses resp into a partially populated pcpMapping.
// In particular, its Client is not populated.
func parsePCPMapResponse(resp []byte) (*pcpMapping, error) {
	if len(resp) < 60 {
		return nil, fmt.Errorf("Does not appear to be PCP MAP response")
	}
	res, ok := parsePCPResponse(resp[:24])
	if !ok {
		return nil, fmt.Errorf("Invalid PCP common header")
	}
	if res.ResultCode == pcpCodeNotAuthorized {
		return nil, fmt.Errorf("PCP is implemented but not enabled in the router")
	}
	if res.ResultCode != pcpCodeOK {
		return nil, fmt.Errorf("PCP response not ok, code %d", res.ResultCode)
	}
	externalPort := binary.BigEndian.Uint16(resp[42:44])
	externalIPBytes := [16]byte{}
	copy(externalIPBytes[:], resp[44:])
	externalIP := netip.AddrFrom16(externalIPBytes).Unmap()

	external := netip.AddrPortFrom(externalIP, externalPort)

	lifetime := time.Second * time.Duration(res.Lifetime)
	now := time.Now()
	mapping := &pcpMapping{
		external:   external,
		renewAfter: now.Add(lifetime / 2),
		goodUntil:  now.Add(lifetime),
		epoch:      res.Epoch,
	}
	copy(mapping.nonce[:], resp[24:36])

	return mapping, nil
}

// pcpAnnounceRequest generates a PCP packet with an ANNOUNCE opcode.
func pcpAnnounceRequest(myIP netip.Addr) []byte {
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
	ResultCode pcpResultCode
	Lifetime   uint32
	Epoch      uint32
}

func parsePCPResponse(b []byte) (res pcpResponse, ok bool) {
	if len(b) < 24 || b[0] != pcpVersion {
		return
	}
	res.OpCode = b[1]
	res.ResultCode = pcpResultCode(b[3])
	res.Lifetime = binary.BigEndian.Uint32(b[4:])
	res.Epoch = binary.BigEndian.Uint32(b[8:])
	return res, true
}
