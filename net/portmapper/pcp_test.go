// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package portmapper

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"tailscale.com/net/netaddr"
)

var examplePCPMapResponse = []byte{2, 129, 0, 0, 0, 0, 28, 32, 0, 2, 155, 237, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 112, 9, 24, 241, 208, 251, 45, 157, 76, 10, 188, 17, 0, 0, 0, 4, 210, 4, 210, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 135, 180, 175, 246}

func TestParsePCPMapResponse(t *testing.T) {
	mapping, err := parsePCPMapResponse(examplePCPMapResponse)
	if err != nil {
		t.Fatalf("failed to parse PCP Map Response: %v", err)
	}
	if mapping == nil {
		t.Fatalf("got nil mapping when expected non-nil")
	}
	expectedAddr := netip.MustParseAddrPort("135.180.175.246:1234")
	if mapping.external != expectedAddr {
		t.Errorf("mismatched external address, got: %v, want: %v", mapping.external, expectedAddr)
	}
	if got, want := mapping.nonce[:], examplePCPMapResponse[24:36]; !bytes.Equal(got, want) {
		t.Errorf("mismatched mapping nonce, got %x, want %x", got, want)
	}
}

func TestBuildPCPRequestMappingPacketWithNonce(t *testing.T) {
	nonce := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	pkt := buildPCPRequestMappingPacketWithNonce(
		netip.MustParseAddr("192.0.2.1"), 41641, 4242, 0, netip.MustParseAddr("198.51.100.1"), nonce,
	)
	if got := pkt[24:36]; !bytes.Equal(got, nonce[:]) {
		t.Errorf("mismatched mapping nonce, got %x, want %x", got, nonce)
	}
}

const (
	serverResponseBit = 1 << 7
	fakeLifetimeSec   = 1<<31 - 1
)

func buildPCPDiscoResponse(req []byte) []byte {
	out := make([]byte, 24)
	out[0] = pcpVersion
	out[1] = req[1] | serverResponseBit
	out[3] = 0
	// Do not put an epoch time in 8:12, when we start using it, tests that use it should fail.
	return out
}

func buildPCPMapResponse(req []byte) []byte {
	out := make([]byte, 24+36)
	out[0] = pcpVersion
	out[1] = req[1] | serverResponseBit
	out[3] = 0
	binary.BigEndian.PutUint32(out[4:8], 1<<30)
	// Do not put an epoch time in 8:12, when we start using it, tests that use it should fail.
	mapResp := out[24:]
	mapReq := req[24:]
	// copy nonce, protocol and internal port
	copy(mapResp[:13], mapReq[:13])
	copy(mapResp[16:18], mapReq[16:18])
	// assign external port
	binary.BigEndian.PutUint16(mapResp[18:20], 4242)
	assignedIP := netaddr.IPv4(127, 0, 0, 1)
	assignedIP16 := assignedIP.As16()
	copy(mapResp[20:36], assignedIP16[:])
	return out
}
