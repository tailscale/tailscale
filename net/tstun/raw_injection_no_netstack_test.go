// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_netstack && ts_omit_gro

package tstun

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/packet"
)

func TestRawInjectionWithoutNetstack(t *testing.T) {
	w := &Wrapper{disableFilter: true}
	w.peerConfig.Store(&peerConfigTable{})
	payload := packet.Generate(&packet.UDP4Header{
		IP4Header: packet.IP4Header{
			Src: netip.MustParseAddr("100.64.0.1"),
			Dst: netip.MustParseAddr("100.64.0.2"),
		},
		SrcPort: 53,
		DstPort: 12345,
	}, []byte("dns response"))
	spacing := tun.ReadPacketSpacing
	slab := make([]byte, MaxPacketSize+2*spacing)
	packets := make([]tun.ReadPacket, 1)
	n, err := w.injectedRead(tunInjectedRead{data: payload}, slab, packets, spacing)
	if err != nil || n != 1 {
		t.Fatalf("injectedRead: n=%d, err=%v", n, err)
	}
	got := slab[packets[0].Offset : packets[0].Offset+packets[0].Size]
	if !bytes.Equal(got, payload) {
		t.Fatal("raw injected packet changed")
	}
}
