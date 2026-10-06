// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netstack

package tstun

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/net/packet"
	"tailscale.com/util/eventbus/eventbustest"
)

func injectionTestPayload(data []byte, viewSize int) buffer.Buffer {
	var payload buffer.Buffer
	for len(data) > 0 {
		n := min(viewSize, len(data))
		part := buffer.MakeWithData(data[:n])
		payload.Merge(&part)
		data = data[n:]
	}
	return payload
}

func TestInjectOutboundPacketBufferViews(t *testing.T) {
	for _, layout := range []string{"raw", "pushed", "consumed"} {
		for _, viewSize := range []int{7, 1280} {
			t.Run(fmt.Sprintf("%s/view=%d", layout, viewSize), func(t *testing.T) {
				h := &packet.UDP4Header{
					IP4Header: packet.IP4Header{Src: netip.MustParseAddr("1.2.3.4"), Dst: netip.MustParseAddr("5.6.7.8")},
					SrcPort:   98, DstPort: 98,
				}
				data := packet.Generate(h, bytes.Repeat([]byte{0x55}, 1280-h.Len()))
				body := data
				opts := stack.PacketBufferOptions{}
				if layout == "pushed" {
					body = data[28:]
					// Leave unused space before the pushed headers, so the
					// start of Data is not simply HeaderSize.
					opts.ReserveHeaderBytes = 128
				}
				opts.Payload = injectionTestPayload(body, viewSize)
				pkt := stack.NewPacketBuffer(opts)
				defer pkt.DecRef()
				switch layout {
				case "consumed":
					// Header consumption can merge views when headers cross
					// their boundaries; the payload may remain fragmented.
					if _, ok := pkt.NetworkHeader().Consume(20); !ok {
						t.Fatal("consume network header")
					}
					if _, ok := pkt.TransportHeader().Consume(8); !ok {
						t.Fatal("consume transport header")
					}
				case "pushed":
					// Link and virtio headers precede the network header but
					// are not part of the injected packet.
					copy(pkt.TransportHeader().Push(8), data[20:28])
					copy(pkt.NetworkHeader().Push(20), data[:20])
					copy(pkt.LinkHeader().Push(14), bytes.Repeat([]byte{0xaa}, 14))
					copy(pkt.VirtioNetHeader().Push(10), bytes.Repeat([]byte{0xbb}, 10))
				}
				original := pkt.Data().AsRange().ToSlice()
				_, w := newFakeTUN(t.Logf, eventbustest.NewBus(t), false)
				defer w.Close()
				w.Start()
				// Reuse the packet to detect accidental consumption or
				// mutation of its backing views while copying.
				for range 2 {
					if err := w.InjectOutboundPacketBuffer(pkt.IncRef()); err != nil {
						t.Fatal(err)
					}
					slab, packets := getSinglePacketReadArgs()
					n, err := w.InjectionQueue().Read(slab, packets)
					if n != 1 || err != nil {
						t.Fatalf("Read = %d, %v", n, err)
					}
					got := slab[packets[0].Offset : packets[0].Offset+packets[0].Size]
					if !bytes.Equal(got, data) {
						t.Fatalf("Read = %x, want %x", got, data)
					}
					if !bytes.Equal(pkt.Data().AsRange().ToSlice(), original) {
						t.Fatal("copy modified the packet payload")
					}
				}
			})
		}
	}
}

func TestInjectOutboundPacketBufferFragmentedGSO(t *testing.T) {
	const payloadLen, mss = 384, 64
	data := make([]byte, 40+payloadLen)
	src, dst := tcpip.AddrFrom4([4]byte{1, 2, 3, 4}), tcpip.AddrFrom4([4]byte{5, 6, 7, 8})
	ih := header.IPv4(data[:20])
	ih.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(data)), TTL: 64, Protocol: uint8(header.TCPProtocolNumber), SrcAddr: src, DstAddr: dst,
	})
	ih.SetChecksum(^ih.CalculateChecksum())
	th := header.TCP(data[20:40])
	th.Encode(&header.TCPFields{
		SrcPort: 1234, DstPort: 5678, SeqNum: 42, AckNum: 1, DataOffset: 20, Flags: header.TCPFlagAck | header.TCPFlagPsh,
	})
	th.SetChecksum(^tun.PseudoHeaderChecksum(uint8(header.TCPProtocolNumber), src.AsSlice(), dst.AsSlice(), payloadLen+20))
	for i := range data[40:] {
		data[40+i] = byte(i)
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 128,
		Payload:            injectionTestPayload(data[40:], 7),
	})
	defer pkt.DecRef()
	copy(pkt.TransportHeader().Push(20), data[20:40])
	copy(pkt.NetworkHeader().Push(20), data[:20])
	pkt.GSOOptions = stack.GSO{Type: stack.GSOTCPv4, NeedsCsum: true, CsumOffset: 16, MSS: mss, L3HdrLen: 20}
	gso, err := stackGSOToTunGSO(data, pkt.GSOOptions)
	if err != nil {
		t.Fatal(err)
	}
	wantSlab := make([]byte, MaxPacketSize+2*tun.ReadPacketSpacing)
	wantPackets := make([]tun.ReadPacket, payloadLen/mss)
	wantN, err := tun.GSOSplit(data, gso, wantSlab, wantPackets, tun.ReadPacketSpacing)
	if err != nil || wantN != len(wantPackets) {
		t.Fatalf("reference GSOSplit = %d, %v", wantN, err)
	}

	_, w := newFakeTUN(t.Logf, eventbustest.NewBus(t), false)
	defer w.Close()
	w.Start()
	if err := w.InjectOutboundPacketBuffer(pkt.IncRef()); err != nil {
		t.Fatal(err)
	}
	slab := make([]byte, len(wantSlab))
	packets := make([]tun.ReadPacket, len(wantPackets))
	n, err := w.InjectionQueue().Read(slab, packets)
	if err != nil || n != wantN {
		t.Fatalf("Read = %d, %v; want %d, nil", n, err, wantN)
	}
	for i, p := range packets[:n] {
		want := wantPackets[i]
		if !bytes.Equal(slab[p.Offset:p.Offset+p.Size], wantSlab[want.Offset:want.Offset+want.Size]) {
			t.Errorf("segment %d differs from reference GSOSplit", i)
		}
	}
	if !bytes.Equal(pkt.Data().AsRange().ToSlice(), data[40:]) {
		t.Error("GSO copy modified the packet payload")
	}
}
