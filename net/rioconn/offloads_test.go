// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package rioconn

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/ipv6"
	"tailscale.com/net/packet"
)

func TestCoalescePackets(t *testing.T) {
	geneve := packet.GeneveHeader{
		Protocol: packet.GeneveProtocolWireGuard,
	}
	geneve.VNI.Set(7)

	tests := []struct {
		name                string
		buffs               [][]byte
		offset              int
		geneve              packet.GeneveHeader
		dst                 []byte
		maxCoalescedPackets int
		maxCoalescedBytes   int
		wantBytes           []byte
		wantPackets         int
		wantPacketSize      int
		wantErr             bool
	}{
		{
			name:           "no-packets",
			buffs:          nil,
			geneve:         packet.GeneveHeader{},
			dst:            make([]byte, 100),
			wantBytes:      nil,
			wantPackets:    0,
			wantPacketSize: 0,
		},
		{
			name: "single-packet",
			buffs: [][]byte{
				{0x01, 0x02, 0x03},
			},
			geneve: packet.GeneveHeader{},
			dst:    make([]byte, 100),
			wantBytes: []byte{
				0x01, 0x02, 0x03,
			},
			wantPackets:    1,
			wantPacketSize: 3,
		},
		{
			name: "single-packet/zero-length",
			buffs: [][]byte{
				{},
			},
			geneve:         packet.GeneveHeader{},
			dst:            make([]byte, 100),
			wantBytes:      []byte{},
			wantPackets:    1,
			wantPacketSize: 0,
		},
		{
			name: "single-packet/with-offset",
			buffs: [][]byte{
				{
					0x00, 0x00,
					0x01, 0x02, 0x03,
				},
			},
			offset: 2,
			dst:    make([]byte, 100),
			wantBytes: []byte{
				0x01, 0x02, 0x03,
			},
			wantPackets:    1,
			wantPacketSize: 3,
		},
		{
			name: "single-packet/with-geneve",
			buffs: [][]byte{
				{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Geneve header space
					0x01, 0x02, 0x03,
				},
			},
			offset: 8,
			geneve: geneve,
			dst:    make([]byte, 100),
			wantBytes: []byte{
				0x00, 0x00, 0x7a, 0x12, 0x00, 0x00, 0x07, 0x00, // Geneve header
				0x01, 0x02, 0x03,
			},
			wantPackets:    1,
			wantPacketSize: 11, // 8 bytes Geneve header + 3 bytes packet
		},
		{
			name: "single-packet/exact-fit",
			buffs: [][]byte{
				{0x01, 0x02, 0x03},
			},
			dst:            make([]byte, 3),
			wantBytes:      []byte{0x01, 0x02, 0x03},
			wantPackets:    1,
			wantPacketSize: 3,
		},
		{
			name: "single-packet/too-large-for-dst",
			buffs: [][]byte{
				{0x01, 0x02, 0x03},
			},
			dst:     make([]byte, 2),
			wantErr: true,
		},
		{
			name: "single-packet/with-geneve/too-large-for-dst",
			buffs: [][]byte{
				{0x01, 0x02, 0x03},
			},
			geneve:  geneve,
			dst:     make([]byte, 10), // smaller than 8 bytes Geneve header + 3 bytes packet
			wantErr: true,
		},
		{
			name: "multiple-packets/coalesce-all",
			buffs: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06},
				{0x07, 0x08, 0x09},
			},
			dst: make([]byte, 100),
			wantBytes: []byte{
				0x01, 0x02, 0x03,
				0x04, 0x05, 0x06,
				0x07, 0x08, 0x09,
			},
			wantPackets:    3,
			wantPacketSize: 3,
		},
		{
			name: "multiple-packets/coalesce-all/with-offset",
			buffs: [][]byte{
				{0x00, 0x00, 0x01, 0x02, 0x03},
				{0x00, 0x00, 0x04, 0x05, 0x06},
				{0x00, 0x00, 0x07, 0x08, 0x09},
			},
			offset: 2,
			dst:    make([]byte, 100),
			wantBytes: []byte{
				0x01, 0x02, 0x03,
				0x04, 0x05, 0x06,
				0x07, 0x08, 0x09,
			},
			wantPackets:    3,
			wantPacketSize: 3,
		},
		{
			name: "multiple-packets/smaller-packet-ends-batch",
			buffs: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06},
				{0x07, 0x08},       // will be coalesced, but ends the batch
				{0x09, 0x0a, 0x0b}, // will not be coalesced in this batch
			},
			dst: make([]byte, 100),
			wantBytes: []byte{
				0x01, 0x02, 0x03,
				0x04, 0x05, 0x06,
				0x07, 0x08,
			},
			wantPackets:    3,
			wantPacketSize: 3,
		},
		{
			name: "multiple-packets/larger-packet-ends-batch",
			buffs: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06},
				{0x07, 0x08, 0x09, 0x0a}, // will not be coalesced in this batch

			},
			dst: make([]byte, 100),
			wantBytes: []byte{
				0x01, 0x02, 0x03,
				0x04, 0x05, 0x06,
			},
			wantPackets:    2,
			wantPacketSize: 3,
		},
		{
			name: "multiple-packets/partial-fit",
			buffs: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06},
				{0x07, 0x08, 0x09}, // could be coalesced, but won't fit

			},
			dst: make([]byte, 7), // can only fit the first two packets
			wantBytes: []byte{
				0x01, 0x02, 0x03,
				0x04, 0x05, 0x06,
			},
			wantPackets:    2,
			wantPacketSize: 3,
			wantErr:        false, // partial fit is not an error
		},
		{
			name: "multiple-packets/exact-fit",
			buffs: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06},
				{0x07, 0x08, 0x09},
			},
			dst: make([]byte, 9), // can exactly fit all three packets
			wantBytes: []byte{
				0x01, 0x02, 0x03,
				0x04, 0x05, 0x06,
				0x07, 0x08, 0x09,
			},
			wantPackets:    3,
			wantPacketSize: 3,
		},
		{
			name: "multiple-packets/with-geneve",
			buffs: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06},
				{0x07, 0x08, 0x09},
				{0x0a, 0x0b}, // ends the batch
				{0x0c, 0x0d, 0x0e},
			},
			geneve: geneve,
			dst:    make([]byte, 100),
			wantBytes: []byte{
				0x00, 0x00, 0x7a, 0x12, 0x00, 0x00, 0x07, 0x00, // Geneve header for first packet
				0x01, 0x02, 0x03,
				0x00, 0x00, 0x7a, 0x12, 0x00, 0x00, 0x07, 0x00, // Geneve header for second packet
				0x04, 0x05, 0x06,
				0x00, 0x00, 0x7a, 0x12, 0x00, 0x00, 0x07, 0x00, // Geneve header for third packet
				0x07, 0x08, 0x09,
				0x00, 0x00, 0x7a, 0x12, 0x00, 0x00, 0x07, 0x00, // Geneve header for fourth packet
				0x0a, 0x0b,
			},
			wantPackets:    4,
			wantPacketSize: 11, // 8 bytes Geneve header + 3 bytes packet
			wantErr:        false,
		},
		{
			name: "multiple-packets/all-zero-length",
			buffs: [][]byte{
				{},
				{},
				{},
			},
			dst:            make([]byte, 100),
			wantBytes:      []byte{},
			wantPackets:    1, // zero-length packets cannot be coalesced
			wantPacketSize: 0,
		},
		{
			name: "multiple-packets/all-zero-length/with-geneve",
			buffs: [][]byte{
				{},
				{},
				{},
			},
			geneve: geneve,
			dst:    make([]byte, 100),
			wantBytes: []byte{
				0x00, 0x00, 0x7a, 0x12, 0x00, 0x00, 0x07, 0x00, // Geneve header for first packet
				0x00, 0x00, 0x7a, 0x12, 0x00, 0x00, 0x07, 0x00, // Geneve header for second packet
				0x00, 0x00, 0x7a, 0x12, 0x00, 0x00, 0x07, 0x00, // Geneve header for third packet
			},
			wantPackets:    3,
			wantPacketSize: 8, // Geneve header size, since the packets are zero-length
		},
		{
			name: "multiple-packets/zero-length-packet-ends-batch",
			buffs: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06},
				{}, // cannot be coalesced, ends the batch

			},
			dst: make([]byte, 100),
			wantBytes: []byte{
				0x01, 0x02, 0x03,
				0x04, 0x05, 0x06,
			},
			wantPackets:    2,
			wantPacketSize: 3,
		},
		{
			name: "invalid-geneve-header",
			buffs: [][]byte{
				{0x01, 0x02, 0x03},
			},
			geneve: packet.GeneveHeader{
				Version: 0xFF,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(1000, func() {
				gotPackets, gotBytes, gotPacketSize, err := coalescePackets(
					tt.dst, tt.geneve, tt.buffs, tt.offset,
					tt.maxCoalescedPackets,
					tt.maxCoalescedBytes,
				)
				if (err != nil) != tt.wantErr {
					t.Fatalf("error: got %v; want error: %v", err, tt.wantErr)
				}
				if gotPackets != tt.wantPackets {
					t.Errorf("packets: got %d; want %d", gotPackets, tt.wantPackets)
				}
				if gotBytes := tt.dst[:gotBytes]; !bytes.Equal(gotBytes, tt.wantBytes) {
					t.Errorf("bytes: got %v; want %v", gotBytes, tt.wantBytes)
				}
				if gotPacketSize != tt.wantPacketSize {
					t.Errorf("packet size: got %d; want %d", gotPacketSize, tt.wantPacketSize)
				}
			})
			// Coalescing packets should not cause any allocations,
			// except for when it returns an error.
			if !tt.wantErr && allocs != 0 {
				t.Errorf("unexpected allocations: got %f; want 0", allocs)
			}
		})
	}
}

func TestSplitCoalescedPackets(t *testing.T) {
	addr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.0:50000"))

	tests := []struct {
		name        string
		addr        *net.UDPAddr
		src         []byte
		packetSize  int
		msgs        []ipv6.Message
		wantMsgs    []ipv6.Message
		wantPackets int
		wantBytes   int
	}{
		{
			name: "single-packet/zero-length",
			addr: addr,
			src:  []byte{}, // zero-length src is treated as a single zero-length packet
			msgs: makeMessages(2, 10),
			wantMsgs: []ipv6.Message{
				{
					Addr: addr,
					Buffers: [][]byte{
						{},
					},
					N: 0,
				},
			},
			wantPackets: 1,
			wantBytes:   0,
		},
		{
			name: "single-packet/no-packet-size",
			addr: addr,
			src:  []byte{0x01, 0x02, 0x03},
			msgs: makeMessages(2, 10),
			wantMsgs: []ipv6.Message{
				{
					Addr:    addr,
					Buffers: [][]byte{{0x01, 0x02, 0x03}},
					N:       3,
				},
			},
			wantPackets: 1,
			wantBytes:   3,
		},
		{
			name:       "single-packet/with-packet-size",
			addr:       addr,
			src:        []byte{0x01, 0x02, 0x03},
			packetSize: 3,
			msgs:       makeMessages(2, 10),
			wantMsgs: []ipv6.Message{
				{
					Addr:    addr,
					Buffers: [][]byte{{0x01, 0x02, 0x03}},
					N:       3,
				},
			},
			wantPackets: 1,
			wantBytes:   3,
		},
		{
			name: "single-packet/too-large-for-msg",
			addr: addr,
			src:  []byte{0x01, 0x02, 0x03},
			msgs: makeMessages(2, 2),
			wantMsgs: []ipv6.Message{
				{
					Addr: addr,
					Buffers: [][]byte{
						{},
					},
					N: 0, // no bytes copied
				},
			},
			wantPackets: 1, // but the packet is still counted
			wantBytes:   3, // and all bytes are still counted as read from src
		},
		{
			name:        "single-packet/no-msgs",
			addr:        addr,
			src:         []byte{0x01, 0x02, 0x03},
			msgs:        nil, // no msgs to copy into
			wantMsgs:    nil,
			wantPackets: 0,
			wantBytes:   0,
		},
		{
			name: "multiple-packets/equal-packet-size",
			addr: addr,
			src: []byte{
				0x01, 0x02, 0x03, // first packet
				0x04, 0x05, 0x06, // second packet
			},
			packetSize: 3,
			msgs:       makeMessages(3, 10),
			wantMsgs: []ipv6.Message{
				{
					Addr:    addr,
					Buffers: [][]byte{{0x01, 0x02, 0x03}},
					N:       3,
				},
				{
					Addr:    addr,
					Buffers: [][]byte{{0x04, 0x05, 0x06}},
					N:       3,
				},
			},
			wantPackets: 2,
			wantBytes:   6,
		},
		{
			name: "multiple-packets/last-packet-smaller",
			addr: addr,
			src: []byte{
				0x01, 0x02, 0x03, // first packet
				0x04, 0x05, 0x06, // second packet
				0x07, 0x08, // third packet, smaller than packetSize, ends the batch
			},
			packetSize: 3,
			msgs:       makeMessages(4, 10),
			wantMsgs: []ipv6.Message{
				{
					Addr:    addr,
					Buffers: [][]byte{{0x01, 0x02, 0x03}},
					N:       3,
				},
				{
					Addr:    addr,
					Buffers: [][]byte{{0x04, 0x05, 0x06}},
					N:       3,
				},
				{
					Addr:    addr,
					Buffers: [][]byte{{0x07, 0x08}},
					N:       2,
				},
			},
			wantPackets: 3,
			wantBytes:   8,
		},
		{
			name: "multiple-packets/partial-fit",
			addr: addr,
			src: []byte{
				0x01, 0x02, 0x03, // first packet
				0x04, 0x05, 0x06, // second packet
				0x07, 0x08, // third packet, smaller than packetSize, ends the batch
			},
			packetSize: 3,
			msgs:       makeMessages(2, 10), // can only fit the first two packets
			wantMsgs: []ipv6.Message{
				{
					Addr:    addr,
					Buffers: [][]byte{{0x01, 0x02, 0x03}},
					N:       3,
				},
				{
					Addr:    addr,
					Buffers: [][]byte{{0x04, 0x05, 0x06}},
					N:       3,
				},
			},
			wantPackets: 2, // the third packet is not included in the msgs
			wantBytes:   6, // and only the first two packets' bytes are counted as read from src
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(1000, func() {
				packets, bytes := splitCoalescedPackets(tt.addr, tt.src, tt.packetSize, tt.msgs)
				if packets != tt.wantPackets {
					t.Errorf("packets: got %d; want %d", packets, tt.wantPackets)
				}
				if bytes != tt.wantBytes {
					t.Errorf("bytes: got %d; want %d", bytes, tt.wantBytes)
				}
				checkMessagesEqual(t, tt.msgs[:packets], tt.wantMsgs)
			})
			// Splitting packets should not cause any allocations.
			if allocs != 0 {
				t.Errorf("unexpected allocations: got %f; want 0", allocs)
			}
		})
	}
}

func makeMessages(num, size int) []ipv6.Message {
	msgs := make([]ipv6.Message, num)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
		msgs[i].Buffers[0] = make([]byte, size)
	}
	return msgs
}

func checkMessagesEqual(t *testing.T, got, want []ipv6.Message) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("number of messages: got %d; want %d", len(got), len(want))
	}
	for i := range got {
		checkNetAddrEqual(t, got[i].Addr, want[i].Addr)
		if got[i].N != want[i].N {
			t.Fatalf("message %d, N: got %d; want %d", i, got[i].N, want[i].N)
		}
		if got[i].N > len(got[i].Buffers[0]) {
			t.Fatalf("message %d, N: got %d exceeds buffer size %d", i, got[i].N, len(got[i].Buffers[0]))
		}
		gotBuff := got[i].Buffers[0][:got[i].N]
		wantBuff := want[i].Buffers[0][:want[i].N]
		if !bytes.Equal(gotBuff, wantBuff) {
			t.Errorf("message %d, buffer: got %v; want %v", i, gotBuff, wantBuff)
		}
	}
}

func checkNetAddrEqual(t *testing.T, got, want net.Addr) {
	t.Helper()
	if got == nil && want == nil {
		return
	}
	if got == nil || want == nil {
		t.Errorf("address: got %v; want %v", got, want)
		return
	}
	switch got := got.(type) {
	case *net.UDPAddr:
		want, ok := want.(*net.UDPAddr)
		if !ok {
			t.Errorf("address type: got %T; want %T", got, want)
			return
		}
		if got.AddrPort() != want.AddrPort() {
			t.Errorf("address: got %v; want %v", got, want)
		}
	default:
		t.Errorf("address type: got %T; want %T", got, want)
	}
}
