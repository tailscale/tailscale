// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

import (
	"encoding/binary"
	"reflect"
	"testing"

	"tailscale.com/disco"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/magicsock"
)

// fakeBackend is a test magicsock.WebRTCBackend that records delivered packets.
type fakeBackend struct {
	delivered [][]byte
}

func (f *fakeBackend) LocalDiscoKey() key.DiscoPublic                            { return key.DiscoPublic{} }
func (f *fakeBackend) PeerForDisco(key.DiscoPublic) (magicsock.WebRTCPeer, bool) { return nil, false }
func (f *fakeBackend) SendSignal(key.DiscoPublic, disco.Message) error           { return nil }
func (f *fakeBackend) DisableWebRTC() bool                                       { return false }
func (f *fakeBackend) Logf(format string, args ...any)                           {}
func (f *fakeBackend) DeliverPacket(b []byte, _ key.NodePublic) {
	// Copy: deliverMsg hands us sub-slices of a reused buffer.
	f.delivered = append(f.delivered, append([]byte(nil), b...))
}

// encodeBatch builds the multi-packet wire framing that magicsock's
// sendWebRTCBatch produces: [magicsock.WebRTCBatchMagic][2-byte BE len][pkt]...
func encodeBatch(pkts ...[]byte) []byte {
	out := []byte{magicsock.WebRTCBatchMagic}
	for _, p := range pkts {
		out = binary.BigEndian.AppendUint16(out, uint16(len(p)))
		out = append(out, p...)
	}
	return out
}

func TestDeliverMsg(t *testing.T) {
	pktA := []byte("alpha")
	pktB := []byte("bravo")

	tests := []struct {
		name string
		in   []byte
		want [][]byte
	}{
		{
			name: "empty",
			in:   nil,
			want: nil,
		},
		{
			name: "single unframed packet",
			in:   pktA,
			want: [][]byte{pktA},
		},
		{
			name: "single-element batch",
			in:   encodeBatch(pktA),
			want: [][]byte{pktA},
		},
		{
			name: "multi-element batch",
			in:   encodeBatch(pktA, pktB),
			want: [][]byte{pktA, pktB},
		},
		{
			name: "truncated length header ignored",
			in:   append([]byte{magicsock.WebRTCBatchMagic}, 0x00), // 1 dangling byte after magic
			want: nil,
		},
		{
			name: "declared length exceeds remaining is dropped",
			in:   append([]byte{magicsock.WebRTCBatchMagic, 0x00, 0xFF}, pktA...), // says 255 bytes, has 5
			want: nil,
		},
		{
			name: "unframed packet that happens to start with 0x01",
			in:   []byte{0x01, 0x02, 0x03},
			want: [][]byte{{0x01, 0x02, 0x03}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := &fakeBackend{}
			m := &manager{b: fb, logf: func(string, ...any) {}}
			ps := &peerState{}
			m.deliverMsg(ps, tt.in)

			// Normalize nil vs empty for comparison.
			got := fb.delivered
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("deliverMsg(%v) delivered %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// The zero-length-packet case above: a batch entry with len 0 advances the
// cursor but DeliverPacket is called with an empty slice. Verify that's what
// happens (it is delivered, just empty), so the count is right.
func TestDeliverMsgZeroLenEntryIsDelivered(t *testing.T) {
	fb := &fakeBackend{}
	m := &manager{b: fb, logf: func(string, ...any) {}}
	m.deliverMsg(&peerState{}, encodeBatch([]byte("x"), nil, []byte("y")))
	if len(fb.delivered) != 3 {
		t.Fatalf("got %d delivered packets, want 3 (including the empty one)", len(fb.delivered))
	}
	if len(fb.delivered[1]) != 0 {
		t.Errorf("middle packet = %q, want empty", fb.delivered[1])
	}
}
