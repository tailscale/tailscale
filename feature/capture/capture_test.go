// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package capture

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"tailscale.com/net/packet"
)

func TestSinkSnapLen(t *testing.T) {
	// A packet with empty CaptureMeta carries 4 bytes of custom metadata, so a
	// 100-byte payload makes a 104-byte record.
	const origLen = 104

	tests := []struct {
		name        string
		snapLen     int
		wantHdrSnap uint32
		wantInclLen uint32
	}{
		{name: "truncates", snapLen: 20, wantHdrSnap: 20, wantInclLen: 20},
		{name: "default_does_not_truncate", snapLen: 0, wantHdrSnap: defaultSnapLen, wantInclLen: origLen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSink(tt.snapLen).(*Sink)
			defer s.Close()

			var buf bytes.Buffer
			s.RegisterOutput(&buf)
			s.LogPacket(packet.CapturePath(0), time.Unix(1, 0), make([]byte, 100), packet.CaptureMeta{})

			b := buf.Bytes()
			// 24-byte global header, then a 16-byte per-packet header, then body.
			if got := binary.LittleEndian.Uint32(b[16:20]); got != tt.wantHdrSnap {
				t.Errorf("global header snaplen = %d, want %d", got, tt.wantHdrSnap)
			}
			inclLen := binary.LittleEndian.Uint32(b[32:36])
			if inclLen != tt.wantInclLen {
				t.Errorf("incl_len = %d, want %d", inclLen, tt.wantInclLen)
			}
			if got := binary.LittleEndian.Uint32(b[36:40]); got != origLen {
				t.Errorf("orig_len = %d, want %d", got, origLen)
			}
			if bodyLen := len(b) - 40; bodyLen != int(inclLen) {
				t.Errorf("stored body = %d bytes, want incl_len %d", bodyLen, inclLen)
			}
		})
	}
}
