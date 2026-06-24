// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func nativeBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func TestPacketMarks_ByteConversions(t *testing.T) {
	// Test that the default marks produce the same byte arrays as the hardcoded ones
	marks := DefaultPacketMarks()

	tests := []struct {
		name string
		got  []byte
		want []byte
	}{
		{
			name: "FwmarkMaskBytes",
			got:  marks.FwmarkMaskBytes(),
			want: nativeBytes(0x00ff0000),
		},
		{
			name: "FwmarkMaskNegBytes",
			got:  marks.FwmarkMaskNegBytes(),
			want: nativeBytes(^uint32(0x00ff0000)),
		},
		{
			name: "SubnetRouteMarkBytes",
			got:  marks.SubnetRouteMarkBytes(),
			want: nativeBytes(0x00040000),
		},
		{
			name: "BypassMarkBytes",
			got:  marks.BypassMarkBytes(),
			want: nativeBytes(0x00080000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !bytes.Equal(tt.got, tt.want) {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestPacketMarks_StringConversions(t *testing.T) {
	marks := DefaultPacketMarks()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "FwmarkMaskString",
			got:  marks.FwmarkMaskString(),
			want: "0xff0000",
		},
		{
			name: "SubnetRouteMarkString",
			got:  marks.SubnetRouteMarkString(),
			want: "0x40000",
		},
		{
			name: "BypassMarkString",
			got:  marks.BypassMarkString(),
			want: "0x80000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestPacketMarks_CustomValues(t *testing.T) {
	// Test with custom mark values
	marks := PacketMarks{
		FwmarkMask:      0xffff00,
		SubnetRouteMark: 0x100,
		BypassMark:      0x200,
	}

	if got := marks.FwmarkMaskString(); got != "0xffff00" {
		t.Errorf("FwmarkMaskString() = %q, want %q", got, "0xffff00")
	}
	if got := marks.SubnetRouteMarkString(); got != "0x100" {
		t.Errorf("SubnetRouteMarkString() = %q, want %q", got, "0x100")
	}
	if got := marks.BypassMarkString(); got != "0x200" {
		t.Errorf("BypassMarkString() = %q, want %q", got, "0x200")
	}

	if got, want := marks.FwmarkMaskBytes(), nativeBytes(0xffff00); !bytes.Equal(got, want) {
		t.Errorf("FwmarkMaskBytes() = %v, want %v", got, want)
	}
	if got, want := marks.SubnetRouteMarkBytes(), nativeBytes(0x100); !bytes.Equal(got, want) {
		t.Errorf("SubnetRouteMarkBytes() = %v, want %v", got, want)
	}
	if got, want := marks.BypassMarkBytes(), nativeBytes(0x200); !bytes.Equal(got, want) {
		t.Errorf("BypassMarkBytes() = %v, want %v", got, want)
	}
}
