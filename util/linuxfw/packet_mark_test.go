// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"bytes"
	"testing"

	"tailscale.com/tsconst"
)

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
			want: []byte{0x00, 0xff, 0x00, 0x00},
		},
		{
			name: "FwmarkMaskNegBytes",
			got:  marks.FwmarkMaskNegBytes(),
			want: []byte{0xff, 0x00, 0xff, 0xff},
		},
		{
			name: "SubnetRouteMarkBytes",
			got:  marks.SubnetRouteMarkBytes(),
			want: []byte{0x00, 0x04, 0x00, 0x00},
		},
		{
			name: "BypassMarkBytes",
			got:  marks.BypassMarkBytes(),
			want: []byte{0x00, 0x08, 0x00, 0x00},
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

func TestPacketMarks_DeprecatedFunctionsMatch(t *testing.T) {
	// Test that deprecated functions return the same as the new methods
	marks := DefaultPacketMarks()

	tests := []struct {
		name string
		got  []byte
		want []byte
	}{
		{
			name: "getTailscaleFwmarkMask",
			got:  getTailscaleFwmarkMask(),
			want: marks.FwmarkMaskBytes(),
		},
		{
			name: "getTailscaleFwmarkMaskNeg",
			got:  getTailscaleFwmarkMaskNeg(),
			want: marks.FwmarkMaskNegBytes(),
		},
		{
			name: "getTailscaleSubnetRouteMark",
			got:  getTailscaleSubnetRouteMark(),
			want: marks.SubnetRouteMarkBytes(),
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

func TestUint32ToBytes(t *testing.T) {
	tests := []struct {
		name string
		val  uint32
		want []byte
	}{
		{
			name: "zero",
			val:  0,
			want: []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "fwmark mask",
			val:  tsconst.LinuxFwmarkMaskNum,
			want: []byte{0x00, 0xff, 0x00, 0x00},
		},
		{
			name: "subnet route mark",
			val:  tsconst.LinuxSubnetRouteMarkNum,
			want: []byte{0x00, 0x04, 0x00, 0x00},
		},
		{
			name: "bypass mark",
			val:  tsconst.LinuxBypassMarkNum,
			want: []byte{0x00, 0x08, 0x00, 0x00},
		},
		{
			name: "max value",
			val:  0xffffffff,
			want: []byte{0xff, 0xff, 0xff, 0xff},
		},
		{
			name: "alternating bits",
			val:  0xaa55aa55,
			want: []byte{0xaa, 0x55, 0xaa, 0x55},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uint32ToBytes(tt.val)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("uint32ToBytes(0x%x) = %v, want %v", tt.val, got, tt.want)
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

	wantMask := []byte{0x00, 0xff, 0xff, 0x00}
	if got := marks.FwmarkMaskBytes(); !bytes.Equal(got, wantMask) {
		t.Errorf("FwmarkMaskBytes() = %v, want %v", got, wantMask)
	}

	wantSubnet := []byte{0x00, 0x00, 0x01, 0x00}
	if got := marks.SubnetRouteMarkBytes(); !bytes.Equal(got, wantSubnet) {
		t.Errorf("SubnetRouteMarkBytes() = %v, want %v", got, wantSubnet)
	}

	wantBypass := []byte{0x00, 0x00, 0x02, 0x00}
	if got := marks.BypassMarkBytes(); !bytes.Equal(got, wantBypass) {
		t.Errorf("BypassMarkBytes() = %v, want %v", got, wantBypass)
	}
}
