// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package preftype

import "testing"

func TestLinuxPacketMarks_Validate(t *testing.T) {
	tests := []struct {
		name    string
		marks   *LinuxPacketMarks
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil_marks_should_be_valid",
			marks:   nil,
			wantErr: false,
		},
		{
			name: "valid_marks",
			marks: &LinuxPacketMarks{
				FwmarkMask:      0xff0000,
				SubnetRouteMark: 0x40000,
				BypassMark:      0x80000,
			},
			wantErr: false,
		},
		{
			name: "zero_fwmark_mask",
			marks: &LinuxPacketMarks{
				FwmarkMask:      0,
				SubnetRouteMark: 0x40000,
				BypassMark:      0x80000,
			},
			wantErr: true,
			errMsg:  "fwmark mask must be non-zero",
		},
		{
			name: "zero_subnet_route_mark",
			marks: &LinuxPacketMarks{
				FwmarkMask:      0xff0000,
				SubnetRouteMark: 0,
				BypassMark:      0x80000,
			},
			wantErr: true,
			errMsg:  "subnet route mark must be non-zero",
		},
		{
			name: "zero_bypass_mark",
			marks: &LinuxPacketMarks{
				FwmarkMask:      0xff0000,
				SubnetRouteMark: 0x40000,
				BypassMark:      0,
			},
			wantErr: true,
			errMsg:  "bypass mark must be non-zero",
		},
		{
			name: "subnet_route_mark_not_covered_by_mask",
			marks: &LinuxPacketMarks{
				FwmarkMask:      0xff0000,
				SubnetRouteMark: 0x1000000,
				BypassMark:      0x80000,
			},
			wantErr: true,
			errMsg:  "subnet route mark (0x1000000) must be covered by fwmark mask (0xff0000)",
		},
		{
			name: "bypass_mark_not_covered_by_mask",
			marks: &LinuxPacketMarks{
				FwmarkMask:      0xff0000,
				SubnetRouteMark: 0x40000,
				BypassMark:      0x1000000,
			},
			wantErr: true,
			errMsg:  "bypass mark (0x1000000) must be covered by fwmark mask (0xff0000)",
		},
		{
			name: "subnet_and_bypass_marks_are_the_same",
			marks: &LinuxPacketMarks{
				FwmarkMask:      0xff0000,
				SubnetRouteMark: 0x40000,
				BypassMark:      0x40000,
			},
			wantErr: true,
			errMsg:  "subnet route mark and bypass mark must differ",
		},
		{
			name: "different_valid_marks",
			marks: &LinuxPacketMarks{
				FwmarkMask:      0xffff00,
				SubnetRouteMark: 0x100,
				BypassMark:      0x200,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.marks.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && err.Error() != tt.errMsg {
				t.Errorf("Validate() error = %q, want %q", err.Error(), tt.errMsg)
			}
		})
	}
}
