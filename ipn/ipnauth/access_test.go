// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"testing"
)

func TestDeviceAccessStringer(t *testing.T) {
	tests := []struct {
		name    string
		access  DeviceAccess
		wantStr string
	}{
		{
			name:    "zero-access",
			access:  0,
			wantStr: "(None)",
		},
		{
			name:    "unrestricted-access",
			access:  ^DeviceAccess(0),
			wantStr: "(Unrestricted)",
		},
		{
			name:    "single-access",
			access:  ReadDeviceStatus,
			wantStr: "ReadDeviceStatus",
		},
		{
			name:    "multi-access",
			access:  ReadDeviceStatus | GenerateBugReport | DeleteAllProfiles,
			wantStr: "ReadDeviceStatus|GenerateBugReport|DeleteAllProfiles",
		},
		{
			name:    "unknown-access",
			access:  DeviceAccess(0xABCD0000),
			wantStr: "0xABCD0000",
		},
		{
			name:    "multi-with-unknown-access",
			access:  ReadDeviceStatus | DeviceAccess(0xABCD0000),
			wantStr: "ReadDeviceStatus|0xABCD0000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStr := tt.access.String()
			if gotStr != tt.wantStr {
				t.Errorf("got %v, want %v", gotStr, tt.wantStr)
			}
		})
	}
}

func TestProfileAccessStringer(t *testing.T) {
	tests := []struct {
		name    string
		access  ProfileAccess
		wantStr string
	}{
		{
			name:    "zero-access",
			access:  0,
			wantStr: "(None)",
		},
		{
			name:    "unrestricted-access",
			access:  ^ProfileAccess(0),
			wantStr: "(Unrestricted)",
		},
		{
			name:    "single-access",
			access:  ReadProfileInfo,
			wantStr: "ReadProfileInfo",
		},
		{
			name:    "multi-access",
			access:  ReadProfileInfo | Connect | Disconnect,
			wantStr: "ReadProfileInfo|Connect|Disconnect",
		},
		{
			name:    "unknown-access",
			access:  ProfileAccess(0xFF000000),
			wantStr: "0xFF000000",
		},
		{
			name:    "multi-with-unknown-access",
			access:  ReadProfileInfo | ProfileAccess(0xFF000000),
			wantStr: "ReadProfileInfo|0xFF000000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStr := tt.access.String()
			if gotStr != tt.wantStr {
				t.Errorf("got %v, want %v", gotStr, tt.wantStr)
			}
		})
	}
}

func TestNamedDeviceAccessFlagsArePowerOfTwo(t *testing.T) {
	for da, name := range deviceAccessNames {
		if (da & (da - 1)) != 0 {
			t.Errorf("DeviceAccess, %s: got 0x%x, want power of two", name, uint64(da))
		}
	}
}

func TestNamedProfileAccessFlagsArePowerOfTwo(t *testing.T) {
	for pa, name := range profileAccessNames {
		if (pa & (pa - 1)) != 0 {
			t.Errorf("ProfileAccess, %s: got 0x%x, want power of two", name, uint64(pa))
		}
	}
}
