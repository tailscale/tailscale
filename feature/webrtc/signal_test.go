// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

import "testing"

func TestParseICECandidateAddr(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		want      string // AddrPort.String(), or "invalid AddrPort" for the zero value
	}{
		{
			name:      "host udp ipv4",
			candidate: "candidate:1 1 udp 2130706431 192.168.1.100 54321 typ host",
			want:      "192.168.1.100:54321",
		},
		{
			name:      "srflx ipv4 with raddr suffix",
			candidate: "candidate:2 1 udp 1694498815 203.0.113.5 45678 typ srflx raddr 192.168.1.100 rport 54321",
			want:      "203.0.113.5:45678",
		},
		{
			name:      "ipv6 host",
			candidate: "candidate:3 1 udp 2130706431 2001:db8::1 60000 typ host",
			want:      "[2001:db8::1]:60000",
		},
		{
			name:      "too few fields",
			candidate: "candidate:1 1 udp 2130706431 192.168.1.100",
			want:      "invalid AddrPort",
		},
		{
			name:      "unparseable ip",
			candidate: "candidate:1 1 udp 2130706431 not-an-ip 54321 typ host",
			want:      "invalid AddrPort",
		},
		{
			name:      "unparseable port",
			candidate: "candidate:1 1 udp 2130706431 192.168.1.100 notaport typ host",
			want:      "invalid AddrPort",
		},
		{
			name:      "empty",
			candidate: "",
			want:      "invalid AddrPort",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseICECandidateAddr(tt.candidate).String()
			if got != tt.want {
				t.Errorf("parseICECandidateAddr(%q) = %q, want %q", tt.candidate, got, tt.want)
			}
		})
	}
}
