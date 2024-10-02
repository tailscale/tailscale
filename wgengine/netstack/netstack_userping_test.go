// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"net/netip"
	"testing"
)

func TestWindowsPingOutputIsSuccess(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		out  string
		want bool
	}{
		{
			name: "success",
			ip:   "10.0.0.1",
			want: true,
			out: `Pinging 10.0.0.1 with 32 bytes of data:
Reply from 10.0.0.1: bytes=32 time=7ms TTL=64

Ping statistics for 10.0.0.1:
	Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
	Minimum = 7ms, Maximum = 7ms, Average = 7ms
`,
		},
		{
			name: "success_sub_millisecond",
			ip:   "10.0.0.1",
			want: true,
			out: `Pinging 10.0.0.1 with 32 bytes of data:
Reply from 10.0.0.1: bytes=32 time<1ms TTL=64

Ping statistics for 10.0.0.1:
	Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
	Minimum = 7ms, Maximum = 7ms, Average = 7ms
`,
		},
		{
			name: "success_german",
			ip:   "10.0.0.1",
			want: true,
			out: `Ping wird ausgeführt für 10.0.0.1 mit 32 Bytes Daten:
Antwort von from 10.0.0.1: Bytes=32 Zeit=7ms TTL=64

Ping-Statistik für 10.0.0.1:
	Pakete: Gesendet = 4, Empfangen = 4, Verloren = 0 (0% Verlust),
Ca. Zeitangaben in Millisek.:
	Minimum = 7ms, Maximum = 7ms, Mittelwert = 7ms
`,
		},
		{
			name: "unreachable",
			ip:   "10.0.0.6",
			want: false,
			out: `Pinging 10.0.0.6 with 32 bytes of data:
Reply from 10.0.108.189: Destination host unreachable

Ping statistics for 10.0.0.6:
	Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := windowsPingOutputIsSuccess(netip.MustParseAddr(tt.ip), []byte(tt.out))
			if got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}
