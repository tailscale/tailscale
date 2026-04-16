// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"net/http"
	"testing"
)

func TestRealClientAddr(t *testing.T) {
	tests := []struct {
		name               string
		remoteAddr         string
		acceptProxyHeaders bool
		xRealIP            string
		xForwardedFor      string
		want               string
	}{
		{
			name:               "disabled_ignores_headers",
			remoteAddr:         "127.0.0.1:1234",
			acceptProxyHeaders: false,
			xRealIP:            "203.0.113.1",
			want:               "127.0.0.1:1234",
		},
		{
			name:               "non_loopback_ignores_headers",
			remoteAddr:         "192.168.1.1:1234",
			acceptProxyHeaders: true,
			xRealIP:            "203.0.113.1",
			want:               "192.168.1.1:1234",
		},
		{
			name:               "loopback_x_real_ip",
			remoteAddr:         "127.0.0.1:1234",
			acceptProxyHeaders: true,
			xRealIP:            "203.0.113.1",
			want:               "203.0.113.1:1234",
		},
		{
			name:               "loopback_x_forwarded_for",
			remoteAddr:         "127.0.0.1:1234",
			acceptProxyHeaders: true,
			xForwardedFor:      "203.0.113.2",
			want:               "203.0.113.2:1234",
		},
		{
			name:               "x_real_ip_takes_priority",
			remoteAddr:         "127.0.0.1:1234",
			acceptProxyHeaders: true,
			xRealIP:            "203.0.113.1",
			xForwardedFor:      "203.0.113.2",
			want:               "203.0.113.1:1234",
		},
		{
			name:               "x_forwarded_for_multiple_takes_first",
			remoteAddr:         "127.0.0.1:1234",
			acceptProxyHeaders: true,
			xForwardedFor:      "203.0.113.3, 10.0.0.1, 172.16.0.1",
			want:               "203.0.113.3:1234",
		},
		{
			name:               "preserves_proxy_upstream_port",
			remoteAddr:         "127.0.0.1:54321",
			acceptProxyHeaders: true,
			xRealIP:            "203.0.113.9",
			want:               "203.0.113.9:54321",
		},
		{
			name:               "x_real_ip_trims_whitespace",
			remoteAddr:         "127.0.0.1:1234",
			acceptProxyHeaders: true,
			xRealIP:            "  203.0.113.10  ",
			want:               "203.0.113.10:1234",
		},
		{
			name:               "invalid_x_real_ip_falls_back",
			remoteAddr:         "127.0.0.1:1234",
			acceptProxyHeaders: true,
			xRealIP:            "not-an-ip",
			want:               "127.0.0.1:1234",
		},
		{
			name:               "invalid_x_real_ip_falls_through_to_xff",
			remoteAddr:         "127.0.0.1:1234",
			acceptProxyHeaders: true,
			xRealIP:            "not-an-ip",
			xForwardedFor:      "203.0.113.5",
			want:               "203.0.113.5:1234",
		},
		{
			name:               "invalid_both_headers_falls_back",
			remoteAddr:         "127.0.0.1:1234",
			acceptProxyHeaders: true,
			xRealIP:            "not-an-ip",
			xForwardedFor:      "also-not-an-ip",
			want:               "127.0.0.1:1234",
		},
		{
			name:               "ipv6_loopback_trusted",
			remoteAddr:         "[::1]:1234",
			acceptProxyHeaders: true,
			xRealIP:            "203.0.113.1",
			want:               "203.0.113.1:1234",
		},
		{
			name:               "ipv6_client_in_header",
			remoteAddr:         "127.0.0.1:1234",
			acceptProxyHeaders: true,
			xRealIP:            "2001:db8::1",
			want:               "[2001:db8::1]:1234",
		},
		{
			name:               "no_headers_returns_remote_addr",
			remoteAddr:         "127.0.0.1:1234",
			acceptProxyHeaders: true,
			want:               "127.0.0.1:1234",
		},
		{
			name:               "empty_x_real_ip_ignored",
			remoteAddr:         "127.0.0.1:1234",
			acceptProxyHeaders: true,
			xRealIP:            "",
			xForwardedFor:      "203.0.113.4",
			want:               "203.0.113.4:1234",
		},
		{
			name:               "unparseable_remote_addr_returns_as_is",
			remoteAddr:         "not-a-valid-addr",
			acceptProxyHeaders: true,
			xRealIP:            "203.0.113.1",
			want:               "not-a-valid-addr",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if tt.xForwardedFor != "" {
				r.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			got := RealClientAddr(r, tt.acceptProxyHeaders)
			if got != tt.want {
				t.Errorf("RealClientAddr() = %q, want %q", got, tt.want)
			}
		})
	}
}
