// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"net/url"
	"testing"
)

func TestUrlOfListenAddr(t *testing.T) {
	tests := []struct {
		name     string
		in, want string
	}{
		{
			name: "TestLocalhost",
			in:   "localhost:8088",
			want: "http://localhost:8088",
		},
		{
			name: "TestNoHost",
			in:   ":8088",
			want: "http://127.0.0.1:8088",
		},
		{
			name: "TestExplicitHost",
			in:   "127.0.0.2:8088",
			want: "http://127.0.0.2:8088",
		},
		{
			name: "TestIPv6",
			in:   "[::1]:8088",
			want: "http://[::1]:8088",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := urlOfListenAddr(tt.in)
			if u != tt.want {
				t.Errorf("expected url: %q, got: %q", tt.want, u)
			}
		})
	}
}

func TestQnapAuthnURL(t *testing.T) {
	query := url.Values{
		"qtoken": []string{"token"},
	}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "localhost http",
			in:   "http://localhost:8088/",
			want: "http://localhost:8088/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "localhost https",
			in:   "https://localhost:5000/",
			want: "https://localhost:5000/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "IP http",
			in:   "http://10.1.20.4:80/",
			want: "http://10.1.20.4:80/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "IP6 https",
			in:   "https://[ff7d:0:1:2::1]/",
			want: "https://[ff7d:0:1:2::1]/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "hostname https",
			in:   "https://qnap.example.com/",
			want: "https://qnap.example.com/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "invalid URL",
			in:   "This is not a URL, it is a really really really really really really really really really really really really long string to exercise the URL truncation code in the error path.",
			want: "http://localhost/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "err != nil",
			in:   "http://192.168.0.%31/",
			want: "http://localhost/cgi-bin/authLogin.cgi?qtoken=token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := qnapAuthnURL(tt.in, query)
			if u != tt.want {
				t.Errorf("expected url: %q, got: %q", tt.want, u)
			}
		})
	}
}
