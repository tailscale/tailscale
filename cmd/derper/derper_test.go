// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tailscale.com/derp/derpserver"
	"tailscale.com/tstest/deptest"
)

func TestProdAutocertHostPolicy(t *testing.T) {
	tests := []struct {
		in     string
		wantOK bool
	}{
		{"derp.tailscale.com", true},
		{"derp.tailscale.com.", true},
		{"derp1.tailscale.com", true},
		{"derp1b.tailscale.com", true},
		{"derp2.tailscale.com", true},
		{"derp02.tailscale.com", true},
		{"derp-nyc.tailscale.com", true},
		{"derpfoo.tailscale.com", true},
		{"derp02.bar.tailscale.com", false},
		{"example.net", false},
	}
	for _, tt := range tests {
		got := prodAutocertHostPolicy(context.Background(), tt.in) == nil
		if got != tt.wantOK {
			t.Errorf("f(%q) = %v; want %v", tt.in, got, tt.wantOK)
		}
	}
}

func TestNoContent(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name: "no-challenge",
		},
		{
			name:  "valid-challenge",
			input: "input",
			want:  "response input",
		},
		{
			name:  "valid-challenge-hostname",
			input: "ts_derp99b.tailscale.com",
			want:  "response ts_derp99b.tailscale.com",
		},
		{
			name:  "invalid-challenge",
			input: "foo\x00bar",
			want:  "",
		},
		{
			name:  "whitespace-invalid-challenge",
			input: "foo bar",
			want:  "",
		},
		{
			name:  "long-challenge",
			input: strings.Repeat("x", 65),
			want:  "",
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://localhost/generate_204", nil)
			if tt.input != "" {
				req.Header.Set(derpserver.NoContentChallengeHeader, tt.input)
			}
			w := httptest.NewRecorder()
			derpserver.ServeNoContent(w, req)
			resp := w.Result()

			if tt.want == "" {
				if h, found := resp.Header[derpserver.NoContentResponseHeader]; found {
					t.Errorf("got %+v; expected no response header", h)
				}
				return
			}

			if got := resp.Header.Get(derpserver.NoContentResponseHeader); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		BadDeps: map[string]string{
			"testing":                            "do not use testing package in production code",
			"gvisor.dev/gvisor/pkg/buffer":       "https://github.com/tailscale/tailscale/issues/9756",
			"gvisor.dev/gvisor/pkg/cpuid":        "https://github.com/tailscale/tailscale/issues/9756",
			"gvisor.dev/gvisor/pkg/tcpip":        "https://github.com/tailscale/tailscale/issues/9756",
			"gvisor.dev/gvisor/pkg/tcpip/header": "https://github.com/tailscale/tailscale/issues/9756",
			"tailscale.com/net/packet":           "not needed in derper",
			"github.com/gaissmai/bart":           "not needed in derper",
			"database/sql/driver":                "not needed in derper", // previously came in via github.com/google/uuid
		},
	}.Check(t)
}

func TestTemplate(t *testing.T) {
	buf := &bytes.Buffer{}
	err := homePageTemplate.Execute(buf, templateData{
		ShowAbuseInfo: true,
		Disabled:      true,
		AllowDebug:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	str := buf.String()
	if !strings.Contains(str, "If you suspect abuse") {
		t.Error("Output is missing abuse mailto")
	}
	if !strings.Contains(str, "Tailscale Security Policies") {
		t.Error("Output is missing Tailscale Security Policies link")
	}
	if !strings.Contains(str, "Status:") {
		t.Error("Output is missing disabled status")
	}
	if !strings.Contains(str, "Debug info") {
		t.Error("Output is missing debug info")
	}
}

type hijackableResponseWriter struct {
	httptest.ResponseRecorder
	conn net.Conn
}

func (w *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func TestHijackTrackingResponseWriter(t *testing.T) {
	t.Run("hijacked", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c2.Close()
		closes := 0
		htw := &hijackTrackingResponseWriter{
			ResponseWriter: &hijackableResponseWriter{conn: c1},
			onConnClose:    func() { closes++ },
		}
		conn, _, err := htw.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		if !htw.hijacked {
			t.Error("hijacked = false; want true")
		}
		if closes != 0 {
			t.Errorf("closes = %d before Close; want 0", closes)
		}
		conn.Close()
		conn.Close() // once only
		if closes != 1 {
			t.Errorf("closes = %d after double Close; want 1", closes)
		}
		if _, ok := conn.(interface{ NetConn() net.Conn }); !ok {
			t.Error("hijacked conn does not expose NetConn for wrapper unwrapping")
		}
	})
	t.Run("not-hijackable", func(t *testing.T) {
		htw := &hijackTrackingResponseWriter{ResponseWriter: httptest.NewRecorder()}
		if _, _, err := htw.Hijack(); err == nil {
			t.Error("Hijack succeeded on non-Hijacker; want error")
		}
		if htw.hijacked {
			t.Error("hijacked = true; want false")
		}
	})
}
