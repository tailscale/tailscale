// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/net/stun"
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

func BenchmarkServerSTUN(b *testing.B) {
	b.ReportAllocs()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serverSTUNListener(ctx, pc.(*net.UDPConn))
	addr := pc.LocalAddr().(*net.UDPAddr)

	var resBuf [1500]byte
	cc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatal(err)
	}

	tx := stun.NewTxID()
	req := stun.Request(tx)
	for i := 0; i < b.N; i++ {
		if _, err := cc.WriteToUDP(req, addr); err != nil {
			b.Fatal(err)
		}
		_, _, err := cc.ReadFromUDP(resBuf[:])
		if err != nil {
			b.Fatal(err)
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
			name: "no challenge",
		},
		{
			name:  "valid challenge",
			input: "input",
			want:  "response input",
		},
		{
			name:  "valid challenge hostname",
			input: "ts_derp99b.tailscale.com",
			want:  "response ts_derp99b.tailscale.com",
		},
		{
			name:  "invalid challenge",
			input: "foo\x00bar",
			want:  "",
		},
		{
			name:  "whitespace invalid challenge",
			input: "foo bar",
			want:  "",
		},
		{
			name:  "long challenge",
			input: strings.Repeat("x", 65),
			want:  "",
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://localhost/generate_204", nil)
			if tt.input != "" {
				req.Header.Set(noContentChallengeHeader, tt.input)
			}
			w := httptest.NewRecorder()
			serveNoContent(w, req)
			resp := w.Result()

			if tt.want == "" {
				if h, found := resp.Header[noContentResponseHeader]; found {
					t.Errorf("got %+v; expected no response header", h)
				}
				return
			}

			if got := resp.Header.Get(noContentResponseHeader); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestSTUNChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping subprocess test on windows")
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "derper")
	// TODO(crawshaw): most of this test is spent here building the binary.
	// If we break out the derper main function into its own function
	// (in the style of cmd/tailscale/cli) then we can call main directly
	// from this process and save this time.
	if err := exec.Command("go", "build", "-o", bin, "tailscale.com/cmd/derper").Run(); err != nil {
		t.Fatalf("building cmd/derper: %v", err)
	}

	b := &iobuf{
		runningSTUN: make(chan string, 1),
		runningDERP: make(chan string, 1),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-stun", "-c", filepath.Join(tmp, "derper.cfg"), "-a", ":18421", "-stun-port", "18422")
	cmd.Stderr = b
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var stunPID, derpPID string
	select {
	case stunPID = <-b.runningSTUN:
	case <-ctx.Done():
		t.Fatal("timeout waiting for STUN to start")
	}
	select {
	case derpPID = <-b.runningDERP:
	case <-ctx.Done():
		t.Fatal("timeout waiting for DERP to start")
	}
	if stunPID == derpPID {
		t.Errorf("STUN and DERP running in same process: %s", stunPID)
	}
	cmd.Process.Kill()
	if t.Failed() {
		t.Logf("output: %s", b)
	}
	cmd.Wait()
}

type iobuf struct {
	runningSTUN chan string // sent STUN pid
	runningDERP chan string // sent DERP pid

	mu       sync.Mutex
	b        []byte
	seenSTUN bool
	seenDERP bool
}

func (b *iobuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.b)
}

var stunRE = regexp.MustCompile(`running STUN server on .* \(pid (\d+)\)`)
var derpRE = regexp.MustCompile(`derper: serving on .* \(pid (\d+)\)`)

func (b *iobuf) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.b = append(b.b, p...)
	if !b.seenSTUN {
		if m := stunRE.FindSubmatch(b.b); len(m) == 2 {
			b.seenSTUN = true
			b.runningSTUN <- string(m[1])
		}
	}
	if !b.seenDERP {
		if m := derpRE.FindSubmatch(b.b); len(m) == 2 {
			b.seenDERP = true
			b.runningDERP <- string(m[1])
		}
	}
	return len(p), nil
}
