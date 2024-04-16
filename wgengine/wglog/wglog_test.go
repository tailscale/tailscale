// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wglog_test

import (
	"fmt"
	"testing"

	"go4.org/mem"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wglog"
)

func TestLogger(t *testing.T) {
	tests := []struct {
		format string
		args   []any
		want   string
		omit   bool
	}{
		{"hi", nil, "wg: hi", false},
		{"Routine: starting", nil, "", true},
		{"%v says it misses you", []any{stringer("peer(IMTB…r7lM)")}, "wg: [IMTBr] says it misses you", false},
	}

	type log struct {
		format string
		args   []any
	}

	c := make(chan log, 1)
	logf := func(format string, args ...any) {
		select {
		case c <- log{format, args}:
		default:
			t.Errorf("wrote %q, but shouldn't have", fmt.Sprintf(format, args...))
		}
	}

	x := wglog.NewLogger(logf)
	key, err := key.ParseNodePublicUntyped(mem.S("20c4c1ae54e1fd37cab6e9a532ca20646aff496796cc41d4519560e5e82bee53"))
	if err != nil {
		t.Fatal(err)
	}
	x.SetPeers([]wgcfg.Peer{{PublicKey: key}})

	for _, tt := range tests {
		if tt.omit {
			// Write a message ourselves into the channel.
			// Then if logf also attempts to write into the channel, it'll fail.
			c <- log{}
		}
		x.DeviceLogger.Errorf(tt.format, tt.args...)
		gotLog := <-c
		if tt.omit {
			continue
		}
		if got := fmt.Sprintf(gotLog.format, gotLog.args...); got != tt.want {
			t.Errorf("Printf(%q, %v) = %q want %q", tt.format, tt.args, got, tt.want)
		}
	}
}

func TestSuppressLogs(t *testing.T) {
	var logs []string
	logf := func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	x := wglog.NewLogger(logf)
	x.DeviceLogger.Verbosef("pass")
	x.DeviceLogger.Verbosef("UAPI: Adding allowedip")

	if len(logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(logs))
	}
	if logs[0] != "wg: [v2] pass" {
		t.Errorf("got %q, want \"wg: [v2] pass\"", logs[0])
	}
}

func stringer(s string) stringerString {
	return stringerString(s)
}

type stringerString string

func (s stringerString) String() string { return string(s) }

func BenchmarkSetPeers(b *testing.B) {
	b.ReportAllocs()
	x := wglog.NewLogger(logger.Discard)
	peers := [][]wgcfg.Peer{genPeers(0), genPeers(15), genPeers(16), genPeers(15)}
	for range b.N {
		for _, p := range peers {
			x.SetPeers(p)
		}
	}
}

func genPeers(n int) []wgcfg.Peer {
	if n > 32 {
		panic("too many peers")
	}
	if n == 0 {
		return nil
	}
	peers := make([]wgcfg.Peer, n)
	for i := range peers {
		var k [32]byte
		k[n] = byte(n)
		peers[i].PublicKey = key.NodePublicFromRaw32(mem.B(k[:]))
	}
	return peers
}
