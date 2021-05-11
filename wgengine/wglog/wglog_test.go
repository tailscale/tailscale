// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wglog_test

import (
	"fmt"
	"testing"

	"tailscale.com/types/logger"
	"tailscale.com/types/wgkey"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wglog"
)

func TestLogger(t *testing.T) {
	tests := []struct {
		format string
		args   []interface{}
		want   string
		omit   bool
	}{
		{"hi", nil, "hi", false},
		{"Routine: starting", nil, "", true},
		{"%v says it misses you", []interface{}{stringer("peer(IMTB…r7lM)")}, "[IMTBr] says it misses you", false},
	}

	type log struct {
		format string
		args   []interface{}
	}

	c := make(chan log, 1)
	logf := func(format string, args ...interface{}) {
		select {
		case c <- log{format, args}:
		default:
			t.Errorf("wrote %q, but shouldn't have", fmt.Sprintf(format, args...))
		}
	}

	x := wglog.NewLogger(logf)
	key, err := wgkey.ParseHex("20c4c1ae54e1fd37cab6e9a532ca20646aff496796cc41d4519560e5e82bee53")
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

func stringer(s string) stringerString {
	return stringerString(s)
}

type stringerString string

func (s stringerString) String() string { return string(s) }

func BenchmarkSetPeers(b *testing.B) {
	b.ReportAllocs()
	x := wglog.NewLogger(logger.Discard)
	peers := [][]wgcfg.Peer{genPeers(0), genPeers(15), genPeers(16), genPeers(15)}
	for i := 0; i < b.N; i++ {
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
		var k wgkey.Key
		k[n] = byte(n)
		peers[i].PublicKey = k
	}
	return peers
}
