// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wglog_test

import (
	"fmt"
	"testing"

	"tailscale.com/types/wgkey"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wglog"
)

func TestLogger(t *testing.T) {
	tests := []struct {
		in   string
		want string
		omit bool
	}{
		{"hi", "hi", false},
		{"Routine: starting", "", true},
		{"peer(IMTB…r7lM) says it misses you", "[IMTBr] says it misses you", false},
	}

	c := make(chan string, 1)
	logf := func(format string, args ...interface{}) {
		s := fmt.Sprintf(format, args...)
		select {
		case c <- s:
		default:
			t.Errorf("wrote %q, but shouldn't have", s)
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
			c <- ""
		}
		x.DeviceLogger.Errorf(tt.in)
		got := <-c
		if tt.omit {
			continue
		}
		if got != tt.want {
			t.Errorf("Println(%q) = %q want %q", tt.in, got, tt.want)
		}
	}
}
