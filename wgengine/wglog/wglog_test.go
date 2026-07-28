// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wglog_test

import (
	"fmt"
	"testing"

	extwgconn "github.com/tailscale/wireguard-go/conn"
	extwgdevice "github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"go4.org/mem"
	"tailscale.com/types/key"
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

	k, err := key.ParseNodePublicUntyped(mem.S("20c4c1ae54e1fd37cab6e9a532ca20646aff496796cc41d4519560e5e82bee53"))
	if err != nil {
		t.Fatal(err)
	}
	wantWG := k.WireGuardGoString()
	wantTS := k.ShortString()
	lookup := func(s string) (string, bool) {
		if s == wantWG {
			return wantTS, true
		}
		return "", false
	}
	x := wglog.NewLogger(logf, lookup)

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
	x := wglog.NewLogger(logf, nil)
	x.DeviceLogger.Verbosef("pass")
	x.DeviceLogger.Verbosef("UAPI: Adding allowedip")

	if len(logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(logs))
	}
	if logs[0] != "wg: [v2] pass" {
		t.Errorf("got %q, want \"wg: [v2] pass\"", logs[0])
	}
}

// TestWireGuardGoStringMatchesWireGuardGo guards against a wireguard-go bump
// silently changing the wireguard-go peer-string format from under us. The
// LocalBackend's nodeByWGString index is built using
// [key.NodePublic.WireGuardGoString]; if wireguard-go's *device.Peer.String
// were to drift, the index would quietly stop matching and wglog would no
// longer translate peer references in log lines.
func TestWireGuardGoStringMatchesWireGuardGo(t *testing.T) {
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	nodeKey := key.NodePublicFromRaw32(mem.B(raw[:]))

	dev := extwgdevice.NewDevice(
		tuntest.NewChannelTUN().TUN(),
		extwgconn.NewDefaultBind(),
		extwgdevice.NewLogger(extwgdevice.LogLevelError, ""),
	)
	t.Cleanup(dev.Close)
	peer, err := dev.NewPeer(extwgdevice.NoisePublicKey(raw))
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	if got, want := nodeKey.WireGuardGoString(), peer.String(); got != want {
		t.Errorf("NodePublic.WireGuardGoString() = %q, want wireguard-go *device.Peer.String() = %q", got, want)
	}
}

func stringer(s string) stringerString {
	return stringerString(s)
}

type stringerString string

func (s stringerString) String() string { return string(s) }
