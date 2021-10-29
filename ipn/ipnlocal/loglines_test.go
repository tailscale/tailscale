// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"reflect"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/logtail"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/persist"
	"tailscale.com/wgengine"
)

// TestLocalLogLines tests to make sure that the log lines required for log parsing are
// being logged by the expected functions. Update these tests if moving log lines between
// functions.
func TestLocalLogLines(t *testing.T) {
	logListen := tstest.NewLogLineTracker(t.Logf, []string{
		"SetPrefs: %v",
		"[v1] peer keys: %s",
		"[v1] v%v peers: %v",
	})
	defer logListen.Close()

	// Put a rate-limiter with a burst of 0 between the components below.
	// This instructs the rate-limiter to eliminate all logging that
	// isn't explicitly exempt from rate-limiting.
	// This lets the logListen tracker verify that the rate-limiter allows these key lines.
	logf := logger.RateLimitedFnWithClock(logListen.Logf, 5*time.Second, 0, 10, time.Now)

	logid := func(hex byte) logtail.PublicID {
		var ret logtail.PublicID
		for i := 0; i < len(ret); i++ {
			ret[i] = hex
		}
		return ret
	}
	idA := logid(0xaa)

	// set up a LocalBackend, super bare bones. No functional data.
	store := &ipn.MemoryStore{}
	e, err := wgengine.NewFakeUserspaceEngine(logf, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	lb, err := NewLocalBackend(logf, idA.String(), store, e)
	if err != nil {
		t.Fatal(err)
	}
	defer lb.Shutdown()

	// custom adjustments for required non-nil fields
	lb.prefs = ipn.NewPrefs()
	lb.hostinfo = &tailcfg.Hostinfo{}
	// hacky manual override of the usual log-on-change behaviour of keylogf
	lb.keyLogf = logListen.Logf

	testWantRemain := func(wantRemain ...string) func(t *testing.T) {
		return func(t *testing.T) {
			if remain := logListen.Check(); !reflect.DeepEqual(remain, wantRemain) {
				t.Helper()
				t.Errorf("remain %q, want %q", remain, wantRemain)
			}
		}
	}

	// log prefs line
	persist := &persist.Persist{}
	prefs := ipn.NewPrefs()
	prefs.Persist = persist
	lb.SetPrefs(prefs)

	t.Run("after_prefs", testWantRemain("[v1] peer keys: %s", "[v1] v%v peers: %v"))

	// log peers, peer keys
	lb.mu.Lock()
	lb.parseWgStatusLocked(&wgengine.Status{
		Peers: []ipnstate.PeerStatusLite{{
			TxBytes:       10,
			RxBytes:       10,
			LastHandshake: time.Now(),
			NodeKey:       tailcfg.NodeKeyFromNodePublic(key.NewNode().Public()),
		}},
	})
	lb.mu.Unlock()

	t.Run("after_peers", testWantRemain())

	// Log it again with different stats to ensure it's not dup-suppressed.
	logListen.Reset()
	lb.mu.Lock()
	lb.parseWgStatusLocked(&wgengine.Status{
		Peers: []ipnstate.PeerStatusLite{{
			TxBytes:       11,
			RxBytes:       12,
			LastHandshake: time.Now(),
			NodeKey:       tailcfg.NodeKeyFromNodePublic(key.NewNode().Public()),
		}},
	})
	lb.mu.Unlock()
	t.Run("after_second_peer_status", testWantRemain("SetPrefs: %v"))
}
