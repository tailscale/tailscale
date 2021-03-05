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
	e, err := wgengine.NewFakeUserspaceEngine(logListen.Logf, 0)
	if err != nil {
		t.Fatal(err)
	}

	lb, err := NewLocalBackend(logListen.Logf, idA.String(), store, e)
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
	status := &wgengine.Status{
		Peers: []ipnstate.PeerStatusLite{{
			TxBytes:       10,
			RxBytes:       10,
			LastHandshake: time.Now(),
			NodeKey:       tailcfg.NodeKey(key.NewPrivate()),
		}},
		LocalAddrs: []string{"idk an address"},
	}
	lb.mu.Lock()
	lb.parseWgStatusLocked(status)
	lb.mu.Unlock()

	t.Run("after_peers", testWantRemain())
}
