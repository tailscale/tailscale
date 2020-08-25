// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"testing"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/logtail"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/wgengine"
)

// TestLocalLogLines tests to make sure that the log lines required for log parsing are
// being logged by the expected functions. Update these tests if moving log lines between
// functions.
func TestLocalLogLines(t *testing.T) {
	logListen := tstest.ListenFor(t.Logf, []string{
		"SetPrefs: %v",
		"peer keys: %s",
		"v%v peers: %v",
	})

	logid := func(hex byte) logtail.PublicID {
		var ret logtail.PublicID
		for i := 0; i < len(ret); i++ {
			ret[i] = hex
		}
		return ret
	}
	idA := logid(0xaa)

	// set up a LocalBackend, super bare bones. No functional data.
	store := &MemoryStore{
		cache: make(map[StateKey][]byte),
	}
	e, err := wgengine.NewFakeUserspaceEngine(logListen.Logf, 0)
	if err != nil {
		t.Fatal(err)
	}

	lb, err := NewLocalBackend(logListen.Logf, idA.String(), store, e)
	if err != nil {
		t.Fatal(err)
	}

	// custom adjustments for required non-nil fields
	lb.prefs = NewPrefs()
	lb.hostinfo = &tailcfg.Hostinfo{}
	// hacky manual override of the usual log-on-change behaviour of keylogf
	lb.keyLogf = logListen.Logf

	// testing infrastructure
	type linesTest struct {
		name string
		want []string
	}

	tests := []linesTest{
		{
			name: "after prefs",
			want: []string{
				"peer keys: %s",
				"v%v peers: %v",
			},
		},
		{
			name: "after peers",
			want: []string{},
		},
	}

	testLogs := func(want linesTest) func(t *testing.T) {
		return func(t *testing.T) {
			if linesLeft := logListen.Check(); len(linesLeft) != len(want.want) {
				t.Errorf("got %v, expected %v", linesLeft, want)
			}
		}
	}

	// log prefs line
	persist := &controlclient.Persist{}
	prefs := NewPrefs()
	prefs.Persist = persist
	lb.SetPrefs(prefs)

	t.Run(tests[0].name, testLogs(tests[0]))

	// log peers, peer keys
	status := &wgengine.Status{
		Peers: []wgengine.PeerStatus{wgengine.PeerStatus{
			TxBytes:       10,
			RxBytes:       10,
			LastHandshake: time.Now(),
			NodeKey:       tailcfg.NodeKey(key.NewPrivate()),
		}},
		LocalAddrs: []string{"idk an address"},
	}
	lb.parseWgStatus(status)

	t.Run(tests[1].name, testLogs(tests[1]))
}
