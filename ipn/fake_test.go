// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"log"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

type FakeBackend struct {
	serverURL string
	notify    func(n Notify)
	live      bool
}

func (b *FakeBackend) Start(opts Options) error {
	b.serverURL = opts.Prefs.ControlURL
	if opts.Notify == nil {
		log.Fatalf("FakeBackend.Start: opts.Notify is nil\n")
	}
	b.notify = opts.Notify
	b.notify(Notify{Prefs: opts.Prefs})
	nl := NeedsLogin
	b.notify(Notify{State: &nl})
	return nil
}

func (b *FakeBackend) newState(s State) {
	b.notify(Notify{State: &s})
	if s == Running {
		b.live = true
	} else {
		b.live = false
	}
}

func (b *FakeBackend) StartLoginInteractive() {
	u := b.serverURL + "/this/is/fake"
	b.notify(Notify{BrowseToURL: &u})
	b.login()
}

func (b *FakeBackend) Login(token *tailcfg.Oauth2Token) {
	b.login()
}

func (b *FakeBackend) login() {
	b.newState(NeedsMachineAuth)
	b.newState(Stopped)
	// TODO(apenwarr): Fill in a more interesting netmap here.
	b.notify(Notify{NetMap: &netmap.NetworkMap{}})
	b.newState(Starting)
	// TODO(apenwarr): Fill in a more interesting status.
	b.notify(Notify{Engine: &EngineStatus{}})
	b.newState(Running)
}

func (b *FakeBackend) Logout() {
	b.newState(NeedsLogin)
}

func (b *FakeBackend) SetPrefs(new *Prefs) {
	if new == nil {
		panic("FakeBackend.SetPrefs got nil prefs")
	}

	b.notify(Notify{Prefs: new.Clone()})
	if new.WantRunning && !b.live {
		b.newState(Starting)
		b.newState(Running)
	} else if !new.WantRunning && b.live {
		b.newState(Stopped)
	}
}

func (b *FakeBackend) EditPrefs(mp *MaskedPrefs) {
	// This fake implementation only cares about this one pref.
	if mp.WantRunningSet {
		b.SetPrefs(&mp.Prefs)
	}
}

func (b *FakeBackend) RequestEngineStatus() {
	b.notify(Notify{Engine: &EngineStatus{}})
}

func (b *FakeBackend) FakeExpireAfter(x time.Duration) {
	b.notify(Notify{NetMap: &netmap.NetworkMap{}})
}

func (b *FakeBackend) Ping(ip string, useTSMP bool) {
	b.notify(Notify{PingResult: &ipnstate.PingResult{}})
}
