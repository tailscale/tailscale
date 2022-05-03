// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

type FakeBackend struct {
	serverURL string
	notify    func(n Notify)
	live      bool
}

func (b *FakeBackend) Start(opts Options) error {
	b.serverURL = opts.Prefs.ControlURLOrDefault()
	if b.notify == nil {
		panic("FakeBackend.Start: SetNotifyCallback not called")
	}
	nl := NeedsLogin
	if b.notify != nil {
		b.notify(Notify{Prefs: opts.Prefs})
		b.notify(Notify{State: &nl})
	}
	return nil
}

func (b *FakeBackend) SetNotifyCallback(notify func(Notify)) {
	if notify == nil {
		panic("FakeBackend.SetNotifyCallback: notify is nil")
	}
	b.notify = notify
}

func (b *FakeBackend) newState(s State) {
	if b.notify != nil {
		b.notify(Notify{State: &s})
	}
	if s == Running {
		b.live = true
	} else {
		b.live = false
	}
}

func (b *FakeBackend) StartLoginInteractive() {
	u := b.serverURL + "/this/is/fake"
	if b.notify != nil {
		b.notify(Notify{BrowseToURL: &u})
	}
	b.login()
}

func (b *FakeBackend) Login(token *tailcfg.Oauth2Token) {
	b.login()
}

func (b *FakeBackend) login() {
	b.newState(NeedsMachineAuth)
	b.newState(Stopped)
	// TODO(apenwarr): Fill in a more interesting netmap here.
	if b.notify != nil {
		b.notify(Notify{NetMap: &netmap.NetworkMap{}})
	}
	b.newState(Starting)
	// TODO(apenwarr): Fill in a more interesting status.
	if b.notify != nil {
		b.notify(Notify{Engine: &EngineStatus{}})
	}
	b.newState(Running)
}

func (b *FakeBackend) Logout() {
	b.newState(NeedsLogin)
}

func (b *FakeBackend) SetPrefs(new *Prefs) {
	if new == nil {
		panic("FakeBackend.SetPrefs got nil prefs")
	}

	if b.notify != nil {
		b.notify(Notify{Prefs: new.Clone()})
	}
	if new.WantRunning && !b.live {
		b.newState(Starting)
		b.newState(Running)
	} else if !new.WantRunning && b.live {
		b.newState(Stopped)
	}
}

func (b *FakeBackend) RequestEngineStatus() {
	if b.notify != nil {
		b.notify(Notify{Engine: &EngineStatus{}})
	}
}
