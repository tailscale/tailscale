// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package serviceclientprefs

import (
	"context"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/wgengine"
)

func TestIPNBusInitialThenDelta(t *testing.T) {
	lb := newTestBackend(t)
	ext := seedProfile(t, lb, "pid")

	w := newIPNBusWatch(t, lb, ipn.NotifyInitialServiceClientPrefs, func() {
		if _, err := ext.setServiceClientPref(apitype.ServiceClientPrefRequest{
			Key:    "svc:demo:22",
			Client: "terminal",
		}); err != nil {
			t.Errorf("setServiceClientPref: %v", err)
		}
	})

	initial := w.waitInitial(t).ServiceClientPrefs
	if initial == nil {
		t.Fatal("initial notify carried no ServiceClientPrefs")
	}
	if len(initial.Prefs) != 0 {
		t.Errorf("initial prefs = %v; want empty", initial.Prefs)
	}

	got := w.waitDelta(t, "the written pref", func(p *ipn.ServiceClientPrefsNotify) bool {
		return len(p.Prefs) > 0
	})
	if got := got.Prefs["svc:demo:22"].Client; got != "terminal" {
		t.Errorf("delta prefs client = %q; want terminal", got)
	}
	if got.ProfileID != "pid" {
		t.Errorf("delta ProfileID = %q; want pid", got.ProfileID)
	}
}

func TestIPNBusProfileSwitchPublishes(t *testing.T) {
	lb := newTestBackend(t)
	ext := seedProfile(t, lb, "pid0")

	if _, err := ext.setServiceClientPref(apitype.ServiceClientPrefRequest{Key: "svc:demo:22", Client: "terminal"}); err != nil {
		t.Fatal(err)
	}

	w := newIPNBusWatch(t, lb, ipn.NotifyInitialServiceClientPrefs, func() {
		ext.onChangeProfile((&ipn.LoginProfile{ID: "pid1"}).View(), ipn.PrefsView{}, false)
	})

	initial := w.waitInitial(t).ServiceClientPrefs
	if initial == nil {
		t.Fatal("initial notify carried no ServiceClientPrefs")
	}
	if initial.ProfileID != "pid0" || initial.Prefs["svc:demo:22"].Client != "terminal" {
		t.Errorf("initial = %+v; want pid0 with svc:demo:22=terminal", initial)
	}

	got := w.waitDelta(t, "the new profile", func(p *ipn.ServiceClientPrefsNotify) bool {
		return p.ProfileID == "pid1"
	})
	if len(got.Prefs) != 0 {
		t.Errorf("after switch = %+v; want pid1 with no prefs", got)
	}
}

func TestIPNBusInitialFlagGatesFirstMessageOnly(t *testing.T) {
	lb := newTestBackend(t)
	ext := seedProfile(t, lb, "pid")

	// NotifyInitialState rather than no flags at all, so there is an initial message to inspect.
	w := newIPNBusWatch(t, lb, ipn.NotifyInitialState, func() {
		if _, err := ext.setServiceClientPref(apitype.ServiceClientPrefRequest{
			Key:    "svc:demo:22",
			Client: "terminal",
		}); err != nil {
			t.Errorf("setServiceClientPref: %v", err)
		}
	})

	if got := w.waitInitial(t); got.ServiceClientPrefs != nil {
		t.Errorf("initial message carried ServiceClientPrefs %+v without the flag set", got.ServiceClientPrefs)
	}

	got := w.waitDelta(t, "the written pref", func(p *ipn.ServiceClientPrefsNotify) bool {
		return len(p.Prefs) > 0
	})
	if got := got.Prefs["svc:demo:22"].Client; got != "terminal" {
		t.Errorf("delta prefs client = %q; want terminal", got)
	}
}

func newTestBackend(t *testing.T) *ipnlocal.LocalBackend {
	t.Helper()

	sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))
	sys.Set(new(mem.Store))
	eng, err := wgengine.NewFakeUserspaceEngine(logger.Discard, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	sys.Set(eng)

	lb, err := ipnlocal.NewLocalBackend(logger.Discard, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lb.Shutdown)

	// Start initializes the extensions, which is what registers the hooks under test.
	lb.SetVarRoot(t.TempDir())
	if err := lb.Start(ipn.Options{}); err != nil {
		t.Fatal(err)
	}
	return lb
}

func seedProfile(t *testing.T, lb *ipnlocal.LocalBackend, pid ipn.ProfileID) *extension {
	t.Helper()

	ext, ok := ipnlocal.GetExt[*extension](lb)
	if !ok {
		t.Fatal("serviceclientprefs extension not loaded")
	}
	ext.onChangeProfile((&ipn.LoginProfile{ID: pid}).View(), ipn.PrefsView{}, false)
	return ext
}

type ipnBusWatch struct {
	initial chan *ipn.Notify // the first message the watcher sees
	deltas  chan *ipn.Notify // every later message carrying ServiceClientPrefs
}

func newIPNBusWatch(t *testing.T, lb *ipnlocal.LocalBackend, mask ipn.NotifyWatchOpt, onWatchAdded func()) ipnBusWatch {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	w := ipnBusWatch{
		initial: make(chan *ipn.Notify, 1),
		deltas:  make(chan *ipn.Notify, 16),
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done
	})
	go func() {
		defer close(done)
		first := true
		lb.WatchNotificationsAs(ctx, nil, mask, onWatchAdded, func(n *ipn.Notify) bool {
			if first {
				first = false
				w.initial <- n
				return true
			}
			if n.ServiceClientPrefs == nil {
				return true
			}
			select {
			case w.deltas <- n:
				return true
			case <-ctx.Done():
				return false
			}
		})
	}()
	return w
}

func (w ipnBusWatch) waitInitial(t *testing.T) *ipn.Notify {
	t.Helper()
	select {
	case n := <-w.initial:
		return n
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the initial notify")
		return nil
	}
}

func (w ipnBusWatch) waitDelta(t *testing.T, want string, match func(*ipn.ServiceClientPrefsNotify) bool) *ipn.ServiceClientPrefsNotify {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case n := <-w.deltas:
			if match(n.ServiceClientPrefs) {
				return n.ServiceClientPrefs
			}
			t.Logf("skipping delta queued before the watch: %+v", n.ServiceClientPrefs)
		case <-deadline:
			t.Fatalf("timed out waiting for a delta with %s", want)
			return nil
		}
	}
}
