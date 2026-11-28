// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package portlist

import (
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
)

// shieldsUpPrefs returns prefs with Shields Up set as given, for driving
// onChangeProfile.
func shieldsUpPrefs(up bool) ipn.PrefsView {
	return (&ipn.Prefs{ShieldsUp: up}).View()
}

// TestShouldUploadServices covers the decision: ports are reported only when
// the tailnet asks for them and shields are down.
func TestShouldUploadServices(t *testing.T) {
	tests := []struct {
		name            string
		shieldsUp       bool
		collectServices bool
		want            bool
	}{
		{"neither", false, false, false},
		{"collecting", false, true, true},
		{"shields up suppresses collecting", true, true, false},
		{"shields up, not collecting", true, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e Extension
			e.shieldsUp.Store(tt.shieldsUp)
			e.collectServicesFn = func() bool { return tt.collectServices }

			if got := e.shouldUploadServices(); got != tt.want {
				t.Errorf("shouldUploadServices() = %v; want %v", got, tt.want)
			}
		})
	}
}

// TestShouldUploadServicesReadsLiveNetmap pins the design: nothing derived from
// the netmap is stored, so the decision follows the netmap with no event, tick
// or profile change in between.
//
// If this fails, a stored copy has been reintroduced, along with every way one
// can disagree with its source.
func TestShouldUploadServicesReadsLiveNetmap(t *testing.T) {
	var e Extension
	collect := false
	e.collectServicesFn = func() bool { return collect }

	if e.shouldUploadServices() {
		t.Fatal("shouldUploadServices() = true before the tailnet asked; want false")
	}

	// No event, no tick, no profile change: only the netmap's answer changed.
	collect = true
	if !e.shouldUploadServices() {
		t.Error("shouldUploadServices() = false after the tailnet enabled collection; want true")
	}

	collect = false
	if e.shouldUploadServices() {
		t.Error("shouldUploadServices() = true after the tailnet disabled collection; want false")
	}
}

// TestOnCollectServicesStoresNothing checks that the event is only a wake-up:
// an event delivered while collection was enabled must not leave behind a
// decision that outlives it, which is how an event from a replaced profile
// would otherwise re-enable reporting the old profile's services.
func TestOnCollectServicesStoresNothing(t *testing.T) {
	var e Extension
	collect := true
	e.collectServicesFn = func() bool { return collect }
	e.wakePoller = make(chan struct{}, 1)

	e.onCollectServices(ipnlocal.CollectServicesChanged{})
	if !e.shouldUploadServices() {
		t.Fatal("shouldUploadServices() = false while collecting; want true")
	}

	// The event already arrived saying "collecting". The netmap now says
	// otherwise, and nothing the event left behind may override it.
	collect = false
	if e.shouldUploadServices() {
		t.Error("shouldUploadServices() = true after the netmap stopped collecting; want false")
	}
}

// TestWakePollerOnlyOnTransition checks that the poller is woken when uploading
// becomes allowed and not for every event after that. A collecting node gets an
// event per netmap, and waking each time would run a full port scan each time.
func TestWakePollerOnlyOnTransition(t *testing.T) {
	var e Extension
	collect := false
	e.collectServicesFn = func() bool { return collect }
	e.wakePoller = make(chan struct{}, 8)

	// Events while nothing is collecting must not wake the poller.
	for range 3 {
		e.onCollectServices(ipnlocal.CollectServicesChanged{})
	}
	if n := len(e.wakePoller); n != 0 {
		t.Errorf("woke the poller %d times while collection was disabled; want 0", n)
	}

	// The transition to allowed wakes it exactly once, however many events
	// arrive afterwards.
	collect = true
	for range 3 {
		e.onCollectServices(ipnlocal.CollectServicesChanged{})
	}
	if n := len(e.wakePoller); n != 1 {
		t.Errorf("woke the poller %d times across one transition and two repeats; want 1", n)
	}
}

// TestShieldsUpSuppressesCollectServices checks that Shields Up wins over a
// tailnet that wants services, including when an event arrives afterwards.
func TestShieldsUpSuppressesCollectServices(t *testing.T) {
	var e Extension
	e.collectServicesFn = func() bool { return true }
	e.wakePoller = make(chan struct{}, 1)

	e.onChangeProfile(ipn.LoginProfileView{}, shieldsUpPrefs(true), false)
	if e.shouldUploadServices() {
		t.Fatal("shouldUploadServices() = true with Shields Up; want false")
	}

	e.onCollectServices(ipnlocal.CollectServicesChanged{})
	if e.shouldUploadServices() {
		t.Error("shouldUploadServices() = true after an event with Shields Up; want false")
	}
	if n := len(e.wakePoller); n != 0 {
		t.Errorf("woke the poller %d times with Shields Up; want 0", n)
	}
}
