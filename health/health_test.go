// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package health

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/opt"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
	"tailscale.com/version"
)

func wantChange(c Change) func(c Change) (bool, error) {
	return func(cEv Change) (bool, error) {
		if cEv.ControlHealthChanged != c.ControlHealthChanged {
			return false, fmt.Errorf("expected ControlHealthChanged %t, got %t", c.ControlHealthChanged, cEv.ControlHealthChanged)
		}
		if cEv.WarnableChanged != c.WarnableChanged {
			return false, fmt.Errorf("expected WarnableChanged %t, got %t", c.WarnableChanged, cEv.WarnableChanged)
		}
		if c.Warnable != nil && (cEv.Warnable == nil || cEv.Warnable != c.Warnable) {
			return false, fmt.Errorf("expected Warnable %+v, got %+v", c.Warnable, cEv.Warnable)
		}

		if c.UnhealthyState != nil {
			panic("comparison of UnhealthyState is not yet supported")
		}

		return true, nil
	}
}

func TestAppendWarnableDebugFlags(t *testing.T) {
	tr := NewTracker(eventbustest.NewBus(t))

	for i := range 10 {
		w := Register(&Warnable{
			Code:         WarnableCode(fmt.Sprintf("warnable-code-%d", i)),
			MapDebugFlag: fmt.Sprint(i),
			Text:         StaticMessage(""),
		})
		defer unregister(w)
		if i%2 == 0 {
			tr.SetUnhealthy(w, Args{"test-arg": fmt.Sprint(i)})
		}
	}

	want := []string{"z", "y", "0", "2", "4", "6", "8"}

	var got []string
	for range 20 {
		got = append(got[:0], "z", "y")
		got = tr.AppendWarnableDebugFlags(got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("AppendWarnableDebugFlags = %q; want %q", got, want)
		}
	}
}

// Test that all exported methods on *Tracker don't panic with a nil receiver.
func TestNilMethodsDontCrash(t *testing.T) {
	var nilt *Tracker
	rv := reflect.ValueOf(nilt)
	for i := 0; i < rv.NumMethod(); i++ {
		mt := rv.Type().Method(i)
		t.Logf("calling Tracker.%s ...", mt.Name)
		var args []reflect.Value
		for j := 0; j < mt.Type.NumIn(); j++ {
			if j == 0 && mt.Type.In(j) == reflect.TypeFor[*Tracker]() {
				continue
			}
			args = append(args, reflect.Zero(mt.Type.In(j)))
		}
		rv.Method(i).Call(args)
	}
}

func TestSetUnhealthyWithDuplicateThenHealthyAgain(t *testing.T) {
	bus := eventbustest.NewBus(t)
	watcher := eventbustest.NewWatcher(t, bus)
	ht := NewTracker(bus)
	if len(ht.Strings()) != 0 {
		t.Fatalf("before first insertion, len(newTracker.Strings) = %d; want = 0", len(ht.Strings()))
	}

	ht.SetUnhealthy(testWarnable, Args{ArgError: "Hello world 1"})
	want := []string{"Hello world 1"}
	if !reflect.DeepEqual(ht.Strings(), want) {
		t.Fatalf("after calling SetUnhealthy, newTracker.Strings() = %v; want = %v", ht.Strings(), want)
	}

	// Adding a second warning state with the same WarningCode overwrites the existing warning state,
	// the count shouldn't have changed.
	ht.SetUnhealthy(testWarnable, Args{ArgError: "Hello world 2"})
	want = []string{"Hello world 2"}
	if !reflect.DeepEqual(ht.Strings(), want) {
		t.Fatalf("after insertion of same WarningCode, newTracker.Strings() = %v; want = %v", ht.Strings(), want)
	}

	ht.SetHealthy(testWarnable)
	want = []string{}
	if !reflect.DeepEqual(ht.Strings(), want) {
		t.Fatalf("after setting the healthy, newTracker.Strings() = %v; want = %v", ht.Strings(), want)
	}

	if err := eventbustest.ExpectExactly(watcher,
		wantChange(Change{WarnableChanged: true, Warnable: testWarnable}),
		wantChange(Change{WarnableChanged: true, Warnable: testWarnable}),
		wantChange(Change{WarnableChanged: true, Warnable: testWarnable}),
	); err != nil {
		t.Fatalf("expected events, got %q", err)
	}
}

func TestRemoveAllWarnings(t *testing.T) {
	bus := eventbustest.NewBus(t)
	watcher := eventbustest.NewWatcher(t, bus)
	ht := NewTracker(bus)
	if len(ht.Strings()) != 0 {
		t.Fatalf("before first insertion, len(newTracker.Strings) = %d; want = 0", len(ht.Strings()))
	}

	ht.SetUnhealthy(testWarnable, Args{"Text": "Hello world 1"})
	if len(ht.Strings()) != 1 {
		t.Fatalf("after first insertion, len(newTracker.Strings) = %d; want = %d", len(ht.Strings()), 1)
	}

	ht.SetHealthy(testWarnable)
	if len(ht.Strings()) != 0 {
		t.Fatalf("after RemoveAll, len(newTracker.Strings) = %d; want = 0", len(ht.Strings()))
	}
	if err := eventbustest.ExpectExactly(watcher,
		wantChange(Change{WarnableChanged: true, Warnable: testWarnable}),
		wantChange(Change{WarnableChanged: true, Warnable: testWarnable}),
	); err != nil {
		t.Fatalf("expected events, got %q", err)
	}
}

// TestWatcher tests that a registered watcher function gets called with the correct
// Warnable and non-nil/nil UnhealthyState upon setting a Warnable to unhealthy/healthy.
func TestWatcher(t *testing.T) {
	tests := []struct {
		name    string
		preFunc func(t *testing.T, ht *Tracker, bus *eventbus.Bus, fn func(Change))
	}{
		{
			name: "with-eventbus",
			preFunc: func(_ *testing.T, _ *Tracker, bus *eventbus.Bus, fn func(c Change)) {
				client := bus.Client("healthwatchertestclient")
				sub := eventbus.Subscribe[Change](client)
				go func() {
					for {
						select {
						case <-sub.Done():
							return
						case change := <-sub.Events():
							fn(change)
						}
					}
				}()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(*testing.T) {
			bus := eventbustest.NewBus(t)
			ht := NewTracker(bus)
			wantText := "Hello world"
			becameUnhealthy := make(chan struct{})
			becameHealthy := make(chan struct{})

			watcherFunc := func(c Change) {
				w := c.Warnable
				us := c.UnhealthyState
				if w != testWarnable {
					t.Fatalf("watcherFunc was called, but with an unexpected Warnable: %v, want: %v", w, testWarnable)
				}

				if us != nil {
					if us.Text != wantText {
						t.Fatalf("unexpected us.Text: %q, want: %s", us.Text, wantText)
					}
					if us.Args[ArgError] != wantText {
						t.Fatalf("unexpected us.Args[ArgError]: %q, want: %s", us.Args[ArgError], wantText)
					}
					becameUnhealthy <- struct{}{}
				} else {
					becameHealthy <- struct{}{}
				}
			}

			// Set up test
			tt.preFunc(t, ht, bus, watcherFunc)

			// Start running actual test
			ht.SetUnhealthy(testWarnable, Args{ArgError: wantText})

			select {
			case <-becameUnhealthy:
				// Test passed because the watcher got notified of an unhealthy state
			case <-becameHealthy:
				// Test failed because the watcher got of a healthy state instead of an unhealthy one
				t.Fatalf("watcherFunc was called with a healthy state")
			case <-time.After(5 * time.Second):
				t.Fatalf("watcherFunc didn't get called upon calling SetUnhealthy")
			}

			ht.SetHealthy(testWarnable)

			select {
			case <-becameUnhealthy:
				// Test failed because the watcher got of an unhealthy state instead of a healthy one
				t.Fatalf("watcherFunc was called with an unhealthy state")
			case <-becameHealthy:
				// Test passed because the watcher got notified of a healthy state
			case <-time.After(5 * time.Second):
				t.Fatalf("watcherFunc didn't get called upon calling SetUnhealthy")
			}
		})
	}
}

// TestWatcherWithTimeToVisible tests that a registered watcher function gets called with the correct
// Warnable and non-nil/nil UnhealthyState upon setting a Warnable to unhealthy/healthy, but the Warnable
// has a TimeToVisible set, which means that a watcher should only be notified of an unhealthy state after
// the TimeToVisible duration has passed.
func TestSetUnhealthyWithTimeToVisible(t *testing.T) {
	tests := []struct {
		name    string
		preFunc func(t *testing.T, ht *Tracker, bus *eventbus.Bus, fn func(Change))
	}{
		{
			name: "with-eventbus",
			preFunc: func(_ *testing.T, _ *Tracker, bus *eventbus.Bus, fn func(c Change)) {
				client := bus.Client("healthwatchertestclient")
				sub := eventbus.Subscribe[Change](client)
				go func() {
					for {
						select {
						case <-sub.Done():
							return
						case change := <-sub.Events():
							fn(change)
						}
					}
				}()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(*testing.T) {
			bus := eventbustest.NewBus(t)
			ht := NewTracker(bus)
			mw := Register(&Warnable{
				Code:                "test-warnable-3-secs-to-visible",
				Title:               "Test Warnable with 3 seconds to visible",
				Text:                StaticMessage("Hello world"),
				TimeToVisible:       2 * time.Second,
				ImpactsConnectivity: true,
			})

			becameUnhealthy := make(chan struct{})
			becameHealthy := make(chan struct{})

			watchFunc := func(c Change) {
				w := c.Warnable
				us := c.UnhealthyState
				if w != mw {
					t.Fatalf("watcherFunc was called, but with an unexpected Warnable: %v, want: %v", w, w)
				}

				if us != nil {
					becameUnhealthy <- struct{}{}
				} else {
					becameHealthy <- struct{}{}
				}
			}

			tt.preFunc(t, ht, bus, watchFunc)
			ht.SetUnhealthy(mw, Args{ArgError: "Hello world"})

			select {
			case <-becameUnhealthy:
				// Test failed because the watcher got notified of an unhealthy state
				t.Fatalf("watcherFunc was called with an unhealthy state")
			case <-becameHealthy:
				// Test failed because the watcher got of a healthy state
				t.Fatalf("watcherFunc was called with a healthy state")
			case <-time.After(1 * time.Second):
				// As expected, watcherFunc still had not been called after 1 second
			}
			unregister(mw)
		})
	}
}

func TestRegisterWarnablePanicsWithDuplicate(t *testing.T) {
	w := &Warnable{
		Code: "test-warnable-1",
	}

	Register(w)
	defer unregister(w)
	if registeredWarnables[w.Code] != w {
		t.Fatalf("after Register, registeredWarnables[%s] = %v; want = %v", w.Code, registeredWarnables[w.Code], w)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("Registering the same Warnable twice didn't panic")
		}
	}()
	Register(w)
}

// TestCheckDependsOnAppearsInUnhealthyState asserts that the DependsOn field in the UnhealthyState
// is populated with the WarnableCode(s) of the Warnable(s) that a warning depends on.
func TestCheckDependsOnAppearsInUnhealthyState(t *testing.T) {
	ht := NewTracker(eventbustest.NewBus(t))
	w1 := Register(&Warnable{
		Code:      "w1",
		Text:      StaticMessage("W1 Text"),
		DependsOn: []*Warnable{},
	})
	defer unregister(w1)
	w2 := Register(&Warnable{
		Code:      "w2",
		Text:      StaticMessage("W2 Text"),
		DependsOn: []*Warnable{w1},
	})
	defer unregister(w2)

	ht.SetUnhealthy(w1, Args{ArgError: "w1 is unhealthy"})
	us1, ok := ht.CurrentState().Warnings[w1.Code]
	if !ok {
		t.Fatalf("Expected an UnhealthyState for w1, got nothing")
	}
	wantDependsOn := []WarnableCode{warmingUpWarnable.Code}
	if !reflect.DeepEqual(us1.DependsOn, wantDependsOn) {
		t.Fatalf("Expected DependsOn = %v in the unhealthy state, got: %v", wantDependsOn, us1.DependsOn)
	}
	ht.SetUnhealthy(w2, Args{ArgError: "w2 is also unhealthy now"})
	us2, ok := ht.CurrentState().Warnings[w2.Code]
	if ok {
		t.Fatalf("Saw w2 being unhealthy but it shouldn't be, as it depends on unhealthy w1")
	}
	ht.SetHealthy(w1)
	us2, ok = ht.CurrentState().Warnings[w2.Code]
	if !ok {
		t.Fatalf("w2 wasn't unhealthy; want it to be unhealthy now that w1 is back healthy")
	}

	wantDependsOn = slices.Concat([]WarnableCode{w1.Code}, wantDependsOn)
	if !reflect.DeepEqual(us2.DependsOn, wantDependsOn) {
		t.Fatalf("Expected DependsOn = %v in the unhealthy state, got: %v", wantDependsOn, us2.DependsOn)
	}
}

func TestShowUpdateWarnable(t *testing.T) {
	tests := []struct {
		desc         string
		check        bool
		apply        opt.Bool
		cv           *tailcfg.ClientVersion
		wantWarnable *Warnable
		wantShow     bool
	}{
		{
			desc:         "nil ClientVersion",
			check:        true,
			cv:           nil,
			wantWarnable: nil,
			wantShow:     false,
		},
		{
			desc:         "RunningLatest",
			check:        true,
			cv:           &tailcfg.ClientVersion{RunningLatest: true},
			wantWarnable: nil,
			wantShow:     false,
		},
		{
			desc:         "no LatestVersion",
			check:        true,
			cv:           &tailcfg.ClientVersion{RunningLatest: false, LatestVersion: ""},
			wantWarnable: nil,
			wantShow:     false,
		},
		{
			desc:         "show regular update",
			check:        true,
			cv:           &tailcfg.ClientVersion{RunningLatest: false, LatestVersion: "1.2.3"},
			wantWarnable: updateAvailableWarnable,
			wantShow:     true,
		},
		{
			desc:         "show security update",
			check:        true,
			cv:           &tailcfg.ClientVersion{RunningLatest: false, LatestVersion: "1.2.3", UrgentSecurityUpdate: true},
			wantWarnable: securityUpdateAvailableWarnable,
			wantShow:     true,
		},
		{
			desc:         "update check disabled",
			check:        false,
			cv:           &tailcfg.ClientVersion{RunningLatest: false, LatestVersion: "1.2.3"},
			wantWarnable: nil,
			wantShow:     false,
		},
		{
			desc:         "hide update with auto-updates",
			check:        true,
			apply:        opt.NewBool(true),
			cv:           &tailcfg.ClientVersion{RunningLatest: false, LatestVersion: "1.2.3"},
			wantWarnable: nil,
			wantShow:     false,
		},
		{
			desc:         "show security update with auto-updates",
			check:        true,
			apply:        opt.NewBool(true),
			cv:           &tailcfg.ClientVersion{RunningLatest: false, LatestVersion: "1.2.3", UrgentSecurityUpdate: true},
			wantWarnable: securityUpdateAvailableWarnable,
			wantShow:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			tr := NewTracker(eventbustest.NewBus(t))
			tr.checkForUpdates = tt.check
			tr.applyUpdates = tt.apply
			tr.latestVersion = tt.cv

			gotWarnable, gotShow := tr.showUpdateWarnable()
			if gotWarnable != tt.wantWarnable {
				t.Errorf("got warnable: %v, want: %v", gotWarnable, tt.wantWarnable)
			}
			if gotShow != tt.wantShow {
				t.Errorf("got show: %v, want: %v", gotShow, tt.wantShow)
			}
		})
	}
}

func TestHealthMetric(t *testing.T) {
	unstableBuildWarning := 0
	if version.IsUnstableBuild() {
		unstableBuildWarning = 1
	}

	tests := []struct {
		desc            string
		check           bool
		apply           opt.Bool
		cv              *tailcfg.ClientVersion
		wantMetricCount int
	}{
		// When running in dev, and not initialising the client, there will be two warnings
		// by default:
		// - is-using-unstable-version (except on the release branch)
		// - wantrunning-false
		{
			desc:            "base-warnings",
			check:           true,
			cv:              nil,
			wantMetricCount: unstableBuildWarning + 1,
		},
		// with: update-available
		{
			desc:            "update-warning",
			check:           true,
			cv:              &tailcfg.ClientVersion{RunningLatest: false, LatestVersion: "1.2.3"},
			wantMetricCount: unstableBuildWarning + 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			tr := NewTracker(eventbustest.NewBus(t))
			tr.checkForUpdates = tt.check
			tr.applyUpdates = tt.apply
			tr.latestVersion = tt.cv
			tr.SetMetricsRegistry(&usermetric.Registry{})
			if val := tr.metricHealthMessage.Get(metricHealthMessageLabel{Type: MetricLabelWarning}).String(); val != strconv.Itoa(tt.wantMetricCount) {
				t.Fatalf("metric value: %q, want: %q", val, strconv.Itoa(tt.wantMetricCount))
			}
			for _, w := range tr.CurrentState().Warnings {
				t.Logf("warning: %v", w)
			}
		})
	}
}

// TestNoDERPHomeWarnable checks that we don't
// complain about no DERP home if we're not in a
// map poll.
func TestNoDERPHomeWarnable(t *testing.T) {
	t.Skip("TODO: fix https://github.com/tailscale/tailscale/issues/14798 to make this test not deadlock")
	clock := tstest.NewClock(tstest.ClockOpts{
		Start:          time.Unix(123, 0),
		FollowRealTime: false,
	})
	ht := NewTracker(eventbustest.NewBus(t))
	ht.testClock = clock
	ht.SetIPNState("NeedsLogin", true)

	// Advance 30 seconds to get past the "recentlyLoggedIn" check.
	clock.Advance(30 * time.Second)
	ht.updateBuiltinWarnablesLocked()

	// Advance to get past the the TimeToVisible delay.
	clock.Advance(noDERPHomeWarnable.TimeToVisible * 2)

	ht.updateBuiltinWarnablesLocked()
	if ws, ok := ht.CurrentState().Warnings[noDERPHomeWarnable.Code]; ok {
		t.Fatalf("got unexpected noDERPHomeWarnable warnable: %v", ws)
	}
}

// TestNoDERPHomeWarnableManual is like TestNoDERPHomeWarnable
// but doesn't use tstest.Clock so avoids the deadlock
// I hit: https://github.com/tailscale/tailscale/issues/14798
func TestNoDERPHomeWarnableManual(t *testing.T) {
	ht := NewTracker(eventbustest.NewBus(t))
	ht.SetIPNState("NeedsLogin", true)

	// Avoid wantRunning:
	ht.ipnWantRunningLastTrue = ht.ipnWantRunningLastTrue.Add(-10 * time.Second)
	ht.updateBuiltinWarnablesLocked()

	ws, ok := ht.warnableVal[noDERPHomeWarnable]
	if ok {
		t.Fatalf("got unexpected noDERPHomeWarnable warnable: %v", ws)
	}
}

func TestControlHealth(t *testing.T) {
	ht := NewTracker(eventbustest.NewBus(t))
	ht.SetIPNState("NeedsLogin", true)
	ht.GotStreamedMapResponse()

	baseWarns := ht.CurrentState().Warnings
	baseStrs := ht.Strings()

	msgs := map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
		"test": {
			Title: "Control health message",
			Text:  "Extra help.",
		},
		"title": {
			Title: "Control health title only",
		},
		"with-action": {
			Title: "Control health message",
			Text:  "Extra help.",
			PrimaryAction: &tailcfg.DisplayMessageAction{
				URL:   "http://www.example.com",
				Label: "Learn more",
			},
		},
	}
	ht.SetControlHealth(msgs)

	t.Run("Warnings", func(t *testing.T) {
		wantWarns := map[WarnableCode]UnhealthyState{
			"control-health.test": {
				WarnableCode: "control-health.test",
				Severity:     SeverityMedium,
				Title:        "Control health message",
				Text:         "Extra help.",
			},
			"control-health.title": {
				WarnableCode: "control-health.title",
				Severity:     SeverityMedium,
				Title:        "Control health title only",
			},
			"control-health.with-action": {
				WarnableCode: "control-health.with-action",
				Severity:     SeverityMedium,
				Title:        "Control health message",
				Text:         "Extra help.",
				PrimaryAction: &UnhealthyStateAction{
					URL:   "http://www.example.com",
					Label: "Learn more",
				},
			},
		}
		state := ht.CurrentState()
		gotWarns := maps.Clone(state.Warnings)
		for k := range gotWarns {
			if _, inBase := baseWarns[k]; inBase {
				delete(gotWarns, k)
			}
		}
		if diff := cmp.Diff(wantWarns, gotWarns, cmpopts.IgnoreFields(UnhealthyState{}, "ETag")); diff != "" {
			t.Fatalf(`CurrentState().Warnings["control-health-*"] wrong (-want +got):\n%s`, diff)
		}
	})

	t.Run("Strings()", func(t *testing.T) {
		wantStrs := []string{
			"Control health message: Extra help.",
			"Control health message: Extra help. Learn more: http://www.example.com",
			"Control health title only.",
		}
		var gotStrs []string
		for _, s := range ht.Strings() {
			if !slices.Contains(baseStrs, s) {
				gotStrs = append(gotStrs, s)
			}
		}
		if diff := cmp.Diff(wantStrs, gotStrs); diff != "" {
			t.Fatalf(`Strings() wrong (-want +got):\n%s`, diff)
		}
	})

	t.Run("tailscaled_health_messages", func(t *testing.T) {
		var r usermetric.Registry
		ht.SetMetricsRegistry(&r)

		got := ht.metricHealthMessage.Get(metricHealthMessageLabel{
			Type: MetricLabelWarning,
		}).String()
		want := strconv.Itoa(
			len(msgs) + len(baseStrs),
		)
		if got != want {
			t.Errorf("metricsHealthMessage.Get(warning) = %q, want %q", got, want)
		}
	})
}

func TestControlHealthNotifies(t *testing.T) {
	type test struct {
		name         string
		initialState map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage
		newState     map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage
		wantEvents   []any
	}
	tests := []test{
		{
			name: "no-change",
			initialState: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"test": {},
			},
			newState: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"test": {},
			},
			wantEvents: []any{},
		},
		{
			name:         "on-set",
			initialState: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{},
			newState: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"test": {},
			},
			wantEvents: []any{
				eventbustest.Type[Change](),
			},
		},
		{
			name: "details-change",
			initialState: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"test": {
					Title: "Title",
				},
			},
			newState: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"test": {
					Title: "Updated title",
				},
			},
			wantEvents: []any{
				eventbustest.Type[Change](),
			},
		},
		{
			name: "action-changes",
			initialState: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"test": {
					PrimaryAction: &tailcfg.DisplayMessageAction{
						URL:   "http://www.example.com/a/123456",
						Label: "Sign in",
					},
				},
			},
			newState: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"test": {
					PrimaryAction: &tailcfg.DisplayMessageAction{
						URL:   "http://www.example.com/a/abcdefg",
						Label: "Sign in",
					},
				},
			},
			wantEvents: []any{
				eventbustest.Type[Change](),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bus := eventbustest.NewBus(t)
			tw := eventbustest.NewWatcher(t, bus)
			tw.TimeOut = time.Second

			ht := NewTracker(bus)
			ht.SetIPNState("NeedsLogin", true)
			ht.GotStreamedMapResponse()

			// Expect events at starup, before doing anything else
			if err := eventbustest.ExpectExactly(tw,
				eventbustest.Type[Change](), // warming-up
				eventbustest.Type[Change](), // is-using-unstable-version
				eventbustest.Type[Change](), // not-in-map-poll
			); err != nil {
				t.Errorf("startup error: %v", err)
			}

			// Only set initial state if we need to
			if len(test.initialState) != 0 {
				ht.SetControlHealth(test.initialState)
				if err := eventbustest.ExpectExactly(tw, eventbustest.Type[Change]()); err != nil {
					t.Errorf("initial state error: %v", err)
				}
			}

			ht.SetControlHealth(test.newState)

			if err := eventbustest.ExpectExactly(tw, test.wantEvents...); err != nil {
				t.Errorf("event error: %v", err)
			}
		})
	}
}

func TestControlHealthIgnoredOutsideMapPoll(t *testing.T) {
	bus := eventbustest.NewBus(t)
	tw := eventbustest.NewWatcher(t, bus)
	tw.TimeOut = 100 * time.Millisecond
	ht := NewTracker(bus)
	ht.SetIPNState("NeedsLogin", true)

	ht.SetControlHealth(map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
		"control-health": {},
	})

	state := ht.CurrentState()
	_, ok := state.Warnings["control-health"]

	if ok {
		t.Error("got a warning with code 'control-health', want none")
	}

	// An event is emitted when SetIPNState is run above,
	// so only fail on the second event.
	eventCounter := 0
	expectOne := func(c *Change) error {
		eventCounter++
		if eventCounter == 1 {
			return nil
		}
		return errors.New("saw more than 1 event")
	}

	if err := eventbustest.Expect(tw, expectOne); err == nil {
		t.Error("event got emitted, want it to not be called")
	}
}

// TestCurrentStateETagControlHealth tests that the ETag on an [UnhealthyState]
// created from Control health & returned by [Tracker.CurrentState] is different
// when the details of the [tailcfg.DisplayMessage] are different.
func TestCurrentStateETagControlHealth(t *testing.T) {
	ht := NewTracker(eventbustest.NewBus(t))
	ht.SetIPNState("NeedsLogin", true)
	ht.GotStreamedMapResponse()

	msg := tailcfg.DisplayMessage{
		Title:               "Test Warning",
		Text:                "This is a test warning.",
		Severity:            tailcfg.SeverityHigh,
		ImpactsConnectivity: true,
		PrimaryAction: &tailcfg.DisplayMessageAction{
			URL:   "https://example.com/",
			Label: "open",
		},
	}

	type test struct {
		name            string
		change          func(tailcfg.DisplayMessage) tailcfg.DisplayMessage
		wantChangedETag bool
	}
	tests := []test{
		{
			name:            "same_value",
			change:          func(m tailcfg.DisplayMessage) tailcfg.DisplayMessage { return m },
			wantChangedETag: false,
		},
		{
			name: "different_severity",
			change: func(m tailcfg.DisplayMessage) tailcfg.DisplayMessage {
				m.Severity = tailcfg.SeverityLow
				return m
			},
			wantChangedETag: true,
		},
		{
			name: "different_title",
			change: func(m tailcfg.DisplayMessage) tailcfg.DisplayMessage {
				m.Title = "Different Title"
				return m
			},
			wantChangedETag: true,
		},
		{
			name: "different_text",
			change: func(m tailcfg.DisplayMessage) tailcfg.DisplayMessage {
				m.Text = "This is a different text."
				return m
			},
			wantChangedETag: true,
		},
		{
			name: "different_impacts_connectivity",
			change: func(m tailcfg.DisplayMessage) tailcfg.DisplayMessage {
				m.ImpactsConnectivity = false
				return m
			},
			wantChangedETag: true,
		},
		{
			name: "different_primary_action_label",
			change: func(m tailcfg.DisplayMessage) tailcfg.DisplayMessage {
				m.PrimaryAction.Label = "new_label"
				return m
			},
			wantChangedETag: true,
		},
		{
			name: "different_primary_action_url",
			change: func(m tailcfg.DisplayMessage) tailcfg.DisplayMessage {
				m.PrimaryAction.URL = "https://new.example.com/"
				return m
			},
			wantChangedETag: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ht.SetControlHealth(map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"test-message": msg,
			})
			state := ht.CurrentState().Warnings["control-health.test-message"]

			newMsg := test.change(msg)
			ht.SetControlHealth(map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"test-message": newMsg,
			})
			newState := ht.CurrentState().Warnings["control-health.test-message"]

			if (state.ETag != newState.ETag) != test.wantChangedETag {
				if test.wantChangedETag {
					t.Errorf("got unchanged ETag, want changed (ETag was %q)", newState.ETag)
				} else {
					t.Errorf("got changed ETag, want unchanged")
				}
			}
		})
	}
}

// TestCurrentStateETagWarnable tests that the ETag on an [UnhealthyState]
// created from a Warnable & returned by [Tracker.CurrentState] is different
// when the details of the Warnable are different.
func TestCurrentStateETagWarnable(t *testing.T) {
	newTracker := func(clock tstime.Clock) *Tracker {
		ht := NewTracker(eventbustest.NewBus(t))
		ht.testClock = clock
		ht.SetIPNState("NeedsLogin", true)
		ht.GotStreamedMapResponse()
		return ht
	}

	t.Run("new_args", func(t *testing.T) {
		ht := newTracker(nil)

		ht.SetUnhealthy(testWarnable, Args{ArgError: "initial value"})
		state := ht.CurrentState().Warnings[testWarnable.Code]

		ht.SetUnhealthy(testWarnable, Args{ArgError: "new value"})
		newState := ht.CurrentState().Warnings[testWarnable.Code]

		if state.ETag == newState.ETag {
			t.Errorf("got unchanged ETag, want changed (ETag was %q)", newState.ETag)
		}
	})

	t.Run("new_broken_since", func(t *testing.T) {
		clock1 := tstest.NewClock(tstest.ClockOpts{
			Start: time.Unix(123, 0),
		})
		ht1 := newTracker(clock1)

		ht1.SetUnhealthy(testWarnable, Args{})
		state := ht1.CurrentState().Warnings[testWarnable.Code]

		// Use a second tracker to get a different broken since time
		clock2 := tstest.NewClock(tstest.ClockOpts{
			Start: time.Unix(456, 0),
		})
		ht2 := newTracker(clock2)

		ht2.SetUnhealthy(testWarnable, Args{})
		newState := ht2.CurrentState().Warnings[testWarnable.Code]

		if state.ETag == newState.ETag {
			t.Errorf("got unchanged ETag, want changed (ETag was %q)", newState.ETag)
		}
	})

	t.Run("no_change", func(t *testing.T) {
		clock := tstest.NewClock(tstest.ClockOpts{})
		ht1 := newTracker(clock)

		ht1.SetUnhealthy(testWarnable, Args{})
		state := ht1.CurrentState().Warnings[testWarnable.Code]

		// Using a second tracker because SetUnhealthy with no changes is a no-op
		ht2 := newTracker(clock)
		ht2.SetUnhealthy(testWarnable, Args{})
		newState := ht2.CurrentState().Warnings[testWarnable.Code]

		if state.ETag != newState.ETag {
			t.Errorf("got changed ETag, want unchanged")
		}
	})
}
