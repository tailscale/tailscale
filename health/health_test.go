// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package health

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
	"tailscale.com/util/usermetric"
	"tailscale.com/version"
)

func TestAppendWarnableDebugFlags(t *testing.T) {
	var tr Tracker

	for i := range 10 {
		w := Register(&Warnable{
			Code:         WarnableCode(fmt.Sprintf("warnable-code-%d", i)),
			MapDebugFlag: fmt.Sprint(i),
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
	ht := Tracker{}
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
}

func TestRemoveAllWarnings(t *testing.T) {
	ht := Tracker{}
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
}

// TestWatcher tests that a registered watcher function gets called with the correct
// Warnable and non-nil/nil UnhealthyState upon setting a Warnable to unhealthy/healthy.
func TestWatcher(t *testing.T) {
	ht := Tracker{}
	wantText := "Hello world"
	becameUnhealthy := make(chan struct{})
	becameHealthy := make(chan struct{})

	watcherFunc := func(w *Warnable, us *UnhealthyState) {
		if w != testWarnable {
			t.Fatalf("watcherFunc was called, but with an unexpected Warnable: %v, want: %v", w, testWarnable)
		}

		if us != nil {
			if us.Text != wantText {
				t.Fatalf("unexpected us.Text: %s, want: %s", us.Text, wantText)
			}
			if us.Args[ArgError] != wantText {
				t.Fatalf("unexpected us.Args[ArgError]: %s, want: %s", us.Args[ArgError], wantText)
			}
			becameUnhealthy <- struct{}{}
		} else {
			becameHealthy <- struct{}{}
		}
	}

	unregisterFunc := ht.RegisterWatcher(watcherFunc)
	if len(ht.watchers) != 1 {
		t.Fatalf("after RegisterWatcher, len(newTracker.watchers) = %d; want = 1", len(ht.watchers))
	}
	ht.SetUnhealthy(testWarnable, Args{ArgError: wantText})

	select {
	case <-becameUnhealthy:
		// Test passed because the watcher got notified of an unhealthy state
	case <-becameHealthy:
		// Test failed because the watcher got of a healthy state instead of an unhealthy one
		t.Fatalf("watcherFunc was called with a healthy state")
	case <-time.After(1 * time.Second):
		t.Fatalf("watcherFunc didn't get called upon calling SetUnhealthy")
	}

	ht.SetHealthy(testWarnable)

	select {
	case <-becameUnhealthy:
		// Test failed because the watcher got of an unhealthy state instead of a healthy one
		t.Fatalf("watcherFunc was called with an unhealthy state")
	case <-becameHealthy:
		// Test passed because the watcher got notified of a healthy state
	case <-time.After(1 * time.Second):
		t.Fatalf("watcherFunc didn't get called upon calling SetUnhealthy")
	}

	unregisterFunc()
	if len(ht.watchers) != 0 {
		t.Fatalf("after unregisterFunc, len(newTracker.watchers) = %d; want = 0", len(ht.watchers))
	}
}

// TestWatcherWithTimeToVisible tests that a registered watcher function gets called with the correct
// Warnable and non-nil/nil UnhealthyState upon setting a Warnable to unhealthy/healthy, but the Warnable
// has a TimeToVisible set, which means that a watcher should only be notified of an unhealthy state after
// the TimeToVisible duration has passed.
func TestSetUnhealthyWithTimeToVisible(t *testing.T) {
	ht := Tracker{}
	mw := Register(&Warnable{
		Code:                "test-warnable-3-secs-to-visible",
		Title:               "Test Warnable with 3 seconds to visible",
		Text:                StaticMessage("Hello world"),
		TimeToVisible:       2 * time.Second,
		ImpactsConnectivity: true,
	})
	defer unregister(mw)

	becameUnhealthy := make(chan struct{})
	becameHealthy := make(chan struct{})

	watchFunc := func(w *Warnable, us *UnhealthyState) {
		if w != mw {
			t.Fatalf("watcherFunc was called, but with an unexpected Warnable: %v, want: %v", w, w)
		}

		if us != nil {
			becameUnhealthy <- struct{}{}
		} else {
			becameHealthy <- struct{}{}
		}
	}

	ht.RegisterWatcher(watchFunc)
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
	ht := Tracker{}
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
	if !ok {
		t.Fatalf("Expected an UnhealthyState for w2, got nothing")
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
			tr := &Tracker{
				checkForUpdates: tt.check,
				applyUpdates:    tt.apply,
				latestVersion:   tt.cv,
			}
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
			tr := &Tracker{
				checkForUpdates: tt.check,
				applyUpdates:    tt.apply,
				latestVersion:   tt.cv,
			}
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
