// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package rsop

import (
	"errors"
	"slices"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/tstest"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/syspolicy/setting"

	"tailscale.com/util/syspolicy/source"
)

func TestGetEffectivePolicyNoSource(t *testing.T) {
	tests := []struct {
		name  string
		scope setting.PolicyScope
	}{
		{
			name:  "DevicePolicy",
			scope: setting.DeviceScope,
		},
		{
			name:  "CurrentProfilePolicy",
			scope: setting.CurrentProfileScope,
		},
		{
			name:  "CurrentUserPolicy",
			scope: setting.CurrentUserScope,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var policy *Policy
			t.Cleanup(func() {
				if policy != nil {
					policy.Close()
					<-policy.Done()
				}
			})

			// Make sure we don't create any goroutines.
			// We intentionally call ResourceCheck after t.Cleanup, so that when the test exits,
			// the resource check runs before the test cleanup closes the policy.
			// This helps to report any unexpectedly created goroutines.
			// The goal is to ensure that using the syspolicy package, and particularly
			// the rsop sub-package, is not wasteful and does not create unnecessary goroutines
			// on platforms without registered policy sources.
			tstest.ResourceCheck(t)

			policy, err := PolicyFor(tt.scope)
			if err != nil {
				t.Fatalf("Failed to get effective policy for %v: %v", tt.scope, err)
			}

			if got := policy.Get(); got.Len() != 0 {
				t.Errorf("Snapshot: got %v; want empty", got)
			}

			if got, err := policy.Reload(); err != nil {
				t.Errorf("Reload failed: %v", err)
			} else if got.Len() != 0 {
				t.Errorf("Snapshot: got %v; want empty", got)
			}
		})
	}
}

func TestRegisterSourceAndGetEffectivePolicy(t *testing.T) {
	type sourceConfig struct {
		name          string
		scope         setting.PolicyScope
		settingKey    pkey.Key
		settingValue  string
		wantEffective bool
	}
	tests := []struct {
		name              string
		scope             setting.PolicyScope
		initialSources    []sourceConfig
		additionalSources []sourceConfig
		wantSnapshot      *setting.Snapshot
	}{
		{
			name:         "DevicePolicy/NoSources",
			scope:        setting.DeviceScope,
			wantSnapshot: setting.NewSnapshot(nil, setting.DeviceScope),
		},
		{
			name:         "UserScope/NoSources",
			scope:        setting.CurrentUserScope,
			wantSnapshot: setting.NewSnapshot(nil, setting.CurrentUserScope),
		},
		{
			name:  "DevicePolicy/OneInitialSource",
			scope: setting.DeviceScope,
			initialSources: []sourceConfig{
				{
					name:          "TestSourceA",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "TestValueA",
					wantEffective: true,
				},
			},
			wantSnapshot: setting.NewSnapshot(map[pkey.Key]setting.RawItem{
				"TestKeyA": setting.RawItemWith("TestValueA", nil, setting.NewNamedOrigin("TestSourceA", setting.DeviceScope)),
			}, setting.NewNamedOrigin("TestSourceA", setting.DeviceScope)),
		},
		{
			name:  "DevicePolicy/OneAdditionalSource",
			scope: setting.DeviceScope,
			additionalSources: []sourceConfig{
				{
					name:          "TestSourceA",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "TestValueA",
					wantEffective: true,
				},
			},
			wantSnapshot: setting.NewSnapshot(map[pkey.Key]setting.RawItem{
				"TestKeyA": setting.RawItemWith("TestValueA", nil, setting.NewNamedOrigin("TestSourceA", setting.DeviceScope)),
			}, setting.NewNamedOrigin("TestSourceA", setting.DeviceScope)),
		},
		{
			name:  "DevicePolicy/ManyInitialSources/NoConflicts",
			scope: setting.DeviceScope,
			initialSources: []sourceConfig{
				{
					name:          "TestSourceA",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "TestValueA",
					wantEffective: true,
				},
				{
					name:          "TestSourceB",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyB",
					settingValue:  "TestValueB",
					wantEffective: true,
				},
				{
					name:          "TestSourceC",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyC",
					settingValue:  "TestValueC",
					wantEffective: true,
				},
			},
			wantSnapshot: setting.NewSnapshot(map[pkey.Key]setting.RawItem{
				"TestKeyA": setting.RawItemWith("TestValueA", nil, setting.NewNamedOrigin("TestSourceA", setting.DeviceScope)),
				"TestKeyB": setting.RawItemWith("TestValueB", nil, setting.NewNamedOrigin("TestSourceB", setting.DeviceScope)),
				"TestKeyC": setting.RawItemWith("TestValueC", nil, setting.NewNamedOrigin("TestSourceC", setting.DeviceScope)),
			}, setting.DeviceScope),
		},
		{
			name:  "DevicePolicy/ManyInitialSources/Conflicts",
			scope: setting.DeviceScope,
			initialSources: []sourceConfig{
				{
					name:          "TestSourceA",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "TestValueA",
					wantEffective: true,
				},
				{
					name:          "TestSourceB",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyB",
					settingValue:  "TestValueB",
					wantEffective: true,
				},
				{
					name:          "TestSourceC",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "TestValueC",
					wantEffective: true,
				},
			},
			wantSnapshot: setting.NewSnapshot(map[pkey.Key]setting.RawItem{
				"TestKeyA": setting.RawItemWith("TestValueC", nil, setting.NewNamedOrigin("TestSourceC", setting.DeviceScope)),
				"TestKeyB": setting.RawItemWith("TestValueB", nil, setting.NewNamedOrigin("TestSourceB", setting.DeviceScope)),
			}, setting.DeviceScope),
		},
		{
			name:  "DevicePolicy/MixedSources/Conflicts",
			scope: setting.DeviceScope,
			initialSources: []sourceConfig{
				{
					name:          "TestSourceA",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "TestValueA",
					wantEffective: true,
				},
				{
					name:          "TestSourceB",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyB",
					settingValue:  "TestValueB",
					wantEffective: true,
				},
				{
					name:          "TestSourceC",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "TestValueC",
					wantEffective: true,
				},
			},
			additionalSources: []sourceConfig{
				{
					name:          "TestSourceD",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "TestValueD",
					wantEffective: true,
				},
				{
					name:          "TestSourceE",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyC",
					settingValue:  "TestValueE",
					wantEffective: true,
				},
				{
					name:          "TestSourceF",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "TestValueF",
					wantEffective: true,
				},
			},
			wantSnapshot: setting.NewSnapshot(map[pkey.Key]setting.RawItem{
				"TestKeyA": setting.RawItemWith("TestValueF", nil, setting.NewNamedOrigin("TestSourceF", setting.DeviceScope)),
				"TestKeyB": setting.RawItemWith("TestValueB", nil, setting.NewNamedOrigin("TestSourceB", setting.DeviceScope)),
				"TestKeyC": setting.RawItemWith("TestValueE", nil, setting.NewNamedOrigin("TestSourceE", setting.DeviceScope)),
			}, setting.DeviceScope),
		},
		{
			name:  "UserScope/Init-DeviceSource",
			scope: setting.CurrentUserScope,
			initialSources: []sourceConfig{
				{
					name:          "TestSourceDevice",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "DeviceValue",
					wantEffective: true,
				},
			},
			wantSnapshot: setting.NewSnapshot(map[pkey.Key]setting.RawItem{
				"TestKeyA": setting.RawItemWith("DeviceValue", nil, setting.NewNamedOrigin("TestSourceDevice", setting.DeviceScope)),
			}, setting.CurrentUserScope, setting.NewNamedOrigin("TestSourceDevice", setting.DeviceScope)),
		},
		{
			name:  "UserScope/Init-DeviceSource/Add-UserSource",
			scope: setting.CurrentUserScope,
			initialSources: []sourceConfig{
				{
					name:          "TestSourceDevice",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "DeviceValue",
					wantEffective: true,
				},
			},
			additionalSources: []sourceConfig{
				{
					name:          "TestSourceUser",
					scope:         setting.CurrentUserScope,
					settingKey:    "TestKeyB",
					settingValue:  "UserValue",
					wantEffective: true,
				},
			},
			wantSnapshot: setting.NewSnapshot(map[pkey.Key]setting.RawItem{
				"TestKeyA": setting.RawItemWith("DeviceValue", nil, setting.NewNamedOrigin("TestSourceDevice", setting.DeviceScope)),
				"TestKeyB": setting.RawItemWith("UserValue", nil, setting.NewNamedOrigin("TestSourceUser", setting.CurrentUserScope)),
			}, setting.CurrentUserScope),
		},
		{
			name:  "UserScope/Init-DeviceSource/Add-UserSource-and-ProfileSource",
			scope: setting.CurrentUserScope,
			initialSources: []sourceConfig{
				{
					name:          "TestSourceDevice",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "DeviceValue",
					wantEffective: true,
				},
			},
			additionalSources: []sourceConfig{
				{
					name:          "TestSourceProfile",
					scope:         setting.CurrentProfileScope,
					settingKey:    "TestKeyB",
					settingValue:  "ProfileValue",
					wantEffective: true,
				},
				{
					name:          "TestSourceUser",
					scope:         setting.CurrentUserScope,
					settingKey:    "TestKeyB",
					settingValue:  "UserValue",
					wantEffective: true,
				},
			},
			wantSnapshot: setting.NewSnapshot(map[pkey.Key]setting.RawItem{
				"TestKeyA": setting.RawItemWith("DeviceValue", nil, setting.NewNamedOrigin("TestSourceDevice", setting.DeviceScope)),
				"TestKeyB": setting.RawItemWith("ProfileValue", nil, setting.NewNamedOrigin("TestSourceProfile", setting.CurrentProfileScope)),
			}, setting.CurrentUserScope),
		},
		{
			name:  "DevicePolicy/User-Source-does-not-apply",
			scope: setting.DeviceScope,
			initialSources: []sourceConfig{
				{
					name:          "TestSourceDevice",
					scope:         setting.DeviceScope,
					settingKey:    "TestKeyA",
					settingValue:  "DeviceValue",
					wantEffective: true,
				},
			},
			additionalSources: []sourceConfig{
				{
					name:          "TestSourceUser",
					scope:         setting.CurrentUserScope,
					settingKey:    "TestKeyA",
					settingValue:  "UserValue",
					wantEffective: false, // Registering a user source should have no impact on the device policy.
				},
			},
			wantSnapshot: setting.NewSnapshot(map[pkey.Key]setting.RawItem{
				"TestKeyA": setting.RawItemWith("DeviceValue", nil, setting.NewNamedOrigin("TestSourceDevice", setting.DeviceScope)),
			}, setting.NewNamedOrigin("TestSourceDevice", setting.DeviceScope)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Register all settings that we use in this test.
			var definitions []*setting.Definition
			for _, source := range slices.Concat(tt.initialSources, tt.additionalSources) {
				definitions = append(definitions, setting.NewDefinition(source.settingKey, tt.scope.Kind(), setting.StringValue))
			}
			if err := setting.SetDefinitionsForTest(t, definitions...); err != nil {
				t.Fatalf("SetDefinitionsForTest failed: %v", err)
			}

			// Add the initial policy sources.
			var wantSources []*source.Source
			for _, s := range tt.initialSources {
				store := source.NewTestStoreOf(t, source.TestSettingOf(s.settingKey, s.settingValue))
				source := source.NewSource(s.name, s.scope, store)
				if err := registerSource(source); err != nil {
					t.Fatalf("Failed to register policy source: %v", source)
				}
				if s.wantEffective {
					wantSources = append(wantSources, source)
				}
				t.Cleanup(func() { unregisterSource(source) })
			}

			// Retrieve the effective policy.
			policy, err := policyForTest(t, tt.scope)
			if err != nil {
				t.Fatalf("Failed to get effective policy for %v: %v", tt.scope, err)
			}

			checkPolicySources(t, policy, wantSources)

			// Add additional setting sources.
			for _, s := range tt.additionalSources {
				store := source.NewTestStoreOf(t, source.TestSettingOf(s.settingKey, s.settingValue))
				source := source.NewSource(s.name, s.scope, store)
				if err := registerSource(source); err != nil {
					t.Fatalf("Failed to register additional policy source: %v", source)
				}
				if s.wantEffective {
					wantSources = append(wantSources, source)
				}
				t.Cleanup(func() { unregisterSource(source) })
			}

			checkPolicySources(t, policy, wantSources)

			// Verify the final effective settings snapshots.
			if got := policy.Get(); !got.Equal(tt.wantSnapshot) {
				t.Errorf("Snapshot: got %v; want %v", got, tt.wantSnapshot)
			}
		})
	}
}

func TestPolicyFor(t *testing.T) {
	tests := []struct {
		name           string
		scopeA, scopeB setting.PolicyScope
		closePolicy    bool // indicates whether to close policyA before retrieving policyB
		wantSame       bool // specifies whether policyA and policyB should reference the same [Policy] instance
	}{
		{
			name:     "Device/Device",
			scopeA:   setting.DeviceScope,
			scopeB:   setting.DeviceScope,
			wantSame: true,
		},
		{
			name:     "Device/CurrentProfile",
			scopeA:   setting.DeviceScope,
			scopeB:   setting.CurrentProfileScope,
			wantSame: false,
		},
		{
			name:     "Device/CurrentUser",
			scopeA:   setting.DeviceScope,
			scopeB:   setting.CurrentUserScope,
			wantSame: false,
		},
		{
			name:     "CurrentProfile/CurrentProfile",
			scopeA:   setting.CurrentProfileScope,
			scopeB:   setting.CurrentProfileScope,
			wantSame: true,
		},
		{
			name:     "CurrentProfile/CurrentUser",
			scopeA:   setting.CurrentProfileScope,
			scopeB:   setting.CurrentUserScope,
			wantSame: false,
		},
		{
			name:     "CurrentUser/CurrentUser",
			scopeA:   setting.CurrentUserScope,
			scopeB:   setting.CurrentUserScope,
			wantSame: true,
		},
		{
			name:     "UserA/UserA",
			scopeA:   setting.UserScopeOf("UserA"),
			scopeB:   setting.UserScopeOf("UserA"),
			wantSame: true,
		},
		{
			name:     "UserA/UserB",
			scopeA:   setting.UserScopeOf("UserA"),
			scopeB:   setting.UserScopeOf("UserB"),
			wantSame: false,
		},
		{
			name:        "New-after-close",
			scopeA:      setting.DeviceScope,
			scopeB:      setting.DeviceScope,
			closePolicy: true,
			wantSame:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyA, err := policyForTest(t, tt.scopeA)
			if err != nil {
				t.Fatalf("Failed to get effective policy for %v: %v", tt.scopeA, err)
			}

			if tt.closePolicy {
				policyA.Close()
			}

			policyB, err := policyForTest(t, tt.scopeB)
			if err != nil {
				t.Fatalf("Failed to get effective policy for %v: %v", tt.scopeB, err)
			}

			if gotSame := policyA == policyB; gotSame != tt.wantSame {
				t.Fatalf("Got same: %v; want same %v", gotSame, tt.wantSame)
			}
		})
	}
}

func TestPolicyChangeHasChanged(t *testing.T) {
	tests := []struct {
		name          string
		old, new      map[pkey.Key]setting.RawItem
		wantChanged   []pkey.Key
		wantUnchanged []pkey.Key
	}{
		{
			name: "String-Settings",
			old: map[pkey.Key]setting.RawItem{
				"ChangedSetting":   setting.RawItemOf("Old"),
				"UnchangedSetting": setting.RawItemOf("Value"),
			},
			new: map[pkey.Key]setting.RawItem{
				"ChangedSetting":   setting.RawItemOf("New"),
				"UnchangedSetting": setting.RawItemOf("Value"),
			},
			wantChanged:   []pkey.Key{"ChangedSetting"},
			wantUnchanged: []pkey.Key{"UnchangedSetting"},
		},
		{
			name: "UInt64-Settings",
			old: map[pkey.Key]setting.RawItem{
				"ChangedSetting":   setting.RawItemOf(uint64(0)),
				"UnchangedSetting": setting.RawItemOf(uint64(42)),
			},
			new: map[pkey.Key]setting.RawItem{
				"ChangedSetting":   setting.RawItemOf(uint64(1)),
				"UnchangedSetting": setting.RawItemOf(uint64(42)),
			},
			wantChanged:   []pkey.Key{"ChangedSetting"},
			wantUnchanged: []pkey.Key{"UnchangedSetting"},
		},
		{
			name: "StringSlice-Settings",
			old: map[pkey.Key]setting.RawItem{
				"ChangedSetting":   setting.RawItemOf([]string{"Chicago"}),
				"UnchangedSetting": setting.RawItemOf([]string{"String1", "String2"}),
			},
			new: map[pkey.Key]setting.RawItem{
				"ChangedSetting":   setting.RawItemOf([]string{"New York"}),
				"UnchangedSetting": setting.RawItemOf([]string{"String1", "String2"}),
			},
			wantChanged:   []pkey.Key{"ChangedSetting"},
			wantUnchanged: []pkey.Key{"UnchangedSetting"},
		},
		{
			name: "Int8-Settings", // We don't have actual int8 settings, but this should still work.
			old: map[pkey.Key]setting.RawItem{
				"ChangedSetting":   setting.RawItemOf(int8(0)),
				"UnchangedSetting": setting.RawItemOf(int8(42)),
			},
			new: map[pkey.Key]setting.RawItem{
				"ChangedSetting":   setting.RawItemOf(int8(1)),
				"UnchangedSetting": setting.RawItemOf(int8(42)),
			},
			wantChanged:   []pkey.Key{"ChangedSetting"},
			wantUnchanged: []pkey.Key{"UnchangedSetting"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := setting.NewSnapshot(tt.old)
			new := setting.NewSnapshot(tt.new)
			change := PolicyChange{Change[*setting.Snapshot]{old, new}}
			for _, wantChanged := range tt.wantChanged {
				if !change.HasChanged(wantChanged) {
					t.Errorf("%q changed: got false; want true", wantChanged)
				}
			}
			for _, wantUnchanged := range tt.wantUnchanged {
				if change.HasChanged(wantUnchanged) {
					t.Errorf("%q unchanged: got true; want false", wantUnchanged)
				}
			}
		})
	}
}

func TestChangePolicySetting(t *testing.T) {
	// Register policy settings used in this test.
	settingA := setting.NewDefinition("TestSettingA", setting.DeviceSetting, setting.StringValue)
	settingB := setting.NewDefinition("TestSettingB", setting.DeviceSetting, setting.StringValue)
	if err := setting.SetDefinitionsForTest(t, settingA, settingB); err != nil {
		t.Fatalf("SetDefinitionsForTest failed: %v", err)
	}

	// Register a test policy store and create a effective policy that reads the policy settings from it.
	store := source.NewTestStoreOf[string](t)
	if _, err := RegisterStoreForTest(t, "TestSource", setting.DeviceScope, store); err != nil {
		t.Fatalf("Failed to register policy store: %v", err)
	}

	setForTest(t, &policyReloadMinDelay, 100*time.Millisecond)
	setForTest(t, &policyReloadMaxDelay, 500*time.Millisecond)

	policy, err := policyForTest(t, setting.DeviceScope)
	if err != nil {
		t.Fatalf("Failed to get effective policy: %v", err)
	}

	// The policy setting is not configured yet.
	if _, ok := policy.Get().GetSetting(settingA.Key()); ok {
		t.Fatalf("Policy setting %q unexpectedly exists", settingA.Key())
	}

	// Subscribe to the policy change callback...
	policyChanged := make(chan policyclient.PolicyChange)
	unregister := policy.RegisterChangeCallback(func(pc policyclient.PolicyChange) { policyChanged <- pc })
	t.Cleanup(unregister)

	// ...make the change, and measure the time between initiating the change
	// and receiving the callback.
	start := time.Now()
	const wantValueA = "TestValueA"
	store.SetStrings(source.TestSettingOf(settingA.Key(), wantValueA))
	change := (<-policyChanged).(*PolicyChange)
	gotDelay := time.Since(start)

	// Ensure there is at least a [policyReloadMinDelay] delay between
	// a change and the policy reload along with the callback invocation.
	// This prevents reloading policy settings too frequently
	// when multiple settings change within a short period of time.
	if gotDelay < policyReloadMinDelay {
		t.Errorf("Delay: got %v; want >= %v", gotDelay, policyReloadMinDelay)
	}

	// Verify that the [PolicyChange] passed to the policy change callback
	// contains the correct information regarding the policy setting changes.
	if !change.HasChanged(settingA.Key()) {
		t.Errorf("Policy setting %q has not changed", settingA.Key())
	}
	if change.HasChanged(settingB.Key()) {
		t.Errorf("Policy setting %q was unexpectedly changed", settingB.Key())
	}
	if _, ok := change.Old().GetSetting(settingA.Key()); ok {
		t.Fatalf("Policy setting %q unexpectedly exists", settingA.Key())
	}
	if gotValue := change.New().Get(settingA.Key()); gotValue != wantValueA {
		t.Errorf("Policy setting %q: got %q; want %q", settingA.Key(), gotValue, wantValueA)
	}

	// And also verify that the current (most recent) [setting.Snapshot]
	// includes the change we just made.
	if gotValue := policy.Get().Get(settingA.Key()); gotValue != wantValueA {
		t.Errorf("Policy setting %q: got %q; want %q", settingA.Key(), gotValue, wantValueA)
	}

	// Now, let's change another policy setting value N times.
	const N = 10
	wantValueB := strconv.Itoa(N)
	start = time.Now()
	for i := range N {
		store.SetStrings(source.TestSettingOf(settingB.Key(), strconv.Itoa(i+1)))
	}

	// The callback should be invoked only once, even though the policy setting
	// has changed N times.
	change = (<-policyChanged).(*PolicyChange)
	gotDelay = time.Since(start)
	gotCallbacks := 1
drain:
	for {
		select {
		case <-policyChanged:
			gotCallbacks++
		case <-time.After(policyReloadMaxDelay):
			break drain
		}
	}
	if wantCallbacks := 1; gotCallbacks > wantCallbacks {
		t.Errorf("Callbacks: got %d; want %d", gotCallbacks, wantCallbacks)
	}

	// Additionally, the policy change callback should be received no sooner
	// than [policyReloadMinDelay] and no later than [policyReloadMaxDelay].
	if gotDelay < policyReloadMinDelay || gotDelay > policyReloadMaxDelay {
		t.Errorf("Delay: got %v; want >= %v && <= %v", gotDelay, policyReloadMinDelay, policyReloadMaxDelay)
	}

	// Verify that the [PolicyChange] received via the callback
	// contains the final policy setting value.
	if !change.HasChanged(settingB.Key()) {
		t.Errorf("Policy setting %q has not changed", settingB.Key())
	}
	if change.HasChanged(settingA.Key()) {
		t.Errorf("Policy setting %q was unexpectedly changed", settingA.Key())
	}
	if _, ok := change.Old().GetSetting(settingB.Key()); ok {
		t.Fatalf("Policy setting %q unexpectedly exists", settingB.Key())
	}
	if gotValue := change.New().Get(settingB.Key()); gotValue != wantValueB {
		t.Errorf("Policy setting %q: got %q; want %q", settingB.Key(), gotValue, wantValueB)
	}

	// Lastly, if a policy store issues a change notification, but the effective policy
	// remains unchanged, the [Policy] should ignore it without invoking the change callbacks.
	store.NotifyPolicyChanged()
	select {
	case <-policyChanged:
		t.Fatal("Unexpected policy changed notification")
	case <-time.After(policyReloadMaxDelay):
	}
}

func TestClosePolicySource(t *testing.T) {
	testSetting := setting.NewDefinition("TestSetting", setting.DeviceSetting, setting.StringValue)
	if err := setting.SetDefinitionsForTest(t, testSetting); err != nil {
		t.Fatalf("SetDefinitionsForTest failed: %v", err)
	}

	wantSettingValue := "TestValue"
	store := source.NewTestStoreOf(t, source.TestSettingOf(testSetting.Key(), wantSettingValue))
	if _, err := RegisterStoreForTest(t, "TestSource", setting.DeviceScope, store); err != nil {
		t.Fatalf("Failed to register policy store: %v", err)
	}
	policy, err := policyForTest(t, setting.DeviceScope)
	if err != nil {
		t.Fatalf("Failed to get effective policy: %v", err)
	}

	initialSnapshot, err := policy.Reload()
	if err != nil {
		t.Fatalf("Failed to reload policy: %v", err)
	}
	if gotSettingValue, err := initialSnapshot.GetErr(testSetting.Key()); err != nil {
		t.Fatalf("Failed to get %q setting value: %v", testSetting.Key(), err)
	} else if gotSettingValue != wantSettingValue {
		t.Fatalf("Setting %q: got %q; want %q", testSetting.Key(), gotSettingValue, wantSettingValue)
	}

	store.Close()

	// Closing a policy source abruptly without removing it first should invalidate and close the policy.
	<-policy.Done()
	if policy.IsValid() {
		t.Fatal("The policy was not properly closed")
	}

	// The resulting policy snapshot should remain valid and unchanged.
	finalSnapshot := policy.Get()
	if !finalSnapshot.Equal(initialSnapshot) {
		t.Fatal("Policy snapshot has changed")
	}
	if gotSettingValue, err := finalSnapshot.GetErr(testSetting.Key()); err != nil {
		t.Fatalf("Failed to get final %q setting value: %v", testSetting.Key(), err)
	} else if gotSettingValue != wantSettingValue {
		t.Fatalf("Setting %q: got %q; want %q", testSetting.Key(), gotSettingValue, wantSettingValue)
	}

	// However, any further requests to reload the policy should fail.
	if _, err := policy.Reload(); err == nil || !errors.Is(err, ErrPolicyClosed) {
		t.Fatalf("Reload: gotErr: %v; wantErr: %v", err, ErrPolicyClosed)
	}
}

func TestRemovePolicySource(t *testing.T) {
	// Register policy settings used in this test.
	settingA := setting.NewDefinition("TestSettingA", setting.DeviceSetting, setting.StringValue)
	settingB := setting.NewDefinition("TestSettingB", setting.DeviceSetting, setting.StringValue)
	if err := setting.SetDefinitionsForTest(t, settingA, settingB); err != nil {
		t.Fatalf("SetDefinitionsForTest failed: %v", err)
	}

	// Register two policy stores.
	storeA := source.NewTestStoreOf(t, source.TestSettingOf(settingA.Key(), "A"))
	storeRegA, err := RegisterStoreForTest(t, "TestSourceA", setting.DeviceScope, storeA)
	if err != nil {
		t.Fatalf("Failed to register policy store A: %v", err)
	}
	storeB := source.NewTestStoreOf(t, source.TestSettingOf(settingB.Key(), "B"))
	storeRegB, err := RegisterStoreForTest(t, "TestSourceB", setting.DeviceScope, storeB)
	if err != nil {
		t.Fatalf("Failed to register policy store A: %v", err)
	}

	// Create a effective [Policy] that reads policy settings from the two stores.
	policy, err := policyForTest(t, setting.DeviceScope)
	if err != nil {
		t.Fatalf("Failed to get effective policy: %v", err)
	}

	// Verify that the [Policy] uses both stores and includes policy settings from each.
	if gotSources, wantSources := len(policy.sources), 2; gotSources != wantSources {
		t.Fatalf("Policy Sources: got %v; want %v", gotSources, wantSources)
	}
	if got, want := policy.Get().Get(settingA.Key()), "A"; got != want {
		t.Fatalf("Setting %q: got %q; want %q", settingA.Key(), got, want)
	}
	if got, want := policy.Get().Get(settingB.Key()), "B"; got != want {
		t.Fatalf("Setting %q: got %q; want %q", settingB.Key(), got, want)
	}

	// Unregister Store A and verify that the effective policy remains valid.
	// It should no longer use the removed store or include any policy settings from it.
	if err := storeRegA.Unregister(); err != nil {
		t.Fatalf("Failed to unregister Store A: %v", err)
	}
	if !policy.IsValid() {
		t.Fatalf("Policy was unexpectedly closed")
	}
	if gotSources, wantSources := len(policy.sources), 1; gotSources != wantSources {
		t.Fatalf("Policy Sources: got %v; want %v", gotSources, wantSources)
	}
	if got, want := policy.Get().Get(settingA.Key()), any(nil); got != want {
		t.Fatalf("Setting %q: got %q; want %q", settingA.Key(), got, want)
	}
	if got, want := policy.Get().Get(settingB.Key()), "B"; got != want {
		t.Fatalf("Setting %q: got %q; want %q", settingB.Key(), got, want)
	}

	// Unregister Store B and verify that the effective policy is still valid.
	// However, it should be empty since there are no associated policy sources.
	if err := storeRegB.Unregister(); err != nil {
		t.Fatalf("Failed to unregister Store B: %v", err)
	}
	if !policy.IsValid() {
		t.Fatalf("Policy was unexpectedly closed")
	}
	if gotSources, wantSources := len(policy.sources), 0; gotSources != wantSources {
		t.Fatalf("Policy Sources: got %v; want %v", gotSources, wantSources)
	}
	if got := policy.Get(); got.Len() != 0 {
		t.Fatalf("Settings: got %v; want {Empty}", got)
	}
}

func TestReplacePolicySource(t *testing.T) {
	setForTest(t, &policyReloadMinDelay, 100*time.Millisecond)
	setForTest(t, &policyReloadMaxDelay, 500*time.Millisecond)

	// Register policy settings used in this test.
	testSetting := setting.NewDefinition("TestSettingA", setting.DeviceSetting, setting.StringValue)
	if err := setting.SetDefinitionsForTest(t, testSetting); err != nil {
		t.Fatalf("SetDefinitionsForTest failed: %v", err)
	}

	// Create two policy stores.
	initialStore := source.NewTestStoreOf(t, source.TestSettingOf(testSetting.Key(), "InitialValue"))
	newStore := source.NewTestStoreOf(t, source.TestSettingOf(testSetting.Key(), "NewValue"))
	unchangedStore := source.NewTestStoreOf(t, source.TestSettingOf(testSetting.Key(), "NewValue"))

	// Register the initial store and create a effective [Policy] that reads policy settings from it.
	reg, err := RegisterStoreForTest(t, "TestStore", setting.DeviceScope, initialStore)
	if err != nil {
		t.Fatalf("Failed to register the initial store: %v", err)
	}
	policy, err := policyForTest(t, setting.DeviceScope)
	if err != nil {
		t.Fatalf("Failed to get effective policy: %v", err)
	}

	// Verify that the test setting has its initial value.
	if got, want := policy.Get().Get(testSetting.Key()), "InitialValue"; got != want {
		t.Fatalf("Setting %q: got %q; want %q", testSetting.Key(), got, want)
	}

	// Subscribe to the policy change callback.
	policyChanged := make(chan policyclient.PolicyChange, 1)
	unregister := policy.RegisterChangeCallback(func(pc policyclient.PolicyChange) { policyChanged <- pc })
	t.Cleanup(unregister)

	// Now, let's replace the initial store with the new store.
	reg, err = reg.ReplaceStore(newStore)
	if err != nil {
		t.Fatalf("Failed to replace the policy store: %v", err)
	}
	t.Cleanup(func() { reg.Unregister() })

	// We should receive a policy change notification as the setting value has changed.
	<-policyChanged

	// Verify that the test setting has the new value.
	if got, want := policy.Get().Get(testSetting.Key()), "NewValue"; got != want {
		t.Fatalf("Setting %q: got %q; want %q", testSetting.Key(), got, want)
	}

	// Replacing a policy store with an identical one containing the same
	// values for the same settings should not be considered a policy change.
	reg, err = reg.ReplaceStore(unchangedStore)
	if err != nil {
		t.Fatalf("Failed to replace the policy store: %v", err)
	}
	t.Cleanup(func() { reg.Unregister() })

	select {
	case <-policyChanged:
		t.Fatal("Unexpected policy changed notification")
	default:
		<-time.After(policyReloadMaxDelay)
	}
}

func TestAddClosedPolicySource(t *testing.T) {
	store := source.NewTestStoreOf[string](t)
	if _, err := RegisterStoreForTest(t, "TestSource", setting.DeviceScope, store); err != nil {
		t.Fatalf("Failed to register policy store: %v", err)
	}
	store.Close()

	_, err := policyForTest(t, setting.DeviceScope)
	if err == nil || !errors.Is(err, source.ErrStoreClosed) {
		t.Fatalf("got: %v; want: %v", err, source.ErrStoreClosed)
	}
}

func TestClosePolicyMoreThanOnce(t *testing.T) {
	tests := []struct {
		name       string
		numSources int
	}{
		{
			name:       "NoSources",
			numSources: 0,
		},
		{
			name:       "OneSource",
			numSources: 1,
		},
		{
			name:       "ManySources",
			numSources: 10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.numSources {
				store := source.NewTestStoreOf[string](t)
				if _, err := RegisterStoreForTest(t, "TestSource #"+strconv.Itoa(i), setting.DeviceScope, store); err != nil {
					t.Fatalf("Failed to register policy store: %v", err)
				}
			}

			policy, err := policyForTest(t, setting.DeviceScope)
			if err != nil {
				t.Fatalf("failed to get effective policy: %v", err)
			}

			const N = 10000
			var wg sync.WaitGroup
			for range N {
				wg.Add(1)
				go func() {
					wg.Done()
					policy.Close()
					<-policy.Done()
				}()
			}
			wg.Wait()
		})
	}
}

func checkPolicySources(tb testing.TB, gotPolicy *Policy, wantSources []*source.Source) {
	tb.Helper()
	sort.SliceStable(wantSources, func(i, j int) bool {
		return wantSources[i].Compare(wantSources[j]) < 0
	})
	gotSources := make([]*source.Source, len(gotPolicy.sources))
	for i := range gotPolicy.sources {
		gotSources[i] = gotPolicy.sources[i].Source
	}
	type sourceSummary struct{ Name, Scope string }
	toSourceSummary := cmp.Transformer("source", func(s *source.Source) sourceSummary { return sourceSummary{s.Name(), s.Scope().String()} })
	if diff := cmp.Diff(wantSources, gotSources, toSourceSummary, cmpopts.EquateEmpty()); diff != "" {
		tb.Errorf("Policy Sources mismatch: %v", diff)
	}
}

// policyForTest is like [PolicyFor], but it deletes the policy
// when tb and all its subtests complete.
func policyForTest(tb testing.TB, target setting.PolicyScope) (*Policy, error) {
	tb.Helper()

	policy, err := PolicyFor(target)
	if err != nil {
		return nil, err
	}
	tb.Cleanup(func() {
		policy.Close()
		<-policy.Done()
		deletePolicy(policy)
	})
	return policy, nil
}
