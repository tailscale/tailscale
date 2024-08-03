// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package rsop

import (
	"slices"
	"sort"
	"testing"

	"tailscale.com/util/syspolicy/setting"

	"tailscale.com/util/syspolicy/source"
)

func TestRegisterSourceAndGetResultantPolicy(t *testing.T) {
	type sourceConfig struct {
		name          string
		scope         setting.PolicyScope
		settingKey    setting.Key
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
			wantSnapshot: setting.NewSnapshot(map[setting.Key]setting.RawItem{
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
			wantSnapshot: setting.NewSnapshot(map[setting.Key]setting.RawItem{
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
			wantSnapshot: setting.NewSnapshot(map[setting.Key]setting.RawItem{
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
			wantSnapshot: setting.NewSnapshot(map[setting.Key]setting.RawItem{
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
			wantSnapshot: setting.NewSnapshot(map[setting.Key]setting.RawItem{
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
			wantSnapshot: setting.NewSnapshot(map[setting.Key]setting.RawItem{
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
			wantSnapshot: setting.NewSnapshot(map[setting.Key]setting.RawItem{
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
			wantSnapshot: setting.NewSnapshot(map[setting.Key]setting.RawItem{
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
			wantSnapshot: setting.NewSnapshot(map[setting.Key]setting.RawItem{
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
					t.Fatalf("failed to register policy source: %v", source)
				}
				if s.wantEffective {
					wantSources = append(wantSources, source)
				}
				t.Cleanup(func() { unregisterSource(source) })
			}

			// Retrieve the resultant policy.
			policy, err := resultantPolicyForTest(t, tt.scope)
			if err != nil {
				t.Fatalf("failed to get resultant policy for %v", tt.scope)
			}

			// Add additional setting sources one by one, and check the policy settings at each step.
			for _, s := range tt.additionalSources {
				store := source.NewTestStoreOf(t, source.TestSettingOf(s.settingKey, s.settingValue))
				source := source.NewSource(s.name, s.scope, store)
				if err := registerSource(source); err != nil {
					t.Fatalf("failed to register additional policy source: %v", source)
				}
				if s.wantEffective {
					wantSources = append(wantSources, source)
				}
				t.Cleanup(func() { unregisterSource(source) })
			}

			sort.SliceStable(wantSources, func(i, j int) bool {
				return wantSources[i].Compare(wantSources[j]) < 0
			})
			gotSources := make([]*source.Source, len(policy.sources))
			for i, s := range policy.sources {
				gotSources[i] = s.Source
			}
			if !slices.Equal(gotSources, wantSources) {
				t.Errorf("Sources: got %v; want %v", gotSources, wantSources)
			}

			// Verify the final resultant settings snapshots.
			if got := policy.Get(); !got.Equal(tt.wantSnapshot) {
				t.Errorf("Snapshot: got %v; want %v", got, tt.wantSnapshot)
			}
		})
	}
}

// resultantPolicyForTest is like [resultantPolicyFor], but it deletes the policy
// when tb and all its subtests complete.
func resultantPolicyForTest(tb testing.TB, target setting.PolicyScope) (*Policy, error) {
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
