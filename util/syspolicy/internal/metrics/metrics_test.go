// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package metrics

import (
	"errors"
	"testing"

	"tailscale.com/types/lazy"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/setting"
)

func TestSettingMetricNames(t *testing.T) {
	tests := []struct {
		name           string
		key            setting.Key
		scope          setting.Scope
		suffix         string
		typ            clientmetric.Type
		osOverride     string
		wantMetricName string
	}{
		{
			name:           "windows-device-no-suffix",
			key:            "AdminConsole",
			scope:          setting.DeviceSetting,
			suffix:         "",
			typ:            clientmetric.TypeCounter,
			osOverride:     "windows",
			wantMetricName: "windows_syspolicy_AdminConsole",
		},
		{
			name:           "windows-user-no-suffix",
			key:            "AdminConsole",
			scope:          setting.UserSetting,
			suffix:         "",
			typ:            clientmetric.TypeCounter,
			osOverride:     "windows",
			wantMetricName: "windows_syspolicy_AdminConsole_user",
		},
		{
			name:           "windows-profile-no-suffix",
			key:            "AdminConsole",
			scope:          setting.ProfileSetting,
			suffix:         "",
			typ:            clientmetric.TypeCounter,
			osOverride:     "windows",
			wantMetricName: "windows_syspolicy_AdminConsole_profile",
		},
		{
			name:           "windows-profile-err",
			key:            "AdminConsole",
			scope:          setting.ProfileSetting,
			suffix:         "error",
			typ:            clientmetric.TypeCounter,
			osOverride:     "windows",
			wantMetricName: "windows_syspolicy_AdminConsole_profile_error",
		},
		{
			name:           "android-device-no-suffix",
			key:            "AdminConsole",
			scope:          setting.DeviceSetting,
			suffix:         "",
			typ:            clientmetric.TypeCounter,
			osOverride:     "android",
			wantMetricName: "android_syspolicy_AdminConsole",
		},
		{
			name:           "key-path",
			key:            "category/subcategory/setting",
			scope:          setting.DeviceSetting,
			suffix:         "",
			typ:            clientmetric.TypeCounter,
			osOverride:     "fakeos",
			wantMetricName: "fakeos_syspolicy_category_subcategory_setting",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			internal.OSForTesting.SetForTest(t, tt.osOverride, nil)
			metric, ok := newSettingMetric(tt.key, tt.scope, tt.suffix, tt.typ).(*funcMetric)
			if !ok {
				t.Fatal("metric is not a funcMetric")
			}
			if metric.name != tt.wantMetricName {
				t.Errorf("got %q, want %q", metric.name, tt.wantMetricName)
			}
		})
	}
}

func TestScopeMetrics(t *testing.T) {
	tests := []struct {
		name               string
		scope              setting.Scope
		osOverride         string
		wantHasAnyName     string
		wantNumErroredName string
		wantHasAnyType     clientmetric.Type
		wantNumErroredType clientmetric.Type
	}{
		{
			name:               "windows-device",
			scope:              setting.DeviceSetting,
			osOverride:         "windows",
			wantHasAnyName:     "windows_syspolicy_any",
			wantHasAnyType:     clientmetric.TypeGauge,
			wantNumErroredName: "windows_syspolicy_errors",
			wantNumErroredType: clientmetric.TypeCounter,
		},
		{
			name:               "windows-profile",
			scope:              setting.ProfileSetting,
			osOverride:         "windows",
			wantHasAnyName:     "windows_syspolicy_profile_any",
			wantHasAnyType:     clientmetric.TypeGauge,
			wantNumErroredName: "windows_syspolicy_profile_errors",
			wantNumErroredType: clientmetric.TypeCounter,
		},
		{
			name:               "windows-user",
			scope:              setting.UserSetting,
			osOverride:         "windows",
			wantHasAnyName:     "windows_syspolicy_user_any",
			wantHasAnyType:     clientmetric.TypeGauge,
			wantNumErroredName: "windows_syspolicy_user_errors",
			wantNumErroredType: clientmetric.TypeCounter,
		},
		{
			name:               "android-device",
			scope:              setting.DeviceSetting,
			osOverride:         "android",
			wantHasAnyName:     "android_syspolicy_any",
			wantHasAnyType:     clientmetric.TypeGauge,
			wantNumErroredName: "android_syspolicy_errors",
			wantNumErroredType: clientmetric.TypeCounter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			internal.OSForTesting.SetForTest(t, tt.osOverride, nil)
			metrics := newScopeMetrics(tt.scope)
			hasAny, ok := metrics.hasAny.(*funcMetric)
			if !ok {
				t.Fatal("hasAny is not a funcMetric")
			}
			numErrored, ok := metrics.numErrored.(*funcMetric)
			if !ok {
				t.Fatal("numErrored is not a funcMetric")
			}
			if hasAny.name != tt.wantHasAnyName {
				t.Errorf("hasAny.Name: got %q, want %q", hasAny.name, tt.wantHasAnyName)
			}
			if hasAny.typ != tt.wantHasAnyType {
				t.Errorf("hasAny.Type: got %q, want %q", hasAny.typ, tt.wantHasAnyType)
			}
			if numErrored.name != tt.wantNumErroredName {
				t.Errorf("numErrored.Name: got %q, want %q", numErrored.name, tt.wantNumErroredName)
			}
			if numErrored.typ != tt.wantNumErroredType {
				t.Errorf("hasAny.Type: got %q, want %q", numErrored.typ, tt.wantNumErroredType)
			}
		})
	}
}

type testSettingDetails struct {
	definition *setting.Definition
	origin     *setting.Origin
	value      any
	err        error
}

func TestReportMetrics(t *testing.T) {
	tests := []struct {
		name             string
		osOverride       string
		useMetrics       bool
		settings         []testSettingDetails
		wantMetrics      []TestState
		wantResetMetrics []TestState
	}{
		{
			name:        "none",
			osOverride:  "windows",
			settings:    []testSettingDetails{},
			wantMetrics: []TestState{},
		},
		{
			name:       "single-value",
			osOverride: "windows",
			settings: []testSettingDetails{
				{
					definition: setting.NewDefinition("TestSetting01", setting.DeviceSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.DeviceScope),
					value:      42,
				},
			},
			wantMetrics: []TestState{
				{"windows_syspolicy_any", 1},
				{"windows_syspolicy_TestSetting01", 1},
			},
			wantResetMetrics: []TestState{
				{"windows_syspolicy_any", 0},
				{"windows_syspolicy_TestSetting01", 0},
			},
		},
		{
			name:       "single-error",
			osOverride: "windows",
			settings: []testSettingDetails{
				{
					definition: setting.NewDefinition("TestSetting02", setting.DeviceSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.DeviceScope),
					err:        errors.New("bang!"),
				},
			},
			wantMetrics: []TestState{
				{"windows_syspolicy_errors", 1},
				{"windows_syspolicy_TestSetting02_error", 1},
			},
			wantResetMetrics: []TestState{
				{"windows_syspolicy_errors", 1},
				{"windows_syspolicy_TestSetting02_error", 0},
			},
		},
		{
			name:       "value-and-error",
			osOverride: "windows",
			settings: []testSettingDetails{
				{
					definition: setting.NewDefinition("TestSetting01", setting.DeviceSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.DeviceScope),
					value:      42,
				},
				{
					definition: setting.NewDefinition("TestSetting02", setting.DeviceSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.DeviceScope),
					err:        errors.New("bang!"),
				},
			},

			wantMetrics: []TestState{
				{"windows_syspolicy_any", 1},
				{"windows_syspolicy_errors", 1},
				{"windows_syspolicy_TestSetting01", 1},
				{"windows_syspolicy_TestSetting02_error", 1},
			},
			wantResetMetrics: []TestState{
				{"windows_syspolicy_any", 0},
				{"windows_syspolicy_errors", 1},
				{"windows_syspolicy_TestSetting01", 0},
				{"windows_syspolicy_TestSetting02_error", 0},
			},
		},
		{
			name:       "two-values",
			osOverride: "windows",
			settings: []testSettingDetails{
				{
					definition: setting.NewDefinition("TestSetting01", setting.DeviceSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.DeviceScope),
					value:      42,
				},
				{
					definition: setting.NewDefinition("TestSetting02", setting.DeviceSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.DeviceScope),
					value:      17,
				},
			},
			wantMetrics: []TestState{
				{"windows_syspolicy_any", 1},
				{"windows_syspolicy_TestSetting01", 1},
				{"windows_syspolicy_TestSetting02", 1},
			},
			wantResetMetrics: []TestState{
				{"windows_syspolicy_any", 0},
				{"windows_syspolicy_TestSetting01", 0},
				{"windows_syspolicy_TestSetting02", 0},
			},
		},
		{
			name:       "two-errors",
			osOverride: "windows",
			settings: []testSettingDetails{
				{
					definition: setting.NewDefinition("TestSetting01", setting.DeviceSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.DeviceScope),
					err:        errors.New("bang!"),
				},
				{
					definition: setting.NewDefinition("TestSetting02", setting.DeviceSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.DeviceScope),
					err:        errors.New("bang!"),
				},
			},
			wantMetrics: []TestState{
				{"windows_syspolicy_errors", 2},
				{"windows_syspolicy_TestSetting01_error", 1},
				{"windows_syspolicy_TestSetting02_error", 1},
			},
			wantResetMetrics: []TestState{
				{"windows_syspolicy_errors", 2},
				{"windows_syspolicy_TestSetting01_error", 0},
				{"windows_syspolicy_TestSetting02_error", 0},
			},
		},
		{
			name:       "multi-scope",
			osOverride: "windows",
			settings: []testSettingDetails{
				{
					definition: setting.NewDefinition("TestSetting01", setting.ProfileSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.DeviceScope),
					value:      42,
				},
				{
					definition: setting.NewDefinition("TestSetting02", setting.ProfileSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.CurrentProfileScope),
					err:        errors.New("bang!"),
				},
				{
					definition: setting.NewDefinition("TestSetting03", setting.UserSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.CurrentUserScope),
					value:      17,
				},
			},
			wantMetrics: []TestState{
				{"windows_syspolicy_any", 1},
				{"windows_syspolicy_profile_errors", 1},
				{"windows_syspolicy_user_any", 1},
				{"windows_syspolicy_TestSetting01", 1},
				{"windows_syspolicy_TestSetting02_profile_error", 1},
				{"windows_syspolicy_TestSetting03_user", 1},
			},
			wantResetMetrics: []TestState{
				{"windows_syspolicy_any", 0},
				{"windows_syspolicy_profile_errors", 1},
				{"windows_syspolicy_user_any", 0},
				{"windows_syspolicy_TestSetting01", 0},
				{"windows_syspolicy_TestSetting02_profile_error", 0},
				{"windows_syspolicy_TestSetting03_user", 0},
			},
		},
		{
			name:       "report-metrics-on-android",
			osOverride: "android",
			settings: []testSettingDetails{
				{
					definition: setting.NewDefinition("TestSetting01", setting.DeviceSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.DeviceScope),
					value:      42,
				},
			},
			wantMetrics: []TestState{
				{"android_syspolicy_any", 1},
				{"android_syspolicy_TestSetting01", 1},
			},
			wantResetMetrics: []TestState{
				{"android_syspolicy_any", 0},
				{"android_syspolicy_TestSetting01", 0},
			},
		},
		{
			name:       "do-not-report-metrics-on-macos",
			osOverride: "macos",
			settings: []testSettingDetails{
				{
					definition: setting.NewDefinition("TestSetting01", setting.DeviceSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.DeviceScope),
					value:      42,
				},
			},

			wantMetrics: []TestState{}, // none reported
		},
		{
			name:       "do-not-report-metrics-on-ios",
			osOverride: "ios",
			settings: []testSettingDetails{
				{
					definition: setting.NewDefinition("TestSetting01", setting.DeviceSetting, setting.IntegerValue),
					origin:     setting.NewOrigin(setting.DeviceScope),
					value:      42,
				},
			},

			wantMetrics: []TestState{}, // none reported
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset the lazy value so it'll be re-evaluated with the osOverride.
			lazyReportMetrics = lazy.SyncValue[bool]{}
			t.Cleanup(func() {
				// Also reset it during the cleanup.
				lazyReportMetrics = lazy.SyncValue[bool]{}
			})
			internal.OSForTesting.SetForTest(t, tt.osOverride, nil)

			h := NewTestHandler(t)
			SetHooksForTest(t, h.AddMetric, h.SetMetric)

			for _, s := range tt.settings {
				if s.err != nil {
					ReportError(s.origin, s.definition, s.err)
				} else {
					ReportConfigured(s.origin, s.definition, s.value)
				}
			}
			h.MustEqual(tt.wantMetrics...)

			for _, s := range tt.settings {
				Reset(s.origin)
				ReportNotConfigured(s.origin, s.definition)
			}
			h.MustEqual(tt.wantResetMetrics...)
		})
	}
}
