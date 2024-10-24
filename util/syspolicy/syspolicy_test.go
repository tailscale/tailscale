// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"errors"
	"slices"
	"testing"
	"time"

	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/internal/loggerx"
	"tailscale.com/util/syspolicy/internal/metrics"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
)

var someOtherError = errors.New("error other than not found")

func TestGetString(t *testing.T) {
	tests := []struct {
		name         string
		key          Key
		handlerValue string
		handlerError error
		defaultValue string
		wantValue    string
		wantError    error
		wantMetrics  []metrics.TestState
	}{
		{
			name:         "read existing value",
			key:          AdminConsoleVisibility,
			handlerValue: "hide",
			wantValue:    "hide",
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AdminConsole", Value: 1},
			},
		},
		{
			name:         "read non-existing value",
			key:          EnableServerMode,
			handlerError: ErrNotConfigured,
			wantError:    nil,
		},
		{
			name:         "read non-existing value, non-blank default",
			key:          EnableServerMode,
			handlerError: ErrNotConfigured,
			defaultValue: "test",
			wantValue:    "test",
			wantError:    nil,
		},
		{
			name:         "reading value returns other error",
			key:          NetworkDevicesVisibility,
			handlerError: someOtherError,
			wantError:    someOtherError,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_errors", Value: 1},
				{Name: "$os_syspolicy_NetworkDevices_error", Value: 1},
			},
		},
	}

	RegisterWellKnownSettingsForTest(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := metrics.NewTestHandler(t)
			metrics.SetHooksForTest(t, h.AddMetric, h.SetMetric)

			s := source.TestSetting[string]{
				Key:   tt.key,
				Value: tt.handlerValue,
				Error: tt.handlerError,
			}
			registerSingleSettingStoreForTest(t, s)

			value, err := GetString(tt.key, tt.defaultValue)
			if !errorsMatchForTest(err, tt.wantError) {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if value != tt.wantValue {
				t.Errorf("value=%v, want %v", value, tt.wantValue)
			}
			wantMetrics := tt.wantMetrics
			if !metrics.ShouldReport() {
				// Check that metrics are not reported on platforms
				// where they shouldn't be reported.
				// As of 2024-09-04, syspolicy only reports metrics
				// on Windows and Android.
				wantMetrics = nil
			}
			h.MustEqual(wantMetrics...)
		})
	}
}

func TestGetUint64(t *testing.T) {
	tests := []struct {
		name         string
		key          Key
		handlerValue uint64
		handlerError error
		defaultValue uint64
		wantValue    uint64
		wantError    error
	}{
		{
			name:         "read existing value",
			key:          LogSCMInteractions,
			handlerValue: 1,
			wantValue:    1,
		},
		{
			name:         "read non-existing value",
			key:          LogSCMInteractions,
			handlerValue: 0,
			handlerError: ErrNotConfigured,
			wantValue:    0,
		},
		{
			name:         "read non-existing value, non-zero default",
			key:          LogSCMInteractions,
			defaultValue: 2,
			handlerError: ErrNotConfigured,
			wantValue:    2,
		},
		{
			name:         "reading value returns other error",
			key:          FlushDNSOnSessionUnlock,
			handlerError: someOtherError,
			wantError:    someOtherError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// None of the policy settings tested here are integers.
			// In fact, we don't have any integer policies as of 2024-10-08.
			// However, we can register each of them as an integer policy setting
			// for the duration of the test, providing us with something to test against.
			if err := setting.SetDefinitionsForTest(t, setting.NewDefinition(tt.key, setting.DeviceSetting, setting.IntegerValue)); err != nil {
				t.Fatalf("SetDefinitionsForTest failed: %v", err)
			}

			s := source.TestSetting[uint64]{
				Key:   tt.key,
				Value: tt.handlerValue,
				Error: tt.handlerError,
			}
			registerSingleSettingStoreForTest(t, s)

			value, err := GetUint64(tt.key, tt.defaultValue)
			if !errorsMatchForTest(err, tt.wantError) {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if value != tt.wantValue {
				t.Errorf("value=%v, want %v", value, tt.wantValue)
			}
		})
	}
}

func TestGetBoolean(t *testing.T) {
	tests := []struct {
		name         string
		key          Key
		handlerValue bool
		handlerError error
		defaultValue bool
		wantValue    bool
		wantError    error
		wantMetrics  []metrics.TestState
	}{
		{
			name:         "read existing value",
			key:          FlushDNSOnSessionUnlock,
			handlerValue: true,
			wantValue:    true,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_FlushDNSOnSessionUnlock", Value: 1},
			},
		},
		{
			name:         "read non-existing value",
			key:          LogSCMInteractions,
			handlerValue: false,
			handlerError: ErrNotConfigured,
			wantValue:    false,
		},
		{
			name:         "reading value returns other error",
			key:          FlushDNSOnSessionUnlock,
			handlerError: someOtherError,
			wantError:    someOtherError, // expect error...
			defaultValue: true,
			wantValue:    true, // ...AND default value if the handler fails.
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_errors", Value: 1},
				{Name: "$os_syspolicy_FlushDNSOnSessionUnlock_error", Value: 1},
			},
		},
	}

	RegisterWellKnownSettingsForTest(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := metrics.NewTestHandler(t)
			metrics.SetHooksForTest(t, h.AddMetric, h.SetMetric)

			s := source.TestSetting[bool]{
				Key:   tt.key,
				Value: tt.handlerValue,
				Error: tt.handlerError,
			}
			registerSingleSettingStoreForTest(t, s)

			value, err := GetBoolean(tt.key, tt.defaultValue)
			if !errorsMatchForTest(err, tt.wantError) {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if value != tt.wantValue {
				t.Errorf("value=%v, want %v", value, tt.wantValue)
			}
			wantMetrics := tt.wantMetrics
			if !metrics.ShouldReport() {
				// Check that metrics are not reported on platforms
				// where they shouldn't be reported.
				// As of 2024-09-04, syspolicy only reports metrics
				// on Windows and Android.
				wantMetrics = nil
			}
			h.MustEqual(wantMetrics...)
		})
	}
}

func TestGetPreferenceOption(t *testing.T) {
	tests := []struct {
		name         string
		key          Key
		handlerValue string
		handlerError error
		wantValue    setting.PreferenceOption
		wantError    error
		wantMetrics  []metrics.TestState
	}{
		{
			name:         "always by policy",
			key:          EnableIncomingConnections,
			handlerValue: "always",
			wantValue:    setting.AlwaysByPolicy,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AllowIncomingConnections", Value: 1},
			},
		},
		{
			name:         "never by policy",
			key:          EnableIncomingConnections,
			handlerValue: "never",
			wantValue:    setting.NeverByPolicy,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AllowIncomingConnections", Value: 1},
			},
		},
		{
			name:         "use default",
			key:          EnableIncomingConnections,
			handlerValue: "",
			wantValue:    setting.ShowChoiceByPolicy,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AllowIncomingConnections", Value: 1},
			},
		},
		{
			name:         "read non-existing value",
			key:          EnableIncomingConnections,
			handlerError: ErrNotConfigured,
			wantValue:    setting.ShowChoiceByPolicy,
		},
		{
			name:         "other error is returned",
			key:          EnableIncomingConnections,
			handlerError: someOtherError,
			wantValue:    setting.ShowChoiceByPolicy,
			wantError:    someOtherError,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_errors", Value: 1},
				{Name: "$os_syspolicy_AllowIncomingConnections_error", Value: 1},
			},
		},
	}

	RegisterWellKnownSettingsForTest(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := metrics.NewTestHandler(t)
			metrics.SetHooksForTest(t, h.AddMetric, h.SetMetric)

			s := source.TestSetting[string]{
				Key:   tt.key,
				Value: tt.handlerValue,
				Error: tt.handlerError,
			}
			registerSingleSettingStoreForTest(t, s)

			option, err := GetPreferenceOption(tt.key)
			if !errorsMatchForTest(err, tt.wantError) {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if option != tt.wantValue {
				t.Errorf("option=%v, want %v", option, tt.wantValue)
			}
			wantMetrics := tt.wantMetrics
			if !metrics.ShouldReport() {
				// Check that metrics are not reported on platforms
				// where they shouldn't be reported.
				// As of 2024-09-04, syspolicy only reports metrics
				// on Windows and Android.
				wantMetrics = nil
			}
			h.MustEqual(wantMetrics...)
		})
	}
}

func TestGetVisibility(t *testing.T) {
	tests := []struct {
		name         string
		key          Key
		handlerValue string
		handlerError error
		wantValue    setting.Visibility
		wantError    error
		wantMetrics  []metrics.TestState
	}{
		{
			name:         "hidden by policy",
			key:          AdminConsoleVisibility,
			handlerValue: "hide",
			wantValue:    setting.HiddenByPolicy,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AdminConsole", Value: 1},
			},
		},
		{
			name:         "visibility default",
			key:          AdminConsoleVisibility,
			handlerValue: "show",
			wantValue:    setting.VisibleByPolicy,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AdminConsole", Value: 1},
			},
		},
		{
			name:         "read non-existing value",
			key:          AdminConsoleVisibility,
			handlerValue: "show",
			handlerError: ErrNotConfigured,
			wantValue:    setting.VisibleByPolicy,
		},
		{
			name:         "other error is returned",
			key:          AdminConsoleVisibility,
			handlerValue: "show",
			handlerError: someOtherError,
			wantValue:    setting.VisibleByPolicy,
			wantError:    someOtherError,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_errors", Value: 1},
				{Name: "$os_syspolicy_AdminConsole_error", Value: 1},
			},
		},
	}

	RegisterWellKnownSettingsForTest(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := metrics.NewTestHandler(t)
			metrics.SetHooksForTest(t, h.AddMetric, h.SetMetric)

			s := source.TestSetting[string]{
				Key:   tt.key,
				Value: tt.handlerValue,
				Error: tt.handlerError,
			}
			registerSingleSettingStoreForTest(t, s)

			visibility, err := GetVisibility(tt.key)
			if !errorsMatchForTest(err, tt.wantError) {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if visibility != tt.wantValue {
				t.Errorf("visibility=%v, want %v", visibility, tt.wantValue)
			}
			wantMetrics := tt.wantMetrics
			if !metrics.ShouldReport() {
				// Check that metrics are not reported on platforms
				// where they shouldn't be reported.
				// As of 2024-09-04, syspolicy only reports metrics
				// on Windows and Android.
				wantMetrics = nil
			}
			h.MustEqual(wantMetrics...)
		})
	}
}

func TestGetDuration(t *testing.T) {
	tests := []struct {
		name         string
		key          Key
		handlerValue string
		handlerError error
		defaultValue time.Duration
		wantValue    time.Duration
		wantError    error
		wantMetrics  []metrics.TestState
	}{
		{
			name:         "read existing value",
			key:          KeyExpirationNoticeTime,
			handlerValue: "2h",
			wantValue:    2 * time.Hour,
			defaultValue: 24 * time.Hour,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_KeyExpirationNotice", Value: 1},
			},
		},
		{
			name:         "invalid duration value",
			key:          KeyExpirationNoticeTime,
			handlerValue: "-20",
			wantValue:    24 * time.Hour,
			wantError:    errors.New(`time: missing unit in duration "-20"`),
			defaultValue: 24 * time.Hour,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_errors", Value: 1},
				{Name: "$os_syspolicy_KeyExpirationNotice_error", Value: 1},
			},
		},
		{
			name:         "read non-existing value",
			key:          KeyExpirationNoticeTime,
			handlerError: ErrNotConfigured,
			wantValue:    24 * time.Hour,
			defaultValue: 24 * time.Hour,
		},
		{
			name:         "read non-existing value different default",
			key:          KeyExpirationNoticeTime,
			handlerError: ErrNotConfigured,
			wantValue:    0 * time.Second,
			defaultValue: 0 * time.Second,
		},
		{
			name:         "other error is returned",
			key:          KeyExpirationNoticeTime,
			handlerError: someOtherError,
			wantValue:    24 * time.Hour,
			wantError:    someOtherError,
			defaultValue: 24 * time.Hour,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_errors", Value: 1},
				{Name: "$os_syspolicy_KeyExpirationNotice_error", Value: 1},
			},
		},
	}

	RegisterWellKnownSettingsForTest(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := metrics.NewTestHandler(t)
			metrics.SetHooksForTest(t, h.AddMetric, h.SetMetric)

			s := source.TestSetting[string]{
				Key:   tt.key,
				Value: tt.handlerValue,
				Error: tt.handlerError,
			}
			registerSingleSettingStoreForTest(t, s)

			duration, err := GetDuration(tt.key, tt.defaultValue)
			if !errorsMatchForTest(err, tt.wantError) {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if duration != tt.wantValue {
				t.Errorf("duration=%v, want %v", duration, tt.wantValue)
			}
			wantMetrics := tt.wantMetrics
			if !metrics.ShouldReport() {
				// Check that metrics are not reported on platforms
				// where they shouldn't be reported.
				// As of 2024-09-04, syspolicy only reports metrics
				// on Windows and Android.
				wantMetrics = nil
			}
			h.MustEqual(wantMetrics...)
		})
	}
}

func TestGetStringArray(t *testing.T) {
	tests := []struct {
		name         string
		key          Key
		handlerValue []string
		handlerError error
		defaultValue []string
		wantValue    []string
		wantError    error
		wantMetrics  []metrics.TestState
	}{
		{
			name:         "read existing value",
			key:          AllowedSuggestedExitNodes,
			handlerValue: []string{"foo", "bar"},
			wantValue:    []string{"foo", "bar"},
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AllowedSuggestedExitNodes", Value: 1},
			},
		},
		{
			name:         "read non-existing value",
			key:          AllowedSuggestedExitNodes,
			handlerError: ErrNotConfigured,
			wantError:    nil,
		},
		{
			name:         "read non-existing value, non nil default",
			key:          AllowedSuggestedExitNodes,
			handlerError: ErrNotConfigured,
			defaultValue: []string{"foo", "bar"},
			wantValue:    []string{"foo", "bar"},
			wantError:    nil,
		},
		{
			name:         "reading value returns other error",
			key:          AllowedSuggestedExitNodes,
			handlerError: someOtherError,
			wantError:    someOtherError,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_errors", Value: 1},
				{Name: "$os_syspolicy_AllowedSuggestedExitNodes_error", Value: 1},
			},
		},
	}

	RegisterWellKnownSettingsForTest(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := metrics.NewTestHandler(t)
			metrics.SetHooksForTest(t, h.AddMetric, h.SetMetric)

			s := source.TestSetting[[]string]{
				Key:   tt.key,
				Value: tt.handlerValue,
				Error: tt.handlerError,
			}
			registerSingleSettingStoreForTest(t, s)

			value, err := GetStringArray(tt.key, tt.defaultValue)
			if !errorsMatchForTest(err, tt.wantError) {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if !slices.Equal(tt.wantValue, value) {
				t.Errorf("value=%v, want %v", value, tt.wantValue)
			}
			wantMetrics := tt.wantMetrics
			if !metrics.ShouldReport() {
				// Check that metrics are not reported on platforms
				// where they shouldn't be reported.
				// As of 2024-09-04, syspolicy only reports metrics
				// on Windows and Android.
				wantMetrics = nil
			}
			h.MustEqual(wantMetrics...)
		})
	}
}

func registerSingleSettingStoreForTest[T source.TestValueType](tb TB, s source.TestSetting[T]) {
	policyStore := source.NewTestStoreOf(tb, s)
	MustRegisterStoreForTest(tb, "TestStore", setting.DeviceScope, policyStore)
}

func BenchmarkGetString(b *testing.B) {
	loggerx.SetForTest(b, logger.Discard, logger.Discard)
	RegisterWellKnownSettingsForTest(b)

	wantControlURL := "https://login.tailscale.com"
	registerSingleSettingStoreForTest(b, source.TestSettingOf(ControlURL, wantControlURL))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gotControlURL, _ := GetString(ControlURL, "https://controlplane.tailscale.com")
		if gotControlURL != wantControlURL {
			b.Fatalf("got %v; want %v", gotControlURL, wantControlURL)
		}
	}
}

func TestSelectControlURL(t *testing.T) {
	tests := []struct {
		reg, disk, want string
	}{
		// Modern default case.
		{"", "", "https://controlplane.tailscale.com"},

		// For a user who installed prior to Dec 2020, with
		// stuff in their registry.
		{"https://login.tailscale.com", "", "https://login.tailscale.com"},

		// Ignore pre-Dec'20 LoginURL from installer if prefs
		// prefs overridden manually to an on-prem control
		// server.
		{"https://login.tailscale.com", "http://on-prem", "http://on-prem"},

		// Something unknown explicitly set in the registry always wins.
		{"http://explicit-reg", "", "http://explicit-reg"},
		{"http://explicit-reg", "http://on-prem", "http://explicit-reg"},
		{"http://explicit-reg", "https://login.tailscale.com", "http://explicit-reg"},
		{"http://explicit-reg", "https://controlplane.tailscale.com", "http://explicit-reg"},

		// If nothing in the registry, disk wins.
		{"", "http://on-prem", "http://on-prem"},
	}
	for _, tt := range tests {
		if got := SelectControlURL(tt.reg, tt.disk); got != tt.want {
			t.Errorf("(reg %q, disk %q) = %q; want %q", tt.reg, tt.disk, got, tt.want)
		}
	}
}

func errorsMatchForTest(got, want error) bool {
	if got == nil && want == nil {
		return true
	}
	if got == nil || want == nil {
		return false
	}
	return errors.Is(got, want) || got.Error() == want.Error()
}
