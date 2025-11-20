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
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
	"tailscale.com/util/testenv"
)

var someOtherError = errors.New("error other than not found")

// registerWellKnownSettingsForTest registers all implicit setting definitions
// for the duration of the test.
func registerWellKnownSettingsForTest(tb testenv.TB) {
	tb.Helper()
	err := setting.SetDefinitionsForTest(tb, implicitDefinitions...)
	if err != nil {
		tb.Fatalf("Failed to register well-known settings: %v", err)
	}
}

func TestGetString(t *testing.T) {
	tests := []struct {
		name         string
		key          pkey.Key
		handlerValue string
		handlerError error
		defaultValue string
		wantValue    string
		wantError    error
		wantMetrics  []metrics.TestState
	}{
		{
			name:         "read existing value",
			key:          pkey.AdminConsoleVisibility,
			handlerValue: "hide",
			wantValue:    "hide",
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AdminConsole", Value: 1},
			},
		},
		{
			name:         "read non-existing value",
			key:          pkey.EnableServerMode,
			handlerError: ErrNotConfigured,
			wantError:    nil,
		},
		{
			name:         "read non-existing value, non-blank default",
			key:          pkey.EnableServerMode,
			handlerError: ErrNotConfigured,
			defaultValue: "test",
			wantValue:    "test",
			wantError:    nil,
		},
		{
			name:         "reading value returns other error",
			key:          pkey.NetworkDevicesVisibility,
			handlerError: someOtherError,
			wantError:    someOtherError,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_errors", Value: 1},
				{Name: "$os_syspolicy_NetworkDevices_error", Value: 1},
			},
		},
	}

	registerWellKnownSettingsForTest(t)

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

			value, err := getString(tt.key, tt.defaultValue)
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
		key          pkey.Key
		handlerValue uint64
		handlerError error
		defaultValue uint64
		wantValue    uint64
		wantError    error
	}{
		{
			name:         "read existing value",
			key:          pkey.LogSCMInteractions,
			handlerValue: 1,
			wantValue:    1,
		},
		{
			name:         "read non-existing value",
			key:          pkey.LogSCMInteractions,
			handlerValue: 0,
			handlerError: ErrNotConfigured,
			wantValue:    0,
		},
		{
			name:         "read non-existing value, non-zero default",
			key:          pkey.LogSCMInteractions,
			defaultValue: 2,
			handlerError: ErrNotConfigured,
			wantValue:    2,
		},
		{
			name:         "reading value returns other error",
			key:          pkey.FlushDNSOnSessionUnlock,
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

			value, err := getUint64(tt.key, tt.defaultValue)
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
		key          pkey.Key
		handlerValue bool
		handlerError error
		defaultValue bool
		wantValue    bool
		wantError    error
		wantMetrics  []metrics.TestState
	}{
		{
			name:         "read existing value",
			key:          pkey.FlushDNSOnSessionUnlock,
			handlerValue: true,
			wantValue:    true,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_FlushDNSOnSessionUnlock", Value: 1},
			},
		},
		{
			name:         "read non-existing value",
			key:          pkey.LogSCMInteractions,
			handlerValue: false,
			handlerError: ErrNotConfigured,
			wantValue:    false,
		},
		{
			name:         "reading value returns other error",
			key:          pkey.FlushDNSOnSessionUnlock,
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

	registerWellKnownSettingsForTest(t)

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

			value, err := getBoolean(tt.key, tt.defaultValue)
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
		key          pkey.Key
		handlerValue string
		handlerError error
		wantValue    ptype.PreferenceOption
		wantError    error
		wantMetrics  []metrics.TestState
	}{
		{
			name:         "always by policy",
			key:          pkey.EnableIncomingConnections,
			handlerValue: "always",
			wantValue:    ptype.AlwaysByPolicy,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AllowIncomingConnections", Value: 1},
			},
		},
		{
			name:         "never by policy",
			key:          pkey.EnableIncomingConnections,
			handlerValue: "never",
			wantValue:    ptype.NeverByPolicy,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AllowIncomingConnections", Value: 1},
			},
		},
		{
			name:         "use default",
			key:          pkey.EnableIncomingConnections,
			handlerValue: "",
			wantValue:    ptype.ShowChoiceByPolicy,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AllowIncomingConnections", Value: 1},
			},
		},
		{
			name:         "read non-existing value",
			key:          pkey.EnableIncomingConnections,
			handlerError: ErrNotConfigured,
			wantValue:    ptype.ShowChoiceByPolicy,
		},
		{
			name:         "other error is returned",
			key:          pkey.EnableIncomingConnections,
			handlerError: someOtherError,
			wantValue:    ptype.ShowChoiceByPolicy,
			wantError:    someOtherError,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_errors", Value: 1},
				{Name: "$os_syspolicy_AllowIncomingConnections_error", Value: 1},
			},
		},
	}

	registerWellKnownSettingsForTest(t)

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

			option, err := getPreferenceOption(tt.key, ptype.ShowChoiceByPolicy)
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
		key          pkey.Key
		handlerValue string
		handlerError error
		wantValue    ptype.Visibility
		wantError    error
		wantMetrics  []metrics.TestState
	}{
		{
			name:         "hidden by policy",
			key:          pkey.AdminConsoleVisibility,
			handlerValue: "hide",
			wantValue:    ptype.HiddenByPolicy,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AdminConsole", Value: 1},
			},
		},
		{
			name:         "visibility default",
			key:          pkey.AdminConsoleVisibility,
			handlerValue: "show",
			wantValue:    ptype.VisibleByPolicy,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AdminConsole", Value: 1},
			},
		},
		{
			name:         "read non-existing value",
			key:          pkey.AdminConsoleVisibility,
			handlerValue: "show",
			handlerError: ErrNotConfigured,
			wantValue:    ptype.VisibleByPolicy,
		},
		{
			name:         "other error is returned",
			key:          pkey.AdminConsoleVisibility,
			handlerValue: "show",
			handlerError: someOtherError,
			wantValue:    ptype.VisibleByPolicy,
			wantError:    someOtherError,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_errors", Value: 1},
				{Name: "$os_syspolicy_AdminConsole_error", Value: 1},
			},
		},
	}

	registerWellKnownSettingsForTest(t)

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

			visibility, err := getVisibility(tt.key)
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
		key          pkey.Key
		handlerValue string
		handlerError error
		defaultValue time.Duration
		wantValue    time.Duration
		wantError    error
		wantMetrics  []metrics.TestState
	}{
		{
			name:         "read existing value",
			key:          pkey.KeyExpirationNoticeTime,
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
			key:          pkey.KeyExpirationNoticeTime,
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
			key:          pkey.KeyExpirationNoticeTime,
			handlerError: ErrNotConfigured,
			wantValue:    24 * time.Hour,
			defaultValue: 24 * time.Hour,
		},
		{
			name:         "read non-existing value different default",
			key:          pkey.KeyExpirationNoticeTime,
			handlerError: ErrNotConfigured,
			wantValue:    0 * time.Second,
			defaultValue: 0 * time.Second,
		},
		{
			name:         "other error is returned",
			key:          pkey.KeyExpirationNoticeTime,
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

	registerWellKnownSettingsForTest(t)

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

			duration, err := getDuration(tt.key, tt.defaultValue)
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
		key          pkey.Key
		handlerValue []string
		handlerError error
		defaultValue []string
		wantValue    []string
		wantError    error
		wantMetrics  []metrics.TestState
	}{
		{
			name:         "read existing value",
			key:          pkey.AllowedSuggestedExitNodes,
			handlerValue: []string{"foo", "bar"},
			wantValue:    []string{"foo", "bar"},
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_any", Value: 1},
				{Name: "$os_syspolicy_AllowedSuggestedExitNodes", Value: 1},
			},
		},
		{
			name:         "read non-existing value",
			key:          pkey.AllowedSuggestedExitNodes,
			handlerError: ErrNotConfigured,
			wantError:    nil,
		},
		{
			name:         "read non-existing value, non nil default",
			key:          pkey.AllowedSuggestedExitNodes,
			handlerError: ErrNotConfigured,
			defaultValue: []string{"foo", "bar"},
			wantValue:    []string{"foo", "bar"},
			wantError:    nil,
		},
		{
			name:         "reading value returns other error",
			key:          pkey.AllowedSuggestedExitNodes,
			handlerError: someOtherError,
			wantError:    someOtherError,
			wantMetrics: []metrics.TestState{
				{Name: "$os_syspolicy_errors", Value: 1},
				{Name: "$os_syspolicy_AllowedSuggestedExitNodes_error", Value: 1},
			},
		},
	}

	registerWellKnownSettingsForTest(t)

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

			value, err := getStringArray(tt.key, tt.defaultValue)
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

// mustRegisterStoreForTest is like [rsop.RegisterStoreForTest], but it fails the test if the store could not be registered.
func mustRegisterStoreForTest(tb testenv.TB, name string, scope setting.PolicyScope, store source.Store) *rsop.StoreRegistration {
	tb.Helper()
	reg, err := rsop.RegisterStoreForTest(tb, name, scope, store)
	if err != nil {
		tb.Fatalf("Failed to register policy store %q as a %v policy source: %v", name, scope, err)
	}
	return reg
}

func registerSingleSettingStoreForTest[T source.TestValueType](tb testenv.TB, s source.TestSetting[T]) {
	policyStore := source.NewTestStoreOf(tb, s)
	mustRegisterStoreForTest(tb, "TestStore", setting.DeviceScope, policyStore)
}

func BenchmarkGetString(b *testing.B) {
	loggerx.SetForTest(b, logger.Discard, logger.Discard)
	registerWellKnownSettingsForTest(b)

	wantControlURL := "https://login.tailscale.com"
	registerSingleSettingStoreForTest(b, source.TestSettingOf(pkey.ControlURL, wantControlURL))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gotControlURL, _ := getString(pkey.ControlURL, "https://controlplane.tailscale.com")
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
