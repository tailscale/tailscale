// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"errors"
	"slices"
	"testing"
	"time"

	"tailscale.com/util/syspolicy/setting"
)

// testHandler encompasses all data types returned when testing any of the syspolicy
// methods that involve getting a policy value.
// For keys and the corresponding values, check policy_keys.go.
type testHandler struct {
	t     *testing.T
	key   Key
	s     string
	u64   uint64
	b     bool
	sArr  []string
	err   error
	calls int // used for testing reads from cache vs. handler
}

var someOtherError = errors.New("error other than not found")

func (th *testHandler) ReadString(key string) (string, error) {
	if key != string(th.key) {
		th.t.Errorf("ReadString(%q) want %q", key, th.key)
	}
	th.calls++
	return th.s, th.err
}

func (th *testHandler) ReadUInt64(key string) (uint64, error) {
	if key != string(th.key) {
		th.t.Errorf("ReadUint64(%q) want %q", key, th.key)
	}
	th.calls++
	return th.u64, th.err
}

func (th *testHandler) ReadBoolean(key string) (bool, error) {
	if key != string(th.key) {
		th.t.Errorf("ReadBool(%q) want %q", key, th.key)
	}
	th.calls++
	return th.b, th.err
}

func (th *testHandler) ReadStringArray(key string) ([]string, error) {
	if key != string(th.key) {
		th.t.Errorf("ReadStringArray(%q) want %q", key, th.key)
	}
	th.calls++
	return th.sArr, th.err
}

func TestGetString(t *testing.T) {
	tests := []struct {
		name         string
		key          Key
		handlerValue string
		handlerError error
		defaultValue string
		wantValue    string
		wantError    error
	}{
		{
			name:         "read existing value",
			key:          AdminConsoleVisibility,
			handlerValue: "hide",
			wantValue:    "hide",
		},
		{
			name:         "read non-existing value",
			key:          EnableServerMode,
			handlerError: ErrNoSuchKey,
			wantError:    nil,
		},
		{
			name:         "read non-existing value, non-blank default",
			key:          EnableServerMode,
			handlerError: ErrNoSuchKey,
			defaultValue: "test",
			wantValue:    "test",
			wantError:    nil,
		},
		{
			name:         "reading value returns other error",
			key:          NetworkDevicesVisibility,
			handlerError: someOtherError,
			wantError:    someOtherError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetHandlerForTest(t, &testHandler{
				t:   t,
				key: tt.key,
				s:   tt.handlerValue,
				err: tt.handlerError,
			})
			value, err := GetString(tt.key, tt.defaultValue)
			if err != tt.wantError {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if value != tt.wantValue {
				t.Errorf("value=%v, want %v", value, tt.wantValue)
			}
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
			key:          KeyExpirationNoticeTime,
			handlerValue: 1,
			wantValue:    1,
		},
		{
			name:         "read non-existing value",
			key:          LogSCMInteractions,
			handlerValue: 0,
			handlerError: ErrNoSuchKey,
			wantValue:    0,
		},
		{
			name:         "read non-existing value, non-zero default",
			key:          LogSCMInteractions,
			defaultValue: 2,
			handlerError: ErrNoSuchKey,
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
			SetHandlerForTest(t, &testHandler{
				t:   t,
				key: tt.key,
				u64: tt.handlerValue,
				err: tt.handlerError,
			})
			value, err := GetUint64(tt.key, tt.defaultValue)
			if err != tt.wantError {
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
	}{
		{
			name:         "read existing value",
			key:          FlushDNSOnSessionUnlock,
			handlerValue: true,
			wantValue:    true,
		},
		{
			name:         "read non-existing value",
			key:          LogSCMInteractions,
			handlerValue: false,
			handlerError: ErrNoSuchKey,
			wantValue:    false,
		},
		{
			name:         "reading value returns other error",
			key:          FlushDNSOnSessionUnlock,
			handlerError: someOtherError,
			wantError:    someOtherError,
			defaultValue: true,
			wantValue:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetHandlerForTest(t, &testHandler{
				t:   t,
				key: tt.key,
				b:   tt.handlerValue,
				err: tt.handlerError,
			})
			value, err := GetBoolean(tt.key, tt.defaultValue)
			if err != tt.wantError {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if value != tt.wantValue {
				t.Errorf("value=%v, want %v", value, tt.wantValue)
			}
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
	}{
		{
			name:         "always by policy",
			key:          EnableIncomingConnections,
			handlerValue: "always",
			wantValue:    setting.AlwaysByPolicy,
		},
		{
			name:         "never by policy",
			key:          EnableIncomingConnections,
			handlerValue: "never",
			wantValue:    setting.NeverByPolicy,
		},
		{
			name:         "use default",
			key:          EnableIncomingConnections,
			handlerValue: "",
			wantValue:    setting.ShowChoiceByPolicy,
		},
		{
			name:         "read non-existing value",
			key:          EnableIncomingConnections,
			handlerError: ErrNoSuchKey,
			wantValue:    setting.ShowChoiceByPolicy,
		},
		{
			name:         "other error is returned",
			key:          EnableIncomingConnections,
			handlerError: someOtherError,
			wantValue:    setting.ShowChoiceByPolicy,
			wantError:    someOtherError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetHandlerForTest(t, &testHandler{
				t:   t,
				key: tt.key,
				s:   tt.handlerValue,
				err: tt.handlerError,
			})
			option, err := GetPreferenceOption(tt.key)
			if err != tt.wantError {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if option != tt.wantValue {
				t.Errorf("option=%v, want %v", option, tt.wantValue)
			}
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
	}{
		{
			name:         "hidden by policy",
			key:          AdminConsoleVisibility,
			handlerValue: "hide",
			wantValue:    setting.HiddenByPolicy,
		},
		{
			name:         "visibility default",
			key:          AdminConsoleVisibility,
			handlerValue: "show",
			wantValue:    setting.VisibleByPolicy,
		},
		{
			name:         "read non-existing value",
			key:          AdminConsoleVisibility,
			handlerValue: "show",
			handlerError: ErrNoSuchKey,
			wantValue:    setting.VisibleByPolicy,
		},
		{
			name:         "other error is returned",
			key:          AdminConsoleVisibility,
			handlerValue: "show",
			handlerError: someOtherError,
			wantValue:    setting.VisibleByPolicy,
			wantError:    someOtherError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetHandlerForTest(t, &testHandler{
				t:   t,
				key: tt.key,
				s:   tt.handlerValue,
				err: tt.handlerError,
			})
			visibility, err := GetVisibility(tt.key)
			if err != tt.wantError {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if visibility != tt.wantValue {
				t.Errorf("visibility=%v, want %v", visibility, tt.wantValue)
			}
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
	}{
		{
			name:         "read existing value",
			key:          KeyExpirationNoticeTime,
			handlerValue: "2h",
			wantValue:    2 * time.Hour,
			defaultValue: 24 * time.Hour,
		},
		{
			name:         "invalid duration value",
			key:          KeyExpirationNoticeTime,
			handlerValue: "-20",
			wantValue:    24 * time.Hour,
			defaultValue: 24 * time.Hour,
		},
		{
			name:         "read non-existing value",
			key:          KeyExpirationNoticeTime,
			handlerError: ErrNoSuchKey,
			wantValue:    24 * time.Hour,
			defaultValue: 24 * time.Hour,
		},
		{
			name:         "read non-existing value different default",
			key:          KeyExpirationNoticeTime,
			handlerError: ErrNoSuchKey,
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetHandlerForTest(t, &testHandler{
				t:   t,
				key: tt.key,
				s:   tt.handlerValue,
				err: tt.handlerError,
			})
			duration, err := GetDuration(tt.key, tt.defaultValue)
			if err != tt.wantError {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if duration != tt.wantValue {
				t.Errorf("duration=%v, want %v", duration, tt.wantValue)
			}
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
	}{
		{
			name:         "read existing value",
			key:          AllowedSuggestedExitNodes,
			handlerValue: []string{"foo", "bar"},
			wantValue:    []string{"foo", "bar"},
		},
		{
			name:         "read non-existing value",
			key:          AllowedSuggestedExitNodes,
			handlerError: ErrNoSuchKey,
			wantError:    nil,
		},
		{
			name:         "read non-existing value, non nil default",
			key:          AllowedSuggestedExitNodes,
			handlerError: ErrNoSuchKey,
			defaultValue: []string{"foo", "bar"},
			wantValue:    []string{"foo", "bar"},
			wantError:    nil,
		},
		{
			name:         "reading value returns other error",
			key:          AllowedSuggestedExitNodes,
			handlerError: someOtherError,
			wantError:    someOtherError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetHandlerForTest(t, &testHandler{
				t:    t,
				key:  tt.key,
				sArr: tt.handlerValue,
				err:  tt.handlerError,
			})
			value, err := GetStringArray(tt.key, tt.defaultValue)
			if err != tt.wantError {
				t.Errorf("err=%q, want %q", err, tt.wantError)
			}
			if !slices.Equal(tt.wantValue, value) {
				t.Errorf("value=%v, want %v", value, tt.wantValue)
			}
		})
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
