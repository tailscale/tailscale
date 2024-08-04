// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import (
	"reflect"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"
)

func TestPolicyScopeIsApplicableSetting(t *testing.T) {
	tests := []struct {
		name           string
		scope          PolicyScope
		setting        *Definition
		wantApplicable bool
	}{
		{
			name:           "DeviceScope/DeviceSetting",
			scope:          DeviceScope,
			setting:        NewDefinition("TestSetting", DeviceSetting, IntegerValue),
			wantApplicable: true,
		},
		{
			name:           "DeviceScope/ProfileSetting",
			scope:          DeviceScope,
			setting:        NewDefinition("TestSetting", ProfileSetting, IntegerValue),
			wantApplicable: false,
		},
		{
			name:           "DeviceScope/UserSetting",
			scope:          DeviceScope,
			setting:        NewDefinition("TestSetting", UserSetting, IntegerValue),
			wantApplicable: false,
		},
		{
			name:           "ProfileScope/DeviceSetting",
			scope:          CurrentProfileScope,
			setting:        NewDefinition("TestSetting", DeviceSetting, IntegerValue),
			wantApplicable: true,
		},
		{
			name:           "ProfileScope/ProfileSetting",
			scope:          CurrentProfileScope,
			setting:        NewDefinition("TestSetting", ProfileSetting, IntegerValue),
			wantApplicable: true,
		},
		{
			name:           "ProfileScope/UserSetting",
			scope:          CurrentProfileScope,
			setting:        NewDefinition("TestSetting", UserSetting, IntegerValue),
			wantApplicable: false,
		},
		{
			name:           "UserScope/DeviceSetting",
			scope:          CurrentUserScope,
			setting:        NewDefinition("TestSetting", DeviceSetting, IntegerValue),
			wantApplicable: true,
		},
		{
			name:           "UserScope/ProfileSetting",
			scope:          CurrentUserScope,
			setting:        NewDefinition("TestSetting", ProfileSetting, IntegerValue),
			wantApplicable: true,
		},
		{
			name:           "UserScope/UserSetting",
			scope:          CurrentUserScope,
			setting:        NewDefinition("TestSetting", UserSetting, IntegerValue),
			wantApplicable: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotApplicable := tt.scope.IsApplicableSetting(tt.setting)
			if gotApplicable != tt.wantApplicable {
				t.Fatalf("got %v, want %v", gotApplicable, tt.wantApplicable)
			}
		})
	}
}

func TestPolicyScopeIsConfigurableSetting(t *testing.T) {
	tests := []struct {
		name             string
		scope            PolicyScope
		setting          *Definition
		wantConfigurable bool
	}{
		{
			name:             "DeviceScope/DeviceSetting",
			scope:            DeviceScope,
			setting:          NewDefinition("TestSetting", DeviceSetting, IntegerValue),
			wantConfigurable: true,
		},
		{
			name:             "DeviceScope/ProfileSetting",
			scope:            DeviceScope,
			setting:          NewDefinition("TestSetting", ProfileSetting, IntegerValue),
			wantConfigurable: true,
		},
		{
			name:             "DeviceScope/UserSetting",
			scope:            DeviceScope,
			setting:          NewDefinition("TestSetting", UserSetting, IntegerValue),
			wantConfigurable: true,
		},
		{
			name:             "ProfileScope/DeviceSetting",
			scope:            CurrentProfileScope,
			setting:          NewDefinition("TestSetting", DeviceSetting, IntegerValue),
			wantConfigurable: false,
		},
		{
			name:             "ProfileScope/ProfileSetting",
			scope:            CurrentProfileScope,
			setting:          NewDefinition("TestSetting", ProfileSetting, IntegerValue),
			wantConfigurable: true,
		},
		{
			name:             "ProfileScope/UserSetting",
			scope:            CurrentProfileScope,
			setting:          NewDefinition("TestSetting", UserSetting, IntegerValue),
			wantConfigurable: true,
		},
		{
			name:             "UserScope/DeviceSetting",
			scope:            CurrentUserScope,
			setting:          NewDefinition("TestSetting", DeviceSetting, IntegerValue),
			wantConfigurable: false,
		},
		{
			name:             "UserScope/ProfileSetting",
			scope:            CurrentUserScope,
			setting:          NewDefinition("TestSetting", ProfileSetting, IntegerValue),
			wantConfigurable: false,
		},
		{
			name:             "UserScope/UserSetting",
			scope:            CurrentUserScope,
			setting:          NewDefinition("TestSetting", UserSetting, IntegerValue),
			wantConfigurable: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotConfigurable := tt.scope.IsConfigurableSetting(tt.setting)
			if gotConfigurable != tt.wantConfigurable {
				t.Fatalf("got %v, want %v", gotConfigurable, tt.wantConfigurable)
			}
		})
	}
}

func TestPolicyScopeContains(t *testing.T) {
	tests := []struct {
		name                   string
		scopeA                 PolicyScope
		scopeB                 PolicyScope
		wantAContainsB         bool
		wantAStrictlyContainsB bool
	}{
		{
			name:                   "DeviceScope/DeviceScope",
			scopeA:                 DeviceScope,
			scopeB:                 DeviceScope,
			wantAContainsB:         true,
			wantAStrictlyContainsB: false,
		},
		{
			name:                   "DeviceScope/CurrentProfileScope",
			scopeA:                 DeviceScope,
			scopeB:                 CurrentProfileScope,
			wantAContainsB:         true,
			wantAStrictlyContainsB: true,
		},
		{
			name:                   "DeviceScope/UserScope",
			scopeA:                 DeviceScope,
			scopeB:                 CurrentUserScope,
			wantAContainsB:         true,
			wantAStrictlyContainsB: true,
		},
		{
			name:                   "ProfileScope/DeviceScope",
			scopeA:                 CurrentProfileScope,
			scopeB:                 DeviceScope,
			wantAContainsB:         false,
			wantAStrictlyContainsB: false,
		},
		{
			name:                   "ProfileScope/ProfileScope",
			scopeA:                 CurrentProfileScope,
			scopeB:                 CurrentProfileScope,
			wantAContainsB:         true,
			wantAStrictlyContainsB: false,
		},
		{
			name:                   "ProfileScope/UserScope",
			scopeA:                 CurrentProfileScope,
			scopeB:                 CurrentUserScope,
			wantAContainsB:         true,
			wantAStrictlyContainsB: true,
		},
		{
			name:                   "UserScope/DeviceScope",
			scopeA:                 CurrentUserScope,
			scopeB:                 DeviceScope,
			wantAContainsB:         false,
			wantAStrictlyContainsB: false,
		},
		{
			name:                   "UserScope/ProfileScope",
			scopeA:                 CurrentUserScope,
			scopeB:                 CurrentProfileScope,
			wantAContainsB:         false,
			wantAStrictlyContainsB: false,
		},
		{
			name:                   "UserScope/UserScope",
			scopeA:                 CurrentUserScope,
			scopeB:                 CurrentUserScope,
			wantAContainsB:         true,
			wantAStrictlyContainsB: false,
		},
		{
			name:                   "UserScope(1234)/UserScope(1234)",
			scopeA:                 UserScopeOf("1234"),
			scopeB:                 UserScopeOf("1234"),
			wantAContainsB:         true,
			wantAStrictlyContainsB: false,
		},
		{
			name:                   "UserScope(1234)/UserScope(5678)",
			scopeA:                 UserScopeOf("1234"),
			scopeB:                 UserScopeOf("5678"),
			wantAContainsB:         false,
			wantAStrictlyContainsB: false,
		},
		{
			name:                   "ProfileScope(A)/UserScope(A/1234)",
			scopeA:                 PolicyScope{kind: ProfileSetting, profileID: "A"},
			scopeB:                 PolicyScope{kind: UserSetting, userID: "1234", profileID: "A"},
			wantAContainsB:         true,
			wantAStrictlyContainsB: true,
		},
		{
			name:                   "ProfileScope(A)/UserScope(B/1234)",
			scopeA:                 PolicyScope{kind: ProfileSetting, profileID: "A"},
			scopeB:                 PolicyScope{kind: UserSetting, userID: "1234", profileID: "B"},
			wantAContainsB:         false,
			wantAStrictlyContainsB: false,
		},
		{
			name:                   "UserScope(1234)/UserScope(A/1234)",
			scopeA:                 PolicyScope{kind: UserSetting, userID: "1234"},
			scopeB:                 PolicyScope{kind: UserSetting, userID: "1234", profileID: "A"},
			wantAContainsB:         true,
			wantAStrictlyContainsB: true,
		},
		{
			name:                   "UserScope(1234)/UserScope(A/5678)",
			scopeA:                 PolicyScope{kind: UserSetting, userID: "1234"},
			scopeB:                 PolicyScope{kind: UserSetting, userID: "5678", profileID: "A"},
			wantAContainsB:         false,
			wantAStrictlyContainsB: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotContains := tt.scopeA.Contains(tt.scopeB)
			if gotContains != tt.wantAContainsB {
				t.Fatalf("WithinOf: got %v, want %v", gotContains, tt.wantAContainsB)
			}

			gotStrictlyContains := tt.scopeA.StrictlyContains(tt.scopeB)
			if gotStrictlyContains != tt.wantAStrictlyContainsB {
				t.Fatalf("StrictlyWithinOf: got %v, want %v", gotStrictlyContains, tt.wantAStrictlyContainsB)
			}
		})
	}
}

func TestPolicyScopeMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name      string
		in        any
		wantJSON  string
		wantError bool
	}{
		{
			name: "null-scope",
			in: &struct {
				Scope PolicyScope
			}{},
			wantJSON: `{"Scope":"Device"}`,
		},
		{
			name: "null-scope-omit-zero",
			in: &struct {
				Scope PolicyScope `json:",omitzero"`
			}{},
			wantJSON: `{}`,
		},
		{
			name: "device-scope",
			in: &struct {
				Scope PolicyScope
			}{DeviceScope},
			wantJSON: `{"Scope":"Device"}`,
		},
		{
			name: "current-profile-scope",
			in: &struct {
				Scope PolicyScope
			}{CurrentProfileScope},
			wantJSON: `{"Scope":"Profile"}`,
		},
		{
			name: "current-user-scope",
			in: &struct {
				Scope PolicyScope
			}{CurrentUserScope},
			wantJSON: `{"Scope":"User"}`,
		},
		{
			name: "specific-user-scope",
			in: &struct {
				Scope PolicyScope
			}{UserScopeOf("_")},
			wantJSON: `{"Scope":"User(_)"}`,
		},
		{
			name: "specific-user-scope",
			in: &struct {
				Scope PolicyScope
			}{UserScopeOf("S-1-5-21-3698941153-1525015703-2649197413-1001")},
			wantJSON: `{"Scope":"User(S-1-5-21-3698941153-1525015703-2649197413-1001)"}`,
		},
		{
			name: "specific-profile-scope",
			in: &struct {
				Scope PolicyScope
			}{PolicyScope{kind: ProfileSetting, profileID: "1234"}},
			wantJSON: `{"Scope":"Profile(1234)"}`,
		},
		{
			name: "specific-profile-and-user-scope",
			in: &struct {
				Scope PolicyScope
			}{PolicyScope{
				kind:      UserSetting,
				profileID: "1234",
				userID:    "S-1-5-21-3698941153-1525015703-2649197413-1001",
			}},
			wantJSON: `{"Scope":"Profile(1234)/User(S-1-5-21-3698941153-1525015703-2649197413-1001)"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotJSON, err := jsonv2.Marshal(tt.in)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if string(gotJSON) != tt.wantJSON {
				t.Fatalf("Marshal got %s, want %s", gotJSON, tt.wantJSON)
			}
			wantBack := tt.in
			gotBack := reflect.New(reflect.TypeOf(tt.in).Elem()).Interface()
			err = jsonv2.Unmarshal(gotJSON, gotBack)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if !reflect.DeepEqual(gotBack, wantBack) {
				t.Fatalf("Unmarshal got %+v, want %+v", gotBack, wantBack)
			}
		})
	}
}

func TestPolicyScopeUnmarshalSpecial(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		want      any
		wantError bool
	}{
		{
			name: "empty",
			json: "{}",
			want: &struct {
				Scope PolicyScope
			}{},
		},
		{
			name:      "too-many-scopes",
			json:      `{"Scope":"Device/Profile/User"}`,
			wantError: true,
		},
		{
			name:      "user/profile", // incorrect order
			json:      `{"Scope":"User/Profile"}`,
			wantError: true,
		},
		{
			name: "profile-user-no-params",
			json: `{"Scope":"Profile/User"}`,
			want: &struct {
				Scope PolicyScope
			}{CurrentUserScope},
		},
		{
			name:      "unknown-scope",
			json:      `{"Scope":"Unknown"}`,
			wantError: true,
		},
		{
			name:      "unknown-scope/unknown-scope",
			json:      `{"Scope":"Unknown/Unknown"}`,
			wantError: true,
		},
		{
			name:      "device-scope/unknown-scope",
			json:      `{"Scope":"Device/Unknown"}`,
			wantError: true,
		},
		{
			name:      "unknown-scope/device-scope",
			json:      `{"Scope":"Unknown/Device"}`,
			wantError: true,
		},
		{
			name:      "slash",
			json:      `{"Scope":"/"}`,
			wantError: true,
		},
		{
			name:      "empty",
			json:      `{"Scope": ""`,
			wantError: true,
		},
		{
			name:      "no-closing-bracket",
			json:      `{"Scope": "user(1234"`,
			wantError: true,
		},
		{
			name:      "device-with-id",
			json:      `{"Scope": "device(123)"`,
			wantError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &struct {
				Scope PolicyScope
			}{}
			err := jsonv2.Unmarshal([]byte(tt.json), got)
			if (err != nil) != tt.wantError {
				t.Errorf("Marshal error: got %v, want %v", err, tt.wantError)
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Unmarshal got %+v, want %+v", got, tt.want)
			}
		})
	}

}

func TestExtractScopeAndParams(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		scope  string
		params string
		wantOk bool
	}{
		{
			name:   "empty",
			s:      "",
			wantOk: true,
		},
		{
			name:   "scope-only",
			s:      "device",
			scope:  "device",
			wantOk: true,
		},
		{
			name:   "scope-with-params",
			s:      "user(1234)",
			scope:  "user",
			params: "1234",
			wantOk: true,
		},
		{
			name:   "params-empty-scope",
			s:      "(1234)",
			scope:  "",
			params: "1234",
			wantOk: true,
		},
		{
			name:   "params-with-brackets",
			s:      "test()())))())",
			scope:  "test",
			params: ")())))()",
			wantOk: true,
		},
		{
			name:   "no-closing-bracket",
			s:      "user(1234",
			scope:  "",
			params: "",
			wantOk: false,
		},
		{
			name:   "open-before-close",
			s:      ")user(1234",
			scope:  "",
			params: "",
			wantOk: false,
		},
		{
			name:   "brackets-only",
			s:      ")(",
			scope:  "",
			params: "",
			wantOk: false,
		},
		{
			name:   "closing-bracket",
			s:      ")",
			scope:  "",
			params: "",
			wantOk: false,
		},
		{
			name:   "opening-bracket",
			s:      ")",
			scope:  "",
			params: "",
			wantOk: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, params, ok := extractScopeAndParams(tt.s)
			if ok != tt.wantOk {
				t.Logf("OK: got %v; want %v", ok, tt.wantOk)
			}
			if scope != tt.scope {
				t.Logf("Scope: got %q; want %q", scope, tt.scope)
			}
			if params != tt.params {
				t.Logf("Params: got %v; want %v", params, tt.params)
			}
		})
	}
}
