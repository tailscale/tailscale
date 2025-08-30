// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import (
	"slices"
	"strings"
	"testing"

	"tailscale.com/types/lazy"
	"tailscale.com/types/ptr"
	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/pkey"
)

func TestSettingDefinition(t *testing.T) {
	tests := []struct {
		name                   string
		setting                *Definition
		osOverride             string
		wantKey                pkey.Key
		wantScope              Scope
		wantType               Type
		wantIsSupported        bool
		wantSupportedPlatforms PlatformList
		wantString             string
	}{
		{
			name:            "Nil",
			setting:         nil,
			wantKey:         "",
			wantScope:       0,
			wantType:        InvalidValue,
			wantIsSupported: false,
			wantString:      "(nil)",
		},
		{
			name:            "Device/Invalid",
			setting:         NewDefinition("TestDevicePolicySetting", DeviceSetting, InvalidValue),
			wantKey:         "TestDevicePolicySetting",
			wantScope:       DeviceSetting,
			wantType:        InvalidValue,
			wantIsSupported: true,
			wantString:      `Device("TestDevicePolicySetting", Invalid)`,
		},
		{
			name:            "Device/Integer",
			setting:         NewDefinition("TestDevicePolicySetting", DeviceSetting, IntegerValue),
			wantKey:         "TestDevicePolicySetting",
			wantScope:       DeviceSetting,
			wantType:        IntegerValue,
			wantIsSupported: true,
			wantString:      `Device("TestDevicePolicySetting", Integer)`,
		},
		{
			name:            "Profile/String",
			setting:         NewDefinition("TestProfilePolicySetting", ProfileSetting, StringValue),
			wantKey:         "TestProfilePolicySetting",
			wantScope:       ProfileSetting,
			wantType:        StringValue,
			wantIsSupported: true,
			wantString:      `Profile("TestProfilePolicySetting", String)`,
		},
		{
			name:            "Device/StringList",
			setting:         NewDefinition("AllowedSuggestedExitNodes", DeviceSetting, StringListValue),
			wantKey:         "AllowedSuggestedExitNodes",
			wantScope:       DeviceSetting,
			wantType:        StringListValue,
			wantIsSupported: true,
			wantString:      `Device("AllowedSuggestedExitNodes", StringList)`,
		},
		{
			name:            "Device/PreferenceOption",
			setting:         NewDefinition("AdvertiseExitNode", DeviceSetting, PreferenceOptionValue),
			wantKey:         "AdvertiseExitNode",
			wantScope:       DeviceSetting,
			wantType:        PreferenceOptionValue,
			wantIsSupported: true,
			wantString:      `Device("AdvertiseExitNode", PreferenceOption)`,
		},
		{
			name:            "User/Boolean",
			setting:         NewDefinition("TestUserPolicySetting", UserSetting, BooleanValue),
			wantKey:         "TestUserPolicySetting",
			wantScope:       UserSetting,
			wantType:        BooleanValue,
			wantIsSupported: true,
			wantString:      `User("TestUserPolicySetting", Boolean)`,
		},
		{
			name:            "User/Visibility",
			setting:         NewDefinition("AdminConsole", UserSetting, VisibilityValue),
			wantKey:         "AdminConsole",
			wantScope:       UserSetting,
			wantType:        VisibilityValue,
			wantIsSupported: true,
			wantString:      `User("AdminConsole", Visibility)`,
		},
		{
			name:            "User/Duration",
			setting:         NewDefinition("KeyExpirationNotice", UserSetting, DurationValue),
			wantKey:         "KeyExpirationNotice",
			wantScope:       UserSetting,
			wantType:        DurationValue,
			wantIsSupported: true,
			wantString:      `User("KeyExpirationNotice", Duration)`,
		},
		{
			name:                   "SupportedSetting",
			setting:                NewDefinition("DesktopPolicySetting", DeviceSetting, StringValue, "macos", "windows"),
			osOverride:             "windows",
			wantKey:                "DesktopPolicySetting",
			wantScope:              DeviceSetting,
			wantType:               StringValue,
			wantIsSupported:        true,
			wantSupportedPlatforms: PlatformList{"macos", "windows"},
			wantString:             `Device("DesktopPolicySetting", String)`,
		},
		{
			name:                   "UnsupportedSetting",
			setting:                NewDefinition("AndroidPolicySetting", DeviceSetting, StringValue, "android"),
			osOverride:             "macos",
			wantKey:                "AndroidPolicySetting",
			wantScope:              DeviceSetting,
			wantType:               StringValue,
			wantIsSupported:        false,
			wantSupportedPlatforms: PlatformList{"android"},
			wantString:             `Device("AndroidPolicySetting", String)`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.osOverride != "" {
				internal.OSForTesting.SetForTest(t, tt.osOverride, nil)
			}
			if !tt.setting.Equal(tt.setting) {
				t.Errorf("the setting should be equal to itself")
			}
			if tt.setting != nil && !tt.setting.Equal(ptr.To(*tt.setting)) {
				t.Errorf("the setting should be equal to its shallow copy")
			}
			if gotKey := tt.setting.Key(); gotKey != tt.wantKey {
				t.Errorf("Key: got %q, want %q", gotKey, tt.wantKey)
			}
			if gotScope := tt.setting.Scope(); gotScope != tt.wantScope {
				t.Errorf("Scope: got %v, want %v", gotScope, tt.wantScope)
			}
			if gotType := tt.setting.Type(); gotType != tt.wantType {
				t.Errorf("Type: got %v, want %v", gotType, tt.wantType)
			}
			if gotIsSupported := tt.setting.IsSupported(); gotIsSupported != tt.wantIsSupported {
				t.Errorf("IsSupported: got %v, want %v", gotIsSupported, tt.wantIsSupported)
			}
			if gotSupportedPlatforms := tt.setting.SupportedPlatforms(); !slices.Equal(gotSupportedPlatforms, tt.wantSupportedPlatforms) {
				t.Errorf("SupportedPlatforms: got %v, want %v", gotSupportedPlatforms, tt.wantSupportedPlatforms)
			}
			if gotString := tt.setting.String(); gotString != tt.wantString {
				t.Errorf("String: got %v, want %v", gotString, tt.wantString)
			}
		})
	}
}

func TestRegisterSettingDefinition(t *testing.T) {
	const testPolicySettingKey pkey.Key = "TestPolicySetting"
	tests := []struct {
		name    string
		key     pkey.Key
		wantEq  *Definition
		wantErr error
	}{
		{
			name:   "GetRegistered",
			key:    "TestPolicySetting",
			wantEq: NewDefinition(testPolicySettingKey, DeviceSetting, StringValue),
		},
		{
			name:    "GetNonRegistered",
			key:     "OtherPolicySetting",
			wantEq:  nil,
			wantErr: ErrNoSuchKey,
		},
	}

	resetSettingDefinitions(t)
	Register(testPolicySettingKey, DeviceSetting, StringValue)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := DefinitionOf(tt.key)
			if gotErr != tt.wantErr {
				t.Errorf("gotErr %v, wantErr %v", gotErr, tt.wantErr)
			}
			if !got.Equal(tt.wantEq) {
				t.Errorf("got %v, want %v", got, tt.wantEq)
			}
		})
	}
}

func TestRegisterAfterUsePanics(t *testing.T) {
	resetSettingDefinitions(t)

	Register("TestPolicySetting", DeviceSetting, StringValue)
	DefinitionOf("TestPolicySetting")

	func() {
		defer func() {
			if gotPanic, wantPanic := recover(), "policy definitions are already in use"; gotPanic != wantPanic {
				t.Errorf("gotPanic: %q, wantPanic: %q", gotPanic, wantPanic)
			}
		}()

		Register("TestPolicySetting", DeviceSetting, StringValue)
	}()
}

func TestRegisterDuplicateSettings(t *testing.T) {

	tests := []struct {
		name       string
		settings   []*Definition
		wantEq     *Definition
		wantErrStr string
	}{
		{
			name: "NoConflict/Exact",
			settings: []*Definition{
				NewDefinition("TestPolicySetting", DeviceSetting, StringValue),
				NewDefinition("TestPolicySetting", DeviceSetting, StringValue),
			},
			wantEq: NewDefinition("TestPolicySetting", DeviceSetting, StringValue),
		},
		{
			name: "NoConflict/MergeOS-First",
			settings: []*Definition{
				NewDefinition("TestPolicySetting", DeviceSetting, StringValue, "android", "macos"),
				NewDefinition("TestPolicySetting", DeviceSetting, StringValue), // all platforms
			},
			wantEq: NewDefinition("TestPolicySetting", DeviceSetting, StringValue), // all platforms
		},
		{
			name: "NoConflict/MergeOS-Second",
			settings: []*Definition{
				NewDefinition("TestPolicySetting", DeviceSetting, StringValue), // all platforms
				NewDefinition("TestPolicySetting", DeviceSetting, StringValue, "android", "macos"),
			},
			wantEq: NewDefinition("TestPolicySetting", DeviceSetting, StringValue), // all platforms
		},
		{
			name: "NoConflict/MergeOS-Both",
			settings: []*Definition{
				NewDefinition("TestPolicySetting", DeviceSetting, StringValue, "macos"),
				NewDefinition("TestPolicySetting", DeviceSetting, StringValue, "windows"),
			},
			wantEq: NewDefinition("TestPolicySetting", DeviceSetting, StringValue, "macos", "windows"),
		},
		{
			name: "Conflict/Scope",
			settings: []*Definition{
				NewDefinition("TestPolicySetting", DeviceSetting, StringValue),
				NewDefinition("TestPolicySetting", UserSetting, StringValue),
			},
			wantEq:     nil,
			wantErrStr: `duplicate policy definition: "TestPolicySetting"`,
		},
		{
			name: "Conflict/Type",
			settings: []*Definition{
				NewDefinition("TestPolicySetting", UserSetting, StringValue),
				NewDefinition("TestPolicySetting", UserSetting, IntegerValue),
			},
			wantEq:     nil,
			wantErrStr: `duplicate policy definition: "TestPolicySetting"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetSettingDefinitions(t)
			for _, s := range tt.settings {
				Register(s.Key(), s.Scope(), s.Type(), s.SupportedPlatforms()...)
			}
			got, err := DefinitionOf("TestPolicySetting")
			var gotErrStr string
			if err != nil {
				gotErrStr = err.Error()
			}
			if gotErrStr != tt.wantErrStr {
				t.Fatalf("ErrStr: got %q, want %q", gotErrStr, tt.wantErrStr)
			}
			if !got.Equal(tt.wantEq) {
				t.Errorf("Definition got %v, want %v", got, tt.wantEq)
			}
			if !slices.Equal(got.SupportedPlatforms(), tt.wantEq.SupportedPlatforms()) {
				t.Errorf("SupportedPlatforms got %v, want %v", got.SupportedPlatforms(), tt.wantEq.SupportedPlatforms())
			}
		})
	}
}

func TestListSettingDefinitions(t *testing.T) {
	definitions := []*Definition{
		NewDefinition("TestDevicePolicySetting", DeviceSetting, IntegerValue),
		NewDefinition("TestProfilePolicySetting", ProfileSetting, StringValue),
		NewDefinition("TestUserPolicySetting", UserSetting, BooleanValue),
		NewDefinition("TestStringListPolicySetting", DeviceSetting, StringListValue),
	}
	if err := SetDefinitionsForTest(t, definitions...); err != nil {
		t.Fatalf("SetDefinitionsForTest failed: %v", err)
	}

	cmp := func(l, r *Definition) int {
		return strings.Compare(string(l.Key()), string(r.Key()))
	}
	want := append([]*Definition{}, definitions...)
	slices.SortFunc(want, cmp)

	got, err := Definitions()
	if err != nil {
		t.Fatalf("Definitions failed: %v", err)
	}
	slices.SortFunc(got, cmp)

	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func resetSettingDefinitions(t *testing.T) {
	t.Cleanup(func() {
		definitionsMu.Lock()
		definitionsList = nil
		definitions = lazy.SyncValue[DefinitionMap]{}
		definitionsUsed = false
		definitionsMu.Unlock()
	})

	definitionsMu.Lock()
	definitionsList = nil
	definitions = lazy.SyncValue[DefinitionMap]{}
	definitionsUsed = false
	definitionsMu.Unlock()
}
