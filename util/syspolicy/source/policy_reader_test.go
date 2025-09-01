// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package source

import (
	"cmp"
	"testing"
	"time"

	"tailscale.com/util/must"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/util/syspolicy/setting"
)

func TestReaderLifecycle(t *testing.T) {
	tests := []struct {
		name           string
		origin         *setting.Origin
		definitions    []*setting.Definition
		wantReads      []TestExpectedReads
		initStrings    []TestSetting[string]
		initUInt64s    []TestSetting[uint64]
		initWant       *setting.Snapshot
		addStrings     []TestSetting[string]
		addStringLists []TestSetting[[]string]
		newWant        *setting.Snapshot
	}{
		{
			name:   "read-all-settings-once",
			origin: setting.NewNamedOrigin("Test", setting.DeviceScope),
			definitions: []*setting.Definition{
				setting.NewDefinition("StringValue", setting.DeviceSetting, setting.StringValue),
				setting.NewDefinition("IntegerValue", setting.DeviceSetting, setting.IntegerValue),
				setting.NewDefinition("BooleanValue", setting.DeviceSetting, setting.BooleanValue),
				setting.NewDefinition("StringListValue", setting.DeviceSetting, setting.StringListValue),
				setting.NewDefinition("DurationValue", setting.DeviceSetting, setting.DurationValue),
				setting.NewDefinition("PreferenceOptionValue", setting.DeviceSetting, setting.PreferenceOptionValue),
				setting.NewDefinition("VisibilityValue", setting.DeviceSetting, setting.VisibilityValue),
			},
			wantReads: []TestExpectedReads{
				{Key: "StringValue", Type: setting.StringValue, NumTimes: 1},
				{Key: "IntegerValue", Type: setting.IntegerValue, NumTimes: 1},
				{Key: "BooleanValue", Type: setting.BooleanValue, NumTimes: 1},
				{Key: "StringListValue", Type: setting.StringListValue, NumTimes: 1},
				{Key: "DurationValue", Type: setting.StringValue, NumTimes: 1},         // duration is string from the [Store]'s perspective
				{Key: "PreferenceOptionValue", Type: setting.StringValue, NumTimes: 1}, // and so are [setting.PreferenceOption]s
				{Key: "VisibilityValue", Type: setting.StringValue, NumTimes: 1},       // and [setting.Visibility]
			},
			initWant: setting.NewSnapshot(nil, setting.NewNamedOrigin("Test", setting.DeviceScope)),
		},
		{
			name:   "re-read-all-settings-when-the-policy-changes",
			origin: setting.NewNamedOrigin("Test", setting.DeviceScope),
			definitions: []*setting.Definition{
				setting.NewDefinition("StringValue", setting.DeviceSetting, setting.StringValue),
				setting.NewDefinition("IntegerValue", setting.DeviceSetting, setting.IntegerValue),
				setting.NewDefinition("BooleanValue", setting.DeviceSetting, setting.BooleanValue),
				setting.NewDefinition("StringListValue", setting.DeviceSetting, setting.StringListValue),
				setting.NewDefinition("DurationValue", setting.DeviceSetting, setting.DurationValue),
				setting.NewDefinition("PreferenceOptionValue", setting.DeviceSetting, setting.PreferenceOptionValue),
				setting.NewDefinition("VisibilityValue", setting.DeviceSetting, setting.VisibilityValue),
			},
			wantReads: []TestExpectedReads{
				{Key: "StringValue", Type: setting.StringValue, NumTimes: 1},
				{Key: "IntegerValue", Type: setting.IntegerValue, NumTimes: 1},
				{Key: "BooleanValue", Type: setting.BooleanValue, NumTimes: 1},
				{Key: "StringListValue", Type: setting.StringListValue, NumTimes: 1},
				{Key: "DurationValue", Type: setting.StringValue, NumTimes: 1},         // duration is string from the [Store]'s perspective
				{Key: "PreferenceOptionValue", Type: setting.StringValue, NumTimes: 1}, // and so are [setting.PreferenceOption]s
				{Key: "VisibilityValue", Type: setting.StringValue, NumTimes: 1},       // and [setting.Visibility]
			},
			initWant:       setting.NewSnapshot(nil, setting.NewNamedOrigin("Test", setting.DeviceScope)),
			addStrings:     []TestSetting[string]{TestSettingOf("StringValue", "S1")},
			addStringLists: []TestSetting[[]string]{TestSettingOf("StringListValue", []string{"S1", "S2", "S3"})},
			newWant: setting.NewSnapshot(map[pkey.Key]setting.RawItem{
				"StringValue":     setting.RawItemWith("S1", nil, setting.NewNamedOrigin("Test", setting.DeviceScope)),
				"StringListValue": setting.RawItemWith([]string{"S1", "S2", "S3"}, nil, setting.NewNamedOrigin("Test", setting.DeviceScope)),
			}, setting.NewNamedOrigin("Test", setting.DeviceScope)),
		},
		{
			name:   "read-settings-if-in-scope/device",
			origin: setting.NewNamedOrigin("Test", setting.DeviceScope),
			definitions: []*setting.Definition{
				setting.NewDefinition("DeviceSetting", setting.DeviceSetting, setting.StringValue),
				setting.NewDefinition("ProfileSetting", setting.ProfileSetting, setting.IntegerValue),
				setting.NewDefinition("UserSetting", setting.UserSetting, setting.BooleanValue),
			},
			wantReads: []TestExpectedReads{
				{Key: "DeviceSetting", Type: setting.StringValue, NumTimes: 1},
				{Key: "ProfileSetting", Type: setting.IntegerValue, NumTimes: 1},
				{Key: "UserSetting", Type: setting.BooleanValue, NumTimes: 1},
			},
		},
		{
			name:   "read-settings-if-in-scope/profile",
			origin: setting.NewNamedOrigin("Test", setting.CurrentProfileScope),
			definitions: []*setting.Definition{
				setting.NewDefinition("DeviceSetting", setting.DeviceSetting, setting.StringValue),
				setting.NewDefinition("ProfileSetting", setting.ProfileSetting, setting.IntegerValue),
				setting.NewDefinition("UserSetting", setting.UserSetting, setting.BooleanValue),
			},
			wantReads: []TestExpectedReads{
				// Device settings cannot be configured at the profile scope and should not be read.
				{Key: "ProfileSetting", Type: setting.IntegerValue, NumTimes: 1},
				{Key: "UserSetting", Type: setting.BooleanValue, NumTimes: 1},
			},
		},
		{
			name:   "read-settings-if-in-scope/user",
			origin: setting.NewNamedOrigin("Test", setting.CurrentUserScope),
			definitions: []*setting.Definition{
				setting.NewDefinition("DeviceSetting", setting.DeviceSetting, setting.StringValue),
				setting.NewDefinition("ProfileSetting", setting.ProfileSetting, setting.IntegerValue),
				setting.NewDefinition("UserSetting", setting.UserSetting, setting.BooleanValue),
			},
			wantReads: []TestExpectedReads{
				// Device and profile settings cannot be configured at the profile scope and should not be read.
				{Key: "UserSetting", Type: setting.BooleanValue, NumTimes: 1},
			},
		},
		{
			name:   "read-stringy-settings",
			origin: setting.NewNamedOrigin("Test", setting.DeviceScope),
			definitions: []*setting.Definition{
				setting.NewDefinition("DurationValue", setting.DeviceSetting, setting.DurationValue),
				setting.NewDefinition("PreferenceOptionValue", setting.DeviceSetting, setting.PreferenceOptionValue),
				setting.NewDefinition("VisibilityValue", setting.DeviceSetting, setting.VisibilityValue),
			},
			wantReads: []TestExpectedReads{
				{Key: "DurationValue", Type: setting.StringValue, NumTimes: 1},         // duration is string from the [Store]'s perspective
				{Key: "PreferenceOptionValue", Type: setting.StringValue, NumTimes: 1}, // and so are [setting.PreferenceOption]s
				{Key: "VisibilityValue", Type: setting.StringValue, NumTimes: 1},       // and [setting.Visibility]
			},
			initStrings: []TestSetting[string]{
				TestSettingOf("DurationValue", "2h30m"),
				TestSettingOf("PreferenceOptionValue", "always"),
				TestSettingOf("VisibilityValue", "show"),
			},
			initWant: setting.NewSnapshot(map[pkey.Key]setting.RawItem{
				"DurationValue":         setting.RawItemWith(must.Get(time.ParseDuration("2h30m")), nil, setting.NewNamedOrigin("Test", setting.DeviceScope)),
				"PreferenceOptionValue": setting.RawItemWith(ptype.AlwaysByPolicy, nil, setting.NewNamedOrigin("Test", setting.DeviceScope)),
				"VisibilityValue":       setting.RawItemWith(ptype.VisibleByPolicy, nil, setting.NewNamedOrigin("Test", setting.DeviceScope)),
			}, setting.NewNamedOrigin("Test", setting.DeviceScope)),
		},
		{
			name:   "read-erroneous-stringy-settings",
			origin: setting.NewNamedOrigin("Test", setting.CurrentUserScope),
			definitions: []*setting.Definition{
				setting.NewDefinition("DurationValue1", setting.UserSetting, setting.DurationValue),
				setting.NewDefinition("DurationValue2", setting.UserSetting, setting.DurationValue),
				setting.NewDefinition("PreferenceOptionValue", setting.UserSetting, setting.PreferenceOptionValue),
				setting.NewDefinition("VisibilityValue", setting.UserSetting, setting.VisibilityValue),
			},
			wantReads: []TestExpectedReads{
				{Key: "DurationValue1", Type: setting.StringValue, NumTimes: 1},        // duration is string from the [Store]'s perspective
				{Key: "DurationValue2", Type: setting.StringValue, NumTimes: 1},        // duration is string from the [Store]'s perspective
				{Key: "PreferenceOptionValue", Type: setting.StringValue, NumTimes: 1}, // and so are [setting.PreferenceOption]s
				{Key: "VisibilityValue", Type: setting.StringValue, NumTimes: 1},       // and [setting.Visibility]
			},
			initStrings: []TestSetting[string]{
				TestSettingOf("DurationValue1", "soon"),
				TestSettingWithError[string]("DurationValue2", setting.NewErrorText("bang!")),
				TestSettingOf("PreferenceOptionValue", "sometimes"),
			},
			initUInt64s: []TestSetting[uint64]{
				TestSettingOf[uint64]("VisibilityValue", 42), // type mismatch
			},
			initWant: setting.NewSnapshot(map[pkey.Key]setting.RawItem{
				"DurationValue1":        setting.RawItemWith(nil, setting.NewErrorText("time: invalid duration \"soon\""), setting.NewNamedOrigin("Test", setting.CurrentUserScope)),
				"DurationValue2":        setting.RawItemWith(nil, setting.NewErrorText("bang!"), setting.NewNamedOrigin("Test", setting.CurrentUserScope)),
				"PreferenceOptionValue": setting.RawItemWith(ptype.ShowChoiceByPolicy, nil, setting.NewNamedOrigin("Test", setting.CurrentUserScope)),
				"VisibilityValue":       setting.RawItemWith(ptype.VisibleByPolicy, setting.NewErrorText("type mismatch in ReadString: got uint64"), setting.NewNamedOrigin("Test", setting.CurrentUserScope)),
			}, setting.NewNamedOrigin("Test", setting.CurrentUserScope)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setting.SetDefinitionsForTest(t, tt.definitions...)
			store := NewTestStore(t)
			store.SetStrings(tt.initStrings...)
			store.SetUInt64s(tt.initUInt64s...)

			reader, err := newReader(store, tt.origin)
			if err != nil {
				t.Fatalf("newReader failed: %v", err)
			}

			if got := reader.GetSettings(); tt.initWant != nil && !got.Equal(tt.initWant) {
				t.Errorf("Settings do not match: got %v, want %v", got, tt.initWant)
			}
			if tt.wantReads != nil {
				store.ReadsMustEqual(tt.wantReads...)
			}

			// Should not result in new reads as there were no changes.
			N := 100
			for range N {
				reader.GetSettings()
			}
			if tt.wantReads != nil {
				store.ReadsMustEqual(tt.wantReads...)
			}
			store.ResetCounters()

			got, err := reader.ReadSettings()
			if err != nil {
				t.Fatalf("ReadSettings failed: %v", err)
			}

			if tt.initWant != nil && !got.Equal(tt.initWant) {
				t.Errorf("Settings do not match: got %v, want %v", got, tt.initWant)
			}

			if tt.wantReads != nil {
				store.ReadsMustEqual(tt.wantReads...)
			}
			store.ResetCounters()

			if len(tt.addStrings) != 0 || len(tt.addStringLists) != 0 {
				store.SetStrings(tt.addStrings...)
				store.SetStringLists(tt.addStringLists...)

				// As the settings have changed, GetSettings needs to re-read them.
				if got, want := reader.GetSettings(), cmp.Or(tt.newWant, tt.initWant); !got.Equal(want) {
					t.Errorf("New Settings do not match: got %v, want %v", got, want)
				}
				if tt.wantReads != nil {
					store.ReadsMustEqual(tt.wantReads...)
				}
			}

			select {
			case <-reader.Done():
				t.Fatalf("the reader is closed")
			default:
			}

			store.Close()

			<-reader.Done()
		})
	}
}

func TestReadingSession(t *testing.T) {
	setting.SetDefinitionsForTest(t, setting.NewDefinition("StringValue", setting.DeviceSetting, setting.StringValue))
	store := NewTestStore(t)

	origin := setting.NewOrigin(setting.DeviceScope)
	reader, err := newReader(store, origin)
	if err != nil {
		t.Fatalf("newReader failed: %v", err)
	}
	session, err := reader.OpenSession()
	if err != nil {
		t.Fatalf("failed to open a reading session: %v", err)
	}
	t.Cleanup(session.Close)

	if got, want := session.GetSettings(), setting.NewSnapshot(nil, origin); !got.Equal(want) {
		t.Errorf("Settings do not match: got %v, want %v", got, want)
	}

	select {
	case _, ok := <-session.PolicyChanged():
		if ok {
			t.Fatalf("the policy changed notification was sent prematurely")
		} else {
			t.Fatalf("the session was closed prematurely")
		}
	default:
	}

	store.SetStrings(TestSettingOf("StringValue", "S1"))
	_, ok := <-session.PolicyChanged()
	if !ok {
		t.Fatalf("the session was closed prematurely")
	}

	want := setting.NewSnapshot(map[pkey.Key]setting.RawItem{
		"StringValue": setting.RawItemWith("S1", nil, origin),
	}, origin)
	if got := session.GetSettings(); !got.Equal(want) {
		t.Errorf("Settings do not match: got %v, want %v", got, want)
	}

	store.Close()
	if _, ok = <-session.PolicyChanged(); ok {
		t.Fatalf("the session must be closed")
	}
}
