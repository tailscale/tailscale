// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package source

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/util/syspolicy/setting"
)

func TestJSONPolicyStoreReadString(t *testing.T) {
	s := NewJSONPolicyStore(map[string]any{
		"ControlURL": "https://controlplane.example.com",
		"AuthKey":    "tskey-auth-xxx",
		"Bool":       true,
	})

	got, err := s.ReadString("ControlURL")
	if err != nil {
		t.Fatalf("ReadString(ControlURL) error: %v", err)
	}
	if want := "https://controlplane.example.com"; got != want {
		t.Errorf("ReadString(ControlURL) = %q, want %q", got, want)
	}

	if _, err := s.ReadString("Missing"); !errors.Is(err, setting.ErrNotConfigured) {
		t.Errorf("ReadString(Missing) err = %v, want ErrNotConfigured", err)
	}

	if _, err := s.ReadString("Bool"); !errors.Is(err, setting.ErrTypeMismatch) {
		t.Errorf("ReadString(Bool) err = %v, want ErrTypeMismatch", err)
	}
}

func TestJSONPolicyStoreReadBoolean(t *testing.T) {
	s := NewJSONPolicyStore(map[string]any{
		"AlwaysOn": true,
		"Str":      "yes",
	})

	got, err := s.ReadBoolean("AlwaysOn")
	if err != nil {
		t.Fatalf("ReadBoolean(AlwaysOn) error: %v", err)
	}
	if !got {
		t.Errorf("ReadBoolean(AlwaysOn) = false, want true")
	}

	if _, err := s.ReadBoolean("Missing"); !errors.Is(err, setting.ErrNotConfigured) {
		t.Errorf("ReadBoolean(Missing) err = %v, want ErrNotConfigured", err)
	}

	if _, err := s.ReadBoolean("Str"); !errors.Is(err, setting.ErrTypeMismatch) {
		t.Errorf("ReadBoolean(Str) err = %v, want ErrTypeMismatch", err)
	}
}

func TestJSONPolicyStoreReadStringArray(t *testing.T) {
	s := NewJSONPolicyStore(map[string]any{
		"AllowedSuggestedExitNodes": []any{"node-a", "node-b"},
		"Empty":                     []any{},
		"NotArray":                  "abc",
		"WrongElem":                 []any{"a", 1},
	})

	got, err := s.ReadStringArray("AllowedSuggestedExitNodes")
	if err != nil {
		t.Fatalf("ReadStringArray(AllowedSuggestedExitNodes) error: %v", err)
	}
	if want := []string{"node-a", "node-b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ReadStringArray = %v, want %v", got, want)
	}

	got, err = s.ReadStringArray("Empty")
	if err != nil {
		t.Fatalf("ReadStringArray(Empty) error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ReadStringArray(Empty) = %v, want empty", got)
	}

	if _, err := s.ReadStringArray("Missing"); !errors.Is(err, setting.ErrNotConfigured) {
		t.Errorf("ReadStringArray(Missing) err = %v, want ErrNotConfigured", err)
	}
	if _, err := s.ReadStringArray("NotArray"); !errors.Is(err, setting.ErrTypeMismatch) {
		t.Errorf("ReadStringArray(NotArray) err = %v, want ErrTypeMismatch", err)
	}
	if _, err := s.ReadStringArray("WrongElem"); !errors.Is(err, setting.ErrTypeMismatch) {
		t.Errorf("ReadStringArray(WrongElem) err = %v, want ErrTypeMismatch", err)
	}
}

func TestJSONPolicyStoreReadUInt64FromMap(t *testing.T) {
	s := NewJSONPolicyStore(map[string]any{
		"Float":    float64(42),
		"Negative": float64(-1),
		"Frac":     float64(1.5),
		"Str":      "nope",
	})

	got, err := s.ReadUInt64("Float")
	if err != nil {
		t.Fatalf("ReadUInt64(Float) error: %v", err)
	}
	if got != 42 {
		t.Errorf("ReadUInt64(Float) = %d, want 42", got)
	}

	if _, err := s.ReadUInt64("Missing"); !errors.Is(err, setting.ErrNotConfigured) {
		t.Errorf("ReadUInt64(Missing) err = %v, want ErrNotConfigured", err)
	}
	for _, k := range []pkey.Key{"Negative", "Frac", "Str"} {
		if _, err := s.ReadUInt64(k); !errors.Is(err, setting.ErrTypeMismatch) {
			t.Errorf("ReadUInt64(%s) err = %v, want ErrTypeMismatch", k, err)
		}
	}
}

func TestJSONPolicyStoreReadUInt64FromJSON(t *testing.T) {
	// json.Number path: bigger than float64 mantissa precision.
	s, err := NewJSONPolicyStoreFromBytes([]byte(`{"Big": 18446744073709551610}`))
	if err != nil {
		t.Fatalf("NewJSONPolicyStoreFromBytes: %v", err)
	}
	got, err := s.ReadUInt64("Big")
	if err != nil {
		t.Fatalf("ReadUInt64(Big) error: %v", err)
	}
	if want := uint64(18446744073709551610); got != want {
		t.Errorf("ReadUInt64(Big) = %d, want %d", got, want)
	}
}

// TestJSONPolicyStoreDuration verifies that duration-typed settings, which
// the reader fetches via ReadString and parses with time.ParseDuration, work
// end-to-end with values like "24h".
func TestJSONPolicyStoreDuration(t *testing.T) {
	s := NewJSONPolicyStore(map[string]any{
		"ReconnectAfter": "24h",
		"Bad":            "notaduration",
	})
	def := setting.NewDefinition("ReconnectAfter", setting.DeviceSetting, setting.DurationValue)
	v, err := readPolicySettingValue(s, def)
	if err != nil {
		t.Fatalf("readPolicySettingValue(ReconnectAfter) error: %v", err)
	}
	if got, want := v.(time.Duration), 24*time.Hour; got != want {
		t.Errorf("ReconnectAfter = %v, want %v", got, want)
	}

	badDef := setting.NewDefinition("Bad", setting.DeviceSetting, setting.DurationValue)
	if _, err := readPolicySettingValue(s, badDef); err == nil {
		t.Errorf("readPolicySettingValue(Bad) err = nil, want parse error")
	}
}

func TestJSONPolicyStorePreferenceOptionAndVisibility(t *testing.T) {
	s := NewJSONPolicyStore(map[string]any{
		"CheckUpdates":           "always",
		"AdminConsoleVisibility": "hide",
	})
	prefDef := setting.NewDefinition("CheckUpdates", setting.DeviceSetting, setting.PreferenceOptionValue)
	v, err := readPolicySettingValue(s, prefDef)
	if err != nil {
		t.Fatalf("readPolicySettingValue(CheckUpdates) error: %v", err)
	}
	if got := v.(ptype.PreferenceOption); got != ptype.AlwaysByPolicy {
		t.Errorf("CheckUpdates = %v, want AlwaysByPolicy", got)
	}

	visDef := setting.NewDefinition("AdminConsoleVisibility", setting.UserSetting, setting.VisibilityValue)
	v, err = readPolicySettingValue(s, visDef)
	if err != nil {
		t.Fatalf("readPolicySettingValue(AdminConsoleVisibility) error: %v", err)
	}
	if got := v.(ptype.Visibility); got != ptype.HiddenByPolicy {
		t.Errorf("AdminConsoleVisibility = %v, want HiddenByPolicy", got)
	}
}

func TestJSONPolicyStoreValidate(t *testing.T) {
	// Register a small set of definitions covering each type that the
	// validator needs to exercise.
	if err := setting.SetDefinitionsForTest(t,
		setting.NewDefinition("ControlURL", setting.DeviceSetting, setting.StringValue),
		setting.NewDefinition("AlwaysOn", setting.DeviceSetting, setting.BooleanValue),
		setting.NewDefinition("AllowedSuggestedExitNodes", setting.DeviceSetting, setting.StringListValue),
		setting.NewDefinition("ReconnectAfter", setting.DeviceSetting, setting.DurationValue),
		setting.NewDefinition("CheckUpdates", setting.DeviceSetting, setting.PreferenceOptionValue),
		setting.NewDefinition("AdminConsoleVisibility", setting.UserSetting, setting.VisibilityValue),
	); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		json        map[string]any
		wantOK      bool
		wantErrSubs []string // substrings the error must contain (only when wantOK is false)
	}{
		{
			name:   "empty",
			json:   map[string]any{},
			wantOK: true,
		},
		{
			name: "all_valid",
			json: map[string]any{
				"ControlURL":                "https://controlplane.example.com",
				"AlwaysOn":                  true,
				"AllowedSuggestedExitNodes": []any{"node-a", "node-b"},
				"ReconnectAfter":            "24h",
				"CheckUpdates":              "always",
				"AdminConsoleVisibility":    "hide",
			},
			wantOK: true,
		},
		{
			name: "unknown_key",
			json: map[string]any{
				"ControlURL":  "https://controlplane.example.com",
				"NoSuchThing": "whatever",
			},
			wantErrSubs: []string{`unknown policy setting "NoSuchThing"`},
		},
		{
			name: "wrong_type_string",
			json: map[string]any{
				"ControlURL": true,
			},
			wantErrSubs: []string{`"ControlURL"`, "type mismatch"},
		},
		{
			name: "wrong_type_bool",
			json: map[string]any{
				"AlwaysOn": "yes",
			},
			wantErrSubs: []string{`"AlwaysOn"`, "type mismatch"},
		},
		{
			name: "wrong_type_array",
			json: map[string]any{
				"AllowedSuggestedExitNodes": "node-a",
			},
			wantErrSubs: []string{`"AllowedSuggestedExitNodes"`, "type mismatch"},
		},
		{
			name: "bad_duration",
			json: map[string]any{
				"ReconnectAfter": "notaduration",
			},
			wantErrSubs: []string{`"ReconnectAfter"`, "notaduration"},
		},
		{
			name: "bad_preference_option",
			json: map[string]any{
				"CheckUpdates": "sometimes",
			},
			wantErrSubs: []string{`"CheckUpdates"`, "sometimes", "always"},
		},
		{
			name: "bad_visibility",
			json: map[string]any{
				"AdminConsoleVisibility": "maybe",
			},
			wantErrSubs: []string{`"AdminConsoleVisibility"`, "maybe", "show"},
		},
		{
			name: "multiple_errors_reported",
			json: map[string]any{
				"AlwaysOn":    "yes",
				"NoSuchThing": 1,
			},
			wantErrSubs: []string{`"AlwaysOn"`, `unknown policy setting "NoSuchThing"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewJSONPolicyStore(tt.json).Validate()
			if tt.wantOK {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %v", tt.wantErrSubs)
			}
			for _, sub := range tt.wantErrSubs {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("Validate() error = %q, want it to contain %q", err, sub)
				}
			}
		})
	}
}

func TestNewJSONPolicyStoreFromBytesHuJSON(t *testing.T) {
	if hujsonStandardize == nil {
		t.Skip("HuJSON support not linked into this build")
	}
	const hujsonInput = `{
  // The control plane URL.
  "ControlURL": "https://controlplane.example.com",
  "AlwaysOn": true, // trailing comma is OK in HuJSON
}`
	s, err := NewJSONPolicyStoreFromBytes([]byte(hujsonInput))
	if err != nil {
		t.Fatalf("NewJSONPolicyStoreFromBytes(HuJSON) error: %v", err)
	}
	got, err := s.ReadString("ControlURL")
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if want := "https://controlplane.example.com"; got != want {
		t.Errorf("ReadString = %q, want %q", got, want)
	}
	gotBool, err := s.ReadBoolean("AlwaysOn")
	if err != nil {
		t.Fatalf("ReadBoolean: %v", err)
	}
	if !gotBool {
		t.Errorf("ReadBoolean = false, want true")
	}
}

func TestNewJSONPolicyStoreFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "syspolicy.json")
	if err := os.WriteFile(path, []byte(`{"ControlURL": "https://example.com"}`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewJSONPolicyStoreFromFile(path)
	if err != nil {
		t.Fatalf("NewJSONPolicyStoreFromFile: %v", err)
	}
	got, err := s.ReadString("ControlURL")
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if want := "https://example.com"; got != want {
		t.Errorf("ReadString = %q, want %q", got, want)
	}

	if _, err := NewJSONPolicyStoreFromFile(filepath.Join(dir, "missing.json")); err == nil {
		t.Errorf("NewJSONPolicyStoreFromFile(missing) err = nil, want error")
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`not json`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewJSONPolicyStoreFromFile(bad); err == nil {
		t.Errorf("NewJSONPolicyStoreFromFile(bad) err = nil, want parse error")
	}
}
