// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package source

import (
	"cmp"
	"errors"
	"math"
	"reflect"
	"strconv"
	"testing"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/setting"
)

func TestKeyToEnvVarName(t *testing.T) {
	tests := []struct {
		name    string
		key     pkey.Key
		want    string // suffix after "TS_DEBUGSYSPOLICY_"
		wantErr error
	}{
		{
			name:    "empty",
			key:     "",
			wantErr: errEmptyKey,
		},
		{
			name: "lowercase",
			key:  "tailnet",
			want: "TAILNET",
		},
		{
			name: "CamelCase",
			key:  "AuthKey",
			want: "AUTH_KEY",
		},
		{
			name: "LongerCamelCase",
			key:  "ManagedByOrganizationName",
			want: "MANAGED_BY_ORGANIZATION_NAME",
		},
		{
			name: "UPPERCASE",
			key:  "UPPERCASE",
			want: "UPPERCASE",
		},
		{
			name: "WithAbbrev/Front",
			key:  "DNSServer",
			want: "DNS_SERVER",
		},
		{
			name: "WithAbbrev/Middle",
			key:  "ExitNodeAllowLANAccess",
			want: "EXIT_NODE_ALLOW_LAN_ACCESS",
		},
		{
			name: "WithAbbrev/Back",
			key:  "ExitNodeID",
			want: "EXIT_NODE_ID",
		},
		{
			name: "WithDigits/Single/Front",
			key:  "0TestKey",
			want: "0_TEST_KEY",
		},
		{
			name: "WithDigits/Multi/Front",
			key:  "64TestKey",
			want: "64_TEST_KEY",
		},
		{
			name: "WithDigits/Single/Middle",
			key:  "Test0Key",
			want: "TEST_0_KEY",
		},
		{
			name: "WithDigits/Multi/Middle",
			key:  "Test64Key",
			want: "TEST_64_KEY",
		},
		{
			name: "WithDigits/Single/Back",
			key:  "TestKey0",
			want: "TEST_KEY_0",
		},
		{
			name: "WithDigits/Multi/Back",
			key:  "TestKey64",
			want: "TEST_KEY_64",
		},
		{
			name: "WithDigits/Multi/Back",
			key:  "TestKey64",
			want: "TEST_KEY_64",
		},
		{
			name: "WithPathSeparators/Single",
			key:  "Key/Subkey",
			want: "KEY_SUBKEY",
		},
		{
			name: "WithPathSeparators/Multi",
			key:  "Root/Level1/Level2",
			want: "ROOT_LEVEL_1_LEVEL_2",
		},
		{
			name: "Mixed",
			key:  "Network/DNSServer/IPAddress",
			want: "NETWORK_DNS_SERVER_IP_ADDRESS",
		},
		{
			name:    "Non-Alphanumeric/NonASCII/1",
			key:     "ж",
			wantErr: errInvalidKey,
		},
		{
			name:    "Non-Alphanumeric/NonASCII/2",
			key:     "KeyжName",
			wantErr: errInvalidKey,
		},
		{
			name:    "Non-Alphanumeric/Space",
			key:     "Key Name",
			wantErr: errInvalidKey,
		},
		{
			name:    "Non-Alphanumeric/Punct",
			key:     "Key!Name",
			wantErr: errInvalidKey,
		},
		{
			name:    "Non-Alphanumeric/Backslash",
			key:     `Key\Name`,
			wantErr: errInvalidKey,
		},
	}
	for _, tt := range tests {
		t.Run(cmp.Or(tt.name, string(tt.key)), func(t *testing.T) {
			got, err := keyToEnvVarName(tt.key)
			checkError(t, err, tt.wantErr, true)

			want := tt.want
			if want != "" {
				want = "TS_DEBUGSYSPOLICY_" + want
			}
			if got != want {
				t.Fatalf("got %q; want %q", got, want)
			}
		})
	}
}

func TestEnvPolicyStore(t *testing.T) {
	blankEnv := func(string) (string, bool) { return "", false }
	makeEnv := func(wantName, value string) func(string) (string, bool) {
		wantName = "TS_DEBUGSYSPOLICY_" + wantName
		return func(gotName string) (string, bool) {
			if gotName != wantName {
				return "", false
			}
			return value, true
		}
	}
	tests := []struct {
		name    string
		key     pkey.Key
		lookup  func(string) (string, bool)
		want    any
		wantErr error
	}{
		{
			name:    "NotConfigured/String",
			key:     "AuthKey",
			lookup:  blankEnv,
			wantErr: setting.ErrNotConfigured,
			want:    "",
		},
		{
			name:   "Configured/String/Empty",
			key:    "AuthKey",
			lookup: makeEnv("AUTH_KEY", ""),
			want:   "",
		},
		{
			name:   "Configured/String/NonEmpty",
			key:    "AuthKey",
			lookup: makeEnv("AUTH_KEY", "ABC123"),
			want:   "ABC123",
		},
		{
			name:    "NotConfigured/UInt64",
			key:     "IntegerSetting",
			lookup:  blankEnv,
			wantErr: setting.ErrNotConfigured,
			want:    uint64(0),
		},
		{
			name:    "Configured/UInt64/Empty",
			key:     "IntegerSetting",
			lookup:  makeEnv("INTEGER_SETTING", ""),
			wantErr: setting.ErrNotConfigured,
			want:    uint64(0),
		},
		{
			name:   "Configured/UInt64/Zero",
			key:    "IntegerSetting",
			lookup: makeEnv("INTEGER_SETTING", "0"),
			want:   uint64(0),
		},
		{
			name:   "Configured/UInt64/NonZero",
			key:    "IntegerSetting",
			lookup: makeEnv("INTEGER_SETTING", "12345"),
			want:   uint64(12345),
		},
		{
			name:   "Configured/UInt64/MaxUInt64",
			key:    "IntegerSetting",
			lookup: makeEnv("INTEGER_SETTING", strconv.FormatUint(math.MaxUint64, 10)),
			want:   uint64(math.MaxUint64),
		},
		{
			name:    "Configured/UInt64/Negative",
			key:     "IntegerSetting",
			lookup:  makeEnv("INTEGER_SETTING", "-1"),
			wantErr: setting.ErrTypeMismatch,
			want:    uint64(0),
		},
		{
			name:   "Configured/UInt64/Hex",
			key:    "IntegerSetting",
			lookup: makeEnv("INTEGER_SETTING", "0xDEADBEEF"),
			want:   uint64(0xDEADBEEF),
		},
		{
			name:    "NotConfigured/Bool",
			key:     "LogSCMInteractions",
			lookup:  blankEnv,
			wantErr: setting.ErrNotConfigured,
			want:    false,
		},
		{
			name:    "Configured/Bool/Empty",
			key:     "LogSCMInteractions",
			lookup:  makeEnv("LOG_SCM_INTERACTIONS", ""),
			wantErr: setting.ErrNotConfigured,
			want:    false,
		},
		{
			name:   "Configured/Bool/True",
			key:    "LogSCMInteractions",
			lookup: makeEnv("LOG_SCM_INTERACTIONS", "true"),
			want:   true,
		},
		{
			name:   "Configured/Bool/False",
			key:    "LogSCMInteractions",
			lookup: makeEnv("LOG_SCM_INTERACTIONS", "False"),
			want:   false,
		},
		{
			name:   "Configured/Bool/1",
			key:    "LogSCMInteractions",
			lookup: makeEnv("LOG_SCM_INTERACTIONS", "1"),
			want:   true,
		},
		{
			name:   "Configured/Bool/0",
			key:    "LogSCMInteractions",
			lookup: makeEnv("LOG_SCM_INTERACTIONS", "0"),
			want:   false,
		},
		{
			name:    "Configured/Bool/Invalid",
			key:     "IntegerSetting",
			lookup:  makeEnv("INTEGER_SETTING", "NotABool"),
			wantErr: setting.ErrTypeMismatch,
			want:    false,
		},
		{
			name:    "NotConfigured/StringArray",
			key:     "AllowedSuggestedExitNodes",
			lookup:  blankEnv,
			wantErr: setting.ErrNotConfigured,
			want:    []string(nil),
		},
		{
			name:   "Configured/StringArray/Empty",
			key:    "AllowedSuggestedExitNodes",
			lookup: makeEnv("ALLOWED_SUGGESTED_EXIT_NODES", ""),
			want:   []string(nil),
		},
		{
			name:   "Configured/StringArray/Spaces",
			key:    "AllowedSuggestedExitNodes",
			lookup: makeEnv("ALLOWED_SUGGESTED_EXIT_NODES", " \t  "),
			want:   []string{},
		},
		{
			name:   "Configured/StringArray/Single",
			key:    "AllowedSuggestedExitNodes",
			lookup: makeEnv("ALLOWED_SUGGESTED_EXIT_NODES", "NodeA"),
			want:   []string{"NodeA"},
		},
		{
			name:   "Configured/StringArray/Multi",
			key:    "AllowedSuggestedExitNodes",
			lookup: makeEnv("ALLOWED_SUGGESTED_EXIT_NODES", "NodeA,NodeB,NodeC"),
			want:   []string{"NodeA", "NodeB", "NodeC"},
		},
		{
			name:   "Configured/StringArray/WithBlank",
			key:    "AllowedSuggestedExitNodes",
			lookup: makeEnv("ALLOWED_SUGGESTED_EXIT_NODES", "NodeA,\t,,   ,NodeB"),
			want:   []string{"NodeA", "NodeB"},
		},
	}
	for _, tt := range tests {
		t.Run(cmp.Or(tt.name, string(tt.key)), func(t *testing.T) {
			oldLookupEnv := lookupEnv
			t.Cleanup(func() { lookupEnv = oldLookupEnv })
			lookupEnv = tt.lookup

			var got any
			var err error
			var store EnvPolicyStore
			switch tt.want.(type) {
			case string:
				got, err = store.ReadString(tt.key)
			case uint64:
				got, err = store.ReadUInt64(tt.key)
			case bool:
				got, err = store.ReadBoolean(tt.key)
			case []string:
				got, err = store.ReadStringArray(tt.key)
			}
			checkError(t, err, tt.wantErr, false)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func checkError(tb testing.TB, got, want error, fatal bool) {
	tb.Helper()
	f := tb.Errorf
	if fatal {
		f = tb.Fatalf
	}
	if (want == nil && got != nil) ||
		(want != nil && got == nil) ||
		(want != nil && got != nil && !errors.Is(got, want) && want.Error() != got.Error()) {
		f("gotErr: %v; wantErr: %v", got, want)
	}
}
