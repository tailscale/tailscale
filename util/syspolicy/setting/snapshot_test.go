// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import (
	"cmp"
	"encoding/json"
	"testing"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	"tailscale.com/util/syspolicy/internal"
)

func TestMergeSnapshots(t *testing.T) {
	tests := []struct {
		name   string
		s1, s2 *Snapshot
		want   *Snapshot
	}{
		{
			name: "both-nil",
			s1:   nil,
			s2:   nil,
			want: NewSnapshot(map[Key]RawItem{}),
		},
		{
			name: "both-empty",
			s1:   NewSnapshot(map[Key]RawItem{}),
			s2:   NewSnapshot(map[Key]RawItem{}),
			want: NewSnapshot(map[Key]RawItem{}),
		},
		{
			name: "first-nil",
			s1:   nil,
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true),
			}),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true),
			}),
		},
		{
			name: "first-empty",
			s1:   NewSnapshot(map[Key]RawItem{}),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}),
		},
		{
			name: "second-nil",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true),
			}),
			s2: nil,
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true),
			}),
		},
		{
			name: "second-empty",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}),
			s2: NewSnapshot(map[Key]RawItem{}),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}),
		},
		{
			name: "no-conflicts",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting4": RawItemOf(2 * time.Hour),
				"Setting5": RawItemOf(VisibleByPolicy),
				"Setting6": RawItemOf(ShowChoiceByPolicy),
			}),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
				"Setting4": RawItemOf(2 * time.Hour),
				"Setting5": RawItemOf(VisibleByPolicy),
				"Setting6": RawItemOf(ShowChoiceByPolicy),
			}),
		},
		{
			name: "with-conflicts",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true),
			}),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(456),
				"Setting3": RawItemOf(false),
				"Setting4": RawItemOf(2 * time.Hour),
			}),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(456),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
				"Setting4": RawItemOf(2 * time.Hour),
			}),
		},
		{
			name: "with-scope-first-wins",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true),
			}, DeviceScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(456),
				"Setting3": RawItemOf(false),
				"Setting4": RawItemOf(2 * time.Hour),
			}, CurrentUserScope),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true),
				"Setting4": RawItemOf(2 * time.Hour),
			}, CurrentUserScope),
		},
		{
			name: "with-scope-second-wins",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true),
			}, CurrentUserScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(456),
				"Setting3": RawItemOf(false),
				"Setting4": RawItemOf(2 * time.Hour),
			}, DeviceScope),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(456),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
				"Setting4": RawItemOf(2 * time.Hour),
			}, CurrentUserScope),
		},
		{
			name: "with-scope-both-empty",
			s1:   NewSnapshot(map[Key]RawItem{}, CurrentUserScope),
			s2:   NewSnapshot(map[Key]RawItem{}, DeviceScope),
			want: NewSnapshot(map[Key]RawItem{}, CurrentUserScope),
		},
		{
			name: "with-scope-first-empty",
			s1:   NewSnapshot(map[Key]RawItem{}, CurrentUserScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true)}, DeviceScope, NewNamedOrigin("TestPolicy", DeviceScope)),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true),
			}, CurrentUserScope, NewNamedOrigin("TestPolicy", DeviceScope)),
		},
		{
			name: "with-scope-second-empty",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true),
			}, CurrentUserScope),
			s2: NewSnapshot(map[Key]RawItem{}),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true),
			}, CurrentUserScope),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeSnapshots(tt.s1, tt.s2)
			if !got.Equal(tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSnapshotEqual(t *testing.T) {
	tests := []struct {
		name           string
		s1, s2         *Snapshot
		wantEqual      bool
		wantEqualItems bool
	}{
		{
			name:           "nil-nil",
			s1:             nil,
			s2:             nil,
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name:           "nil-empty",
			s1:             nil,
			s2:             NewSnapshot(map[Key]RawItem{}),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name:           "empty-nil",
			s1:             NewSnapshot(map[Key]RawItem{}),
			s2:             nil,
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name:           "empty-empty",
			s1:             NewSnapshot(map[Key]RawItem{}),
			s2:             NewSnapshot(map[Key]RawItem{}),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name: "first-nil",
			s1:   nil,
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}),
			wantEqual:      false,
			wantEqualItems: false,
		},
		{
			name: "first-empty",
			s1:   NewSnapshot(map[Key]RawItem{}),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}),
			wantEqual:      false,
			wantEqualItems: false,
		},
		{
			name: "second-nil",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(true),
			}),
			s2:             nil,
			wantEqual:      false,
			wantEqualItems: false,
		},
		{
			name: "second-empty",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}),
			s2:             NewSnapshot(map[Key]RawItem{}),
			wantEqual:      false,
			wantEqualItems: false,
		},
		{
			name: "same-items-same-order-no-scope",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name: "same-items-same-order-same-scope",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}, DeviceScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}, DeviceScope),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name: "same-items-different-order-same-scope",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}, DeviceScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting3": RawItemOf(false),
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
			}, DeviceScope),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name: "same-items-same-order-different-scope",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}, DeviceScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}, CurrentUserScope),
			wantEqual:      false,
			wantEqualItems: true,
		},
		{
			name: "different-items-same-scope",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(123),
				"Setting2": RawItemOf("String"),
				"Setting3": RawItemOf(false),
			}, DeviceScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting4": RawItemOf(2 * time.Hour),
				"Setting5": RawItemOf(VisibleByPolicy),
				"Setting6": RawItemOf(ShowChoiceByPolicy),
			}, DeviceScope),
			wantEqual:      false,
			wantEqualItems: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotEqual := tt.s1.Equal(tt.s2); gotEqual != tt.wantEqual {
				t.Errorf("WantEqual: got %v, want %v", gotEqual, tt.wantEqual)
			}
			if gotEqualItems := tt.s1.EqualItems(tt.s2); gotEqualItems != tt.wantEqualItems {
				t.Errorf("WantEqualItems: got %v, want %v", gotEqualItems, tt.wantEqualItems)
			}
		})
	}
}

func TestSnapshotString(t *testing.T) {
	tests := []struct {
		name       string
		snapshot   *Snapshot
		wantString string
	}{
		{
			name:       "nil",
			snapshot:   nil,
			wantString: "{Empty}",
		},
		{
			name:       "empty",
			snapshot:   NewSnapshot(nil),
			wantString: "{Empty}",
		},
		{
			name:       "empty-with-scope",
			snapshot:   NewSnapshot(nil, DeviceScope),
			wantString: "{Empty, Device}",
		},
		{
			name:       "empty-with-origin",
			snapshot:   NewSnapshot(nil, NewNamedOrigin("Test Policy", DeviceScope)),
			wantString: "{Empty, Test Policy (Device)}",
		},
		{
			name: "non-empty",
			snapshot: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemOf(2 * time.Hour),
				"Setting2": RawItemOf(VisibleByPolicy),
				"Setting3": RawItemOf(ShowChoiceByPolicy),
			}, NewNamedOrigin("Test Policy", DeviceScope)),
			wantString: `{Test Policy (Device)}
Setting1 = 2h0m0s
Setting2 = show
Setting3 = user-decides`,
		},
		{
			name: "non-empty-with-item-origin",
			snapshot: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemWith(42, nil, NewNamedOrigin("Test Policy", DeviceScope)),
			}),
			wantString: `Setting1 = 42 - {Test Policy (Device)}`,
		},
		{
			name: "non-empty-with-item-error",
			snapshot: NewSnapshot(map[Key]RawItem{
				"Setting1": RawItemWith(nil, NewErrorText("bang!"), nil),
			}),
			wantString: `Setting1 = Error{"bang!"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotString := tt.snapshot.String(); gotString != tt.wantString {
				t.Errorf("got %v\nwant %v", gotString, tt.wantString)
			}
		})
	}
}

func TestMarshalUnmarshalSnapshot(t *testing.T) {
	tests := []struct {
		name     string
		snapshot *Snapshot
		wantJSON string
		wantBack *Snapshot
	}{
		{
			name:     "Nil",
			snapshot: (*Snapshot)(nil),
			wantJSON: "null",
			wantBack: NewSnapshot(nil),
		},
		{
			name:     "Zero",
			snapshot: &Snapshot{},
			wantJSON: "{}",
		},
		{
			name:     "Bool/True",
			snapshot: NewSnapshot(map[Key]RawItem{"BoolPolicy": RawItemOf(true)}),
			wantJSON: `{"Settings": {"BoolPolicy": {"Value": true}}}`,
		},
		{
			name:     "Bool/False",
			snapshot: NewSnapshot(map[Key]RawItem{"BoolPolicy": RawItemOf(false)}),
			wantJSON: `{"Settings": {"BoolPolicy": {"Value": false}}}`,
		},
		{
			name:     "String/Non-Empty",
			snapshot: NewSnapshot(map[Key]RawItem{"StringPolicy": RawItemOf("StringValue")}),
			wantJSON: `{"Settings": {"StringPolicy": {"Value": "StringValue"}}}`,
		},
		{
			name:     "String/Empty",
			snapshot: NewSnapshot(map[Key]RawItem{"StringPolicy": RawItemOf("")}),
			wantJSON: `{"Settings": {"StringPolicy": {"Value": ""}}}`,
		},
		{
			name:     "Integer/NonZero",
			snapshot: NewSnapshot(map[Key]RawItem{"IntPolicy": RawItemOf(uint64(42))}),
			wantJSON: `{"Settings": {"IntPolicy": {"Value": 42}}}`,
		},
		{
			name:     "Integer/Zero",
			snapshot: NewSnapshot(map[Key]RawItem{"IntPolicy": RawItemOf(uint64(0))}),
			wantJSON: `{"Settings": {"IntPolicy": {"Value": 0}}}`,
		},
		{
			name:     "String-List",
			snapshot: NewSnapshot(map[Key]RawItem{"ListPolicy": RawItemOf([]string{"Value1", "Value2"})}),
			wantJSON: `{"Settings": {"ListPolicy": {"Value": ["Value1", "Value2"]}}}`,
		},
		{
			name: "Empty/With-Summary",
			snapshot: NewSnapshot(
				map[Key]RawItem{},
				SummaryWith(CurrentUserScope, NewNamedOrigin("TestSource", DeviceScope)),
			),
			wantJSON: `{"Summary": {"Origin": {"Name": "TestSource", "Scope": "Device"}, "Scope": "User"}}`,
		},
		{
			name: "Setting/With-Summary",
			snapshot: NewSnapshot(
				map[Key]RawItem{"PolicySetting": RawItemOf(uint64(42))},
				SummaryWith(CurrentUserScope, NewNamedOrigin("TestSource", DeviceScope)),
			),
			wantJSON: `{
					"Summary": {"Origin": {"Name": "TestSource", "Scope": "Device"}, "Scope": "User"},
					"Settings": {"PolicySetting": {"Value": 42}}
				}`,
		},
		{
			name: "Settings/With-Origins",
			snapshot: NewSnapshot(
				map[Key]RawItem{
					"SettingA": RawItemWith(uint64(42), nil, NewNamedOrigin("SourceA", DeviceScope)),
					"SettingB": RawItemWith("B", nil, NewNamedOrigin("SourceB", CurrentProfileScope)),
					"SettingC": RawItemWith(true, nil, NewNamedOrigin("SourceC", CurrentUserScope)),
				},
			),
			wantJSON: `{
					"Settings": {
						"SettingA": {"Value": 42, "Origin": {"Name": "SourceA", "Scope": "Device"}},
						"SettingB": {"Value": "B", "Origin": {"Name": "SourceB", "Scope": "Profile"}},
						"SettingC": {"Value": true, "Origin": {"Name": "SourceC", "Scope": "User"}}
					}
				}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doTest := func(t *testing.T, useJSONv2 bool) {
				var gotJSON []byte
				var err error
				if useJSONv2 {
					gotJSON, err = jsonv2.Marshal(tt.snapshot)
				} else {
					gotJSON, err = json.Marshal(tt.snapshot)
				}
				if err != nil {
					t.Fatal(err)
				}

				if got, want, equal := internal.EqualJSONForTest(t, gotJSON, []byte(tt.wantJSON)); !equal {
					t.Errorf("JSON: got %s; want %s", got, want)
				}

				gotBack := &Snapshot{}
				if useJSONv2 {
					err = jsonv2.Unmarshal(gotJSON, &gotBack)
				} else {
					err = json.Unmarshal(gotJSON, &gotBack)
				}
				if err != nil {
					t.Fatal(err)
				}

				if wantBack := cmp.Or(tt.wantBack, tt.snapshot); !gotBack.Equal(wantBack) {
					t.Errorf("Snapshot: got %+v; want %+v", gotBack, wantBack)
				}
			}

			t.Run("json", func(t *testing.T) { doTest(t, false) })
			t.Run("jsonv2", func(t *testing.T) { doTest(t, true) })
		})
	}
}
