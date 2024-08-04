// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import (
	"testing"
	"time"
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
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}),
		},
		{
			name: "first-empty",
			s1:   NewSnapshot(map[Key]RawItem{}),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
		},
		{
			name: "second-nil",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}),
			s2: nil,
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}),
		},
		{
			name: "second-empty",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			s2: NewSnapshot(map[Key]RawItem{}),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
		},
		{
			name: "no-conflicts",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting4": {value: 2 * time.Hour},
				"Setting5": {value: VisibleByPolicy},
				"Setting6": {value: ShowChoiceByPolicy},
			}),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
				"Setting4": {value: 2 * time.Hour},
				"Setting5": {value: VisibleByPolicy},
				"Setting6": {value: ShowChoiceByPolicy},
			}),
		},
		{
			name: "with-conflicts",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 456},
				"Setting3": {value: false},
				"Setting4": {value: 2 * time.Hour},
			}),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 456},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
				"Setting4": {value: 2 * time.Hour},
			}),
		},
		{
			name: "with-scope-first-wins",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}, DeviceScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 456},
				"Setting3": {value: false},
				"Setting4": {value: 2 * time.Hour},
			}, CurrentUserScope),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
				"Setting4": {value: 2 * time.Hour},
			}, CurrentUserScope),
		},
		{
			name: "with-scope-second-wins",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}, CurrentUserScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 456},
				"Setting3": {value: false},
				"Setting4": {value: 2 * time.Hour},
			}, DeviceScope),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 456},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
				"Setting4": {value: 2 * time.Hour},
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
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true}},
				DeviceScope, NewNamedOrigin("TestPolicy", DeviceScope)),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}, CurrentUserScope, NewNamedOrigin("TestPolicy", DeviceScope)),
		},
		{
			name: "with-scope-second-empty",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}, CurrentUserScope),
			s2: NewSnapshot(map[Key]RawItem{}),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
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
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			wantEqual:      false,
			wantEqualItems: false,
		},
		{
			name: "first-empty",
			s1:   NewSnapshot(map[Key]RawItem{}),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			wantEqual:      false,
			wantEqualItems: false,
		},
		{
			name: "second-nil",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}),
			s2:             nil,
			wantEqual:      false,
			wantEqualItems: false,
		},
		{
			name: "second-empty",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			s2:             NewSnapshot(map[Key]RawItem{}),
			wantEqual:      false,
			wantEqualItems: false,
		},
		{
			name: "same-items-same-order-no-scope",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name: "same-items-same-order-same-scope",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}, DeviceScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}, DeviceScope),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name: "same-items-different-order-same-scope",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}, DeviceScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting3": {value: false},
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
			}, DeviceScope),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name: "same-items-same-order-different-scope",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}, DeviceScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}, CurrentUserScope),
			wantEqual:      false,
			wantEqualItems: true,
		},
		{
			name: "different-items-same-scope",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}, DeviceScope),
			s2: NewSnapshot(map[Key]RawItem{
				"Setting4": {value: 2 * time.Hour},
				"Setting5": {value: VisibleByPolicy},
				"Setting6": {value: ShowChoiceByPolicy},
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
				"Setting1": {value: 2 * time.Hour},
				"Setting2": {value: VisibleByPolicy},
				"Setting3": {value: ShowChoiceByPolicy},
			}, NewNamedOrigin("Test Policy", DeviceScope)),
			wantString: `{Test Policy (Device)}
Setting1 = 2h0m0s
Setting2 = show
Setting3 = user-decides`,
		},
		{
			name: "non-empty-with-item-origin",
			snapshot: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 42, origin: NewNamedOrigin("Test Policy", DeviceScope)},
			}),
			wantString: `Setting1 = 42 - {Test Policy (Device)}`,
		},
		{
			name: "non-empty-with-item-error",
			snapshot: NewSnapshot(map[Key]RawItem{
				"Setting1": {err: NewErrorText("bang!")},
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
