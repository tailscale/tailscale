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
				"Setting3": {value: true}}, DeviceScope),
			want: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}, CurrentUserScope),
		},
		{
			name: "with-scope-second-empty",
			s1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}, CurrentUserScope),
			s2: NewSnapshot(map[Key]RawItem{}, DeviceScope),
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
		b1, b2         *Snapshot
		wantEqual      bool
		wantEqualItems bool
	}{
		{
			name:           "nil-nil",
			b1:             nil,
			b2:             nil,
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name:           "nil-empty",
			b1:             nil,
			b2:             NewSnapshot(map[Key]RawItem{}),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name:           "empty-nil",
			b1:             NewSnapshot(map[Key]RawItem{}),
			b2:             nil,
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name:           "empty-empty",
			b1:             NewSnapshot(map[Key]RawItem{}),
			b2:             NewSnapshot(map[Key]RawItem{}),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name: "first-nil",
			b1:   nil,
			b2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			wantEqual:      false,
			wantEqualItems: false,
		},
		{
			name: "first-empty",
			b1:   NewSnapshot(map[Key]RawItem{}),
			b2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			wantEqual:      false,
			wantEqualItems: false,
		},
		{
			name: "second-nil",
			b1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: true},
			}),
			b2:             nil,
			wantEqual:      false,
			wantEqualItems: false,
		},
		{
			name: "second-empty",
			b1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			b2:             NewSnapshot(map[Key]RawItem{}),
			wantEqual:      false,
			wantEqualItems: false,
		},
		{
			name: "same-items-same-order-no-scope",
			b1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			b2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name: "same-items-same-order-same-scope",
			b1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}, DeviceScope),
			b2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}, DeviceScope),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name: "same-items-different-order-same-scope",
			b1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}, DeviceScope),
			b2: NewSnapshot(map[Key]RawItem{
				"Setting3": {value: false},
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
			}, DeviceScope),
			wantEqual:      true,
			wantEqualItems: true,
		},
		{
			name: "same-items-same-order-different-scope",
			b1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}, DeviceScope),
			b2: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}, CurrentUserScope),
			wantEqual:      false,
			wantEqualItems: true,
		},
		{
			name: "different-items-same-scope",
			b1: NewSnapshot(map[Key]RawItem{
				"Setting1": {value: 123},
				"Setting2": {value: "String"},
				"Setting3": {value: false},
			}, DeviceScope),
			b2: NewSnapshot(map[Key]RawItem{
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
			if gotEqual := tt.b1.Equal(tt.b2); gotEqual != tt.wantEqual {
				t.Errorf("WantEqual: got %v, want %v", gotEqual, tt.wantEqual)
			}
			if gotEqualItems := tt.b1.EqualItems(tt.b2); gotEqualItems != tt.wantEqualItems {
				t.Errorf("WantEqualItems: got %v, want %v", gotEqualItems, tt.wantEqualItems)
			}
		})
	}
}
