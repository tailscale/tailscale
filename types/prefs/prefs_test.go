// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prefs

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
)

//go:generate go run tailscale.com/cmd/viewer --tags=test --type=TestPrefs,TestBundle,TestValueStruct,TestGenericStruct,TestPrefsGroup

type TestPrefs struct {
	Int32Item   Item[int32]  `json:",omitzero"`
	UInt64Item  Item[uint64] `json:",omitzero"`
	StringItem1 Item[string] `json:",omitzero"`
	StringItem2 Item[string] `json:",omitzero"`
	BoolItem1   Item[bool]   `json:",omitzero"`
	BoolItem2   Item[bool]   `json:",omitzero"`
	StringSlice List[string] `json:",omitzero"`
	IntSlice    List[int]    `json:",omitzero"`

	AddrItem Item[netip.Addr] `json:",omitzero"`

	// Bundles are complex preferences that usually consist of
	// multiple parameters that must be configured atomically.
	Bundle1 Item[*TestBundle]             `json:",omitzero"`
	Bundle2 Item[*TestBundle]             `json:",omitzero"`
	Generic Item[*TestGenericStruct[int]] `json:",omitzero"`

	// Group is a nested struct that contains one or more preferences.
	// Each preference in a group can be configured individually.
	// Preference groups should be included directly rather than by pointers.
	Group TestPrefsGroup `json:",omitzero"`
}

// TestBundle is an example structure type that,
// despite containing multiple values, represents
// a single configurable preference item.
type TestBundle struct {
	Name   string           `json:",omitzero"`
	Nested *TestValueStruct `json:",omitzero"`
}

// TestPrefsGroup contains logically grouped preference items.
// Each preference item in a group can be configured individually.
type TestPrefsGroup struct {
	FloatItem Item[float64] `json:",omitzero"`

	TestStringItem Item[TestStringType] `json:",omitzero"`
}

type TestValueStruct struct {
	Value int
}

type TestGenericStruct[T ImmutableType] struct {
	Value T
}

type TestStringType string

func TestMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name   string
		prefs  *TestPrefs
		indent bool
		want   string
	}{
		{
			name:  "string",
			prefs: &TestPrefs{StringItem1: ItemOf("Value1")},
			want:  `{"StringItem1": {"Value": "Value1"}}`,
		},
		{
			name:  "empty-string",
			prefs: &TestPrefs{StringItem1: ItemOf("")},
			want:  `{"StringItem1": {"Value": ""}}`,
		},
		{
			name:  "managed-string",
			prefs: &TestPrefs{StringItem1: ItemOf("Value1", Managed)},
			want:  `{"StringItem1": {"Value": "Value1", "Managed": true}}`,
		},
		{
			name:  "readonly-item",
			prefs: &TestPrefs{StringItem1: ItemWithOpts[string](ReadOnly)},
			want:  `{"StringItem1": {"ReadOnly": true}}`,
		},
		{
			name:  "readonly-item-with-value",
			prefs: &TestPrefs{StringItem1: ItemOf("RO", ReadOnly)},
			want:  `{"StringItem1": {"Value": "RO", "ReadOnly": true}}`,
		},
		{
			name:  "int32",
			prefs: &TestPrefs{Int32Item: ItemOf[int32](101)},
			want:  `{"Int32Item": {"Value": 101}}`,
		},
		{
			name:  "uint64",
			prefs: &TestPrefs{UInt64Item: ItemOf[uint64](42)},
			want:  `{"UInt64Item": {"Value": 42}}`,
		},
		{
			name:  "bool-true",
			prefs: &TestPrefs{BoolItem1: ItemOf(true)},
			want:  `{"BoolItem1": {"Value": true}}`,
		},
		{
			name:  "bool-false",
			prefs: &TestPrefs{BoolItem1: ItemOf(false)},
			want:  `{"BoolItem1": {"Value": false}}`,
		},
		{
			name:  "empty-slice",
			prefs: &TestPrefs{StringSlice: ListOf([]string{})},
			want:  `{"StringSlice": {"Value": []}}`,
		},
		{
			name:  "string-slice",
			prefs: &TestPrefs{StringSlice: ListOf([]string{"1", "2", "3"})},
			want:  `{"StringSlice": {"Value": ["1", "2", "3"]}}`,
		},
		{
			name:  "int-slice",
			prefs: &TestPrefs{IntSlice: ListOf([]int{4, 8, 15, 16, 23})},
			want:  `{"IntSlice": {"Value": [4, 8, 15, 16, 23]}}`,
		},
		{
			name:  "managed-int-slice",
			prefs: &TestPrefs{IntSlice: ListOf([]int{4, 8, 15, 16, 23}, Managed)},
			want:  `{"IntSlice": {"Value": [4, 8, 15, 16, 23], "Managed": true}}`,
		},
		{
			name:  "netip-addr",
			prefs: &TestPrefs{AddrItem: ItemOf(netip.MustParseAddr("127.0.0.1"))},
			want:  `{"AddrItem": {"Value": "127.0.0.1"}}`,
		},
		{
			name:  "bundle",
			prefs: &TestPrefs{Bundle1: ItemOf(&TestBundle{Name: "Bundle1"})},
			want:  `{"Bundle1": {"Value": {"Name": "Bundle1"}}}`,
		},
		{
			name:  "managed-bundle",
			prefs: &TestPrefs{Bundle2: ItemOf(&TestBundle{Name: "Bundle2", Nested: &TestValueStruct{Value: 17}}, Managed)},
			want:  `{"Bundle2": {"Value": {"Name": "Bundle2", "Nested": {"Value": 17}}, "Managed": true}}`,
		},
		{
			name:  "subgroup",
			prefs: &TestPrefs{Group: TestPrefsGroup{FloatItem: ItemOf(1.618), TestStringItem: ItemOf(TestStringType("Value"))}},
			want:  `{"Group": {"FloatItem": {"Value": 1.618}, "TestStringItem": {"Value": "Value"}}}`,
		},
		{
			name: "all",
			prefs: &TestPrefs{
				Int32Item:   ItemOf[int32](101),
				UInt64Item:  ItemOf[uint64](42),
				StringItem1: ItemOf("Value1"),
				StringItem2: ItemWithOpts[string](ReadOnly),
				BoolItem1:   ItemOf(true),
				BoolItem2:   ItemOf(false, Managed),
				StringSlice: ListOf([]string{"1", "2", "3"}),
				IntSlice:    ListOf([]int{4, 8, 15, 16, 23}, Managed),
				AddrItem:    ItemOf(netip.MustParseAddr("127.0.0.1")),
				Bundle1:     ItemOf(&TestBundle{Name: "Bundle1"}),
				Bundle2:     ItemOf(&TestBundle{Name: "Bundle2", Nested: &TestValueStruct{Value: 17}}, Managed),
				Group: TestPrefsGroup{
					FloatItem:      ItemOf(1.618),
					TestStringItem: ItemOf(TestStringType("Value")),
				},
			},
			want: `{
				"Int32Item":    {"Value": 101},
				"UInt64Item":   {"Value": 42},
				"StringItem1":  {"Value": "Value1"},
				"StringItem2":  {"ReadOnly": true},
				"BoolItem1":    {"Value": true},
				"BoolItem2":    {"Value": false, "Managed": true},
				"StringSlice":  {"Value": ["1", "2", "3"]},
				"IntSlice":     {"Value": [4, 8, 15, 16, 23], "Managed": true},
				"AddrItem":     {"Value": "127.0.0.1"},
				"Bundle1":      {"Value": {"Name": "Bundle1"}},
				"Bundle2":      {"Value": {"Name": "Bundle2", "Nested": {"Value": 17}}, "Managed": true},
				"Group":        {
				                    "FloatItem":      {"Value": 1.618},
									"TestStringItem": {"Value": "Value"}
								}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wantJSON bytes.Buffer
			if err := json.Compact(&wantJSON, []byte(tt.want)); err != nil {
				t.Fatalf("failed to compact %s: %v", tt.want, err)
			}

			gotJSON, err := MarshalJSON(tt.prefs)
			if err != nil {
				t.Fatalf("marshalling failed: %v", err)
			}

			if want := wantJSON.Bytes(); !bytes.Equal(gotJSON, want) {
				t.Errorf("got %v; want %v", string(gotJSON), string(want))
			}

			var gotPrefs TestPrefs
			if err = UnmarshalJSON(gotJSON, &gotPrefs); err != nil {
				t.Fatalf("unmarshalling failed: %v", err)
			}

			if !reflect.DeepEqual(&gotPrefs, tt.prefs) {
				t.Errorf("got %+v; want %+v", gotPrefs, tt.prefs)
			}
		})
	}

}

func BenchmarkMarshal(b *testing.B) {
	tests := []struct {
		name  string
		prefs *TestPrefs
	}{
		{
			name:  "empty",
			prefs: &TestPrefs{},
		},
		{
			name: "some",
			prefs: &TestPrefs{
				Int32Item:   ItemOf[int32](101),
				UInt64Item:  ItemOf[uint64](42),
				BoolItem1:   ItemOf(true),
				BoolItem2:   ItemOf(false, Managed),
				StringItem2: ItemWithOpts[string](ReadOnly),
			},
		},
		{
			name: "all",
			prefs: &TestPrefs{
				Int32Item:   ItemOf[int32](101),
				UInt64Item:  ItemOf[uint64](42),
				StringItem1: ItemOf("Value1"),
				StringItem2: ItemWithOpts[string](ReadOnly),
				BoolItem1:   ItemOf(true),
				BoolItem2:   ItemOf(false, Managed),
				StringSlice: ListOf([]string{"1", "2", "3"}),
				IntSlice:    ListOf([]int{4, 8, 15, 16, 23}, Managed),
				AddrItem:    ItemOf(netip.MustParseAddr("127.0.0.1")),
				Bundle1:     ItemOf(&TestBundle{Name: "Bundle1"}),
				Bundle2:     ItemOf(&TestBundle{Name: "Bundle2", Nested: &TestValueStruct{Value: 17}}, Managed),
				Group: TestPrefsGroup{
					FloatItem:      ItemOf(1.618),
					TestStringItem: ItemOf(TestStringType("Value")),
				},
			},
		},
	}

	for _, tt := range tests {
		b.Run(tt.name+"-marshal", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := MarshalJSON(tt.prefs); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(tt.name+"-unmarshal", func(b *testing.B) {
			j, err := MarshalJSON(tt.prefs)
			if err != nil {
				b.Fatal(err)
			}
			testPrefs := &TestPrefs{}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				*testPrefs = TestPrefs{}
				if err := UnmarshalJSON(j, tt.prefs); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
