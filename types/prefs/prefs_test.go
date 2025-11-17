// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prefs

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/google/go-cmp/cmp"
	"tailscale.com/types/views"
)

//go:generate go run tailscale.com/cmd/viewer --tags=test --type=TestPrefs,TestBundle,TestValueStruct,TestGenericStruct,TestPrefsGroup

var (
	_ jsonv2.MarshalerTo     = (*ItemView[*TestBundle, TestBundleView])(nil)
	_ jsonv2.UnmarshalerFrom = (*ItemView[*TestBundle, TestBundleView])(nil)

	_ jsonv2.MarshalerTo     = (*MapView[string, string])(nil)
	_ jsonv2.UnmarshalerFrom = (*MapView[string, string])(nil)

	_ jsonv2.MarshalerTo     = (*StructListView[*TestBundle, TestBundleView])(nil)
	_ jsonv2.UnmarshalerFrom = (*StructListView[*TestBundle, TestBundleView])(nil)

	_ jsonv2.MarshalerTo     = (*StructMapView[string, *TestBundle, TestBundleView])(nil)
	_ jsonv2.UnmarshalerFrom = (*StructMapView[string, *TestBundle, TestBundleView])(nil)
)

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

	StringStringMap Map[string, string]  `json:",omitzero"`
	IntStringMap    Map[int, string]     `json:",omitzero"`
	AddrIntMap      Map[netip.Addr, int] `json:",omitzero"`

	// Bundles are complex preferences that usually consist of
	// multiple parameters that must be configured atomically.
	Bundle1 Item[*TestBundle]             `json:",omitzero"`
	Bundle2 Item[*TestBundle]             `json:",omitzero"`
	Generic Item[*TestGenericStruct[int]] `json:",omitzero"`

	BundleList StructList[*TestBundle] `json:",omitzero"`

	StringBundleMap StructMap[string, *TestBundle]     `json:",omitzero"`
	IntBundleMap    StructMap[int, *TestBundle]        `json:",omitzero"`
	AddrBundleMap   StructMap[netip.Addr, *TestBundle] `json:",omitzero"`

	// Group is a nested struct that contains one or more preferences.
	// Each preference in a group can be configured individually.
	// Preference groups should be included directly rather than by pointers.
	Group TestPrefsGroup `json:",omitzero"`
}

var (
	_ jsonv2.MarshalerTo     = (*TestPrefs)(nil)
	_ jsonv2.UnmarshalerFrom = (*TestPrefs)(nil)
)

// MarshalJSONTo implements [jsonv2.MarshalerTo].
func (p TestPrefs) MarshalJSONTo(out *jsontext.Encoder) error {
	// The testPrefs type shadows the TestPrefs's method set,
	// causing jsonv2 to use the default marshaler and avoiding
	// infinite recursion.
	type testPrefs TestPrefs
	return jsonv2.MarshalEncode(out, (*testPrefs)(&p))
}

// UnmarshalJSONFrom implements [jsonv2.UnmarshalerFrom].
func (p *TestPrefs) UnmarshalJSONFrom(in *jsontext.Decoder) error {
	// The testPrefs type shadows the TestPrefs's method set,
	// causing jsonv2 to use the default unmarshaler and avoiding
	// infinite recursion.
	type testPrefs TestPrefs
	return jsonv2.UnmarshalDecode(in, (*testPrefs)(p))
}

// MarshalJSON implements [json.Marshaler].
func (p TestPrefs) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(p) // uses MarshalJSONTo
}

// UnmarshalJSON implements [json.Unmarshaler].
func (p *TestPrefs) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, p) // uses UnmarshalJSONFrom
}

// TestBundle is an example structure type that,
// despite containing multiple values, represents
// a single configurable preference item.
type TestBundle struct {
	Name   string           `json:",omitzero"`
	Nested *TestValueStruct `json:",omitzero"`
}

func (b *TestBundle) Equal(b2 *TestBundle) bool {
	if b == b2 {
		return true
	}
	if b == nil || b2 == nil {
		return false
	}
	return b.Name == b2.Name && b.Nested.Equal(b2.Nested)
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

func (s *TestValueStruct) Equal(s2 *TestValueStruct) bool {
	if s == s2 {
		return true
	}
	if s == nil || s2 == nil {
		return false
	}
	return *s == *s2
}

type TestGenericStruct[T ImmutableType] struct {
	Value T
}

func (s *TestGenericStruct[T]) Equal(s2 *TestGenericStruct[T]) bool {
	if s == s2 {
		return true
	}
	if s == nil || s2 == nil {
		return false
	}
	return *s == *s2
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
			name:  "string-string-map",
			prefs: &TestPrefs{StringStringMap: MapOf(map[string]string{"K1": "V1"})},
			want:  `{"StringStringMap": {"Value": {"K1": "V1"}}}`,
		},
		{
			name:  "int-string-map",
			prefs: &TestPrefs{IntStringMap: MapOf(map[int]string{42: "V1"})},
			want:  `{"IntStringMap": {"Value": {"42": "V1"}}}`,
		},
		{
			name:  "addr-int-map",
			prefs: &TestPrefs{AddrIntMap: MapOf(map[netip.Addr]int{netip.MustParseAddr("127.0.0.1"): 42})},
			want:  `{"AddrIntMap": {"Value": {"127.0.0.1": 42}}}`,
		},
		{
			name:  "bundle-list",
			prefs: &TestPrefs{BundleList: StructListOf([]*TestBundle{{Name: "Bundle1"}, {Name: "Bundle2"}})},
			want:  `{"BundleList": {"Value": [{"Name": "Bundle1"},{"Name": "Bundle2"}]}}`,
		},
		{
			name: "string-bundle-map",
			prefs: &TestPrefs{StringBundleMap: StructMapOf(map[string]*TestBundle{
				"K1": {Name: "Bundle1"},
				"K2": {Name: "Bundle2"},
			})},
			want: `{"StringBundleMap": {"Value": {"K1": {"Name": "Bundle1"}, "K2": {"Name": "Bundle2"}}}}`,
		},
		{
			name:  "int-bundle-map",
			prefs: &TestPrefs{IntBundleMap: StructMapOf(map[int]*TestBundle{42: {Name: "Bundle1"}})},
			want:  `{"IntBundleMap": {"Value": {"42": {"Name": "Bundle1"}}}}`,
		},
		{
			name:  "addr-bundle-map",
			prefs: &TestPrefs{AddrBundleMap: StructMapOf(map[netip.Addr]*TestBundle{netip.MustParseAddr("127.0.0.1"): {Name: "Bundle1"}})},
			want:  `{"AddrBundleMap": {"Value": {"127.0.0.1": {"Name": "Bundle1"}}}}`,
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
			name: "various",
			prefs: &TestPrefs{
				Int32Item:       ItemOf[int32](101),
				UInt64Item:      ItemOf[uint64](42),
				StringItem1:     ItemOf("Value1"),
				StringItem2:     ItemWithOpts[string](ReadOnly),
				BoolItem1:       ItemOf(true),
				BoolItem2:       ItemOf(false, Managed),
				StringSlice:     ListOf([]string{"1", "2", "3"}),
				IntSlice:        ListOf([]int{4, 8, 15, 16, 23}, Managed),
				AddrItem:        ItemOf(netip.MustParseAddr("127.0.0.1")),
				StringStringMap: MapOf(map[string]string{"K1": "V1"}),
				IntStringMap:    MapOf(map[int]string{42: "V1"}),
				AddrIntMap:      MapOf(map[netip.Addr]int{netip.MustParseAddr("127.0.0.1"): 42}),
				BundleList:      StructListOf([]*TestBundle{{Name: "Bundle1"}}),
				StringBundleMap: StructMapOf(map[string]*TestBundle{"K1": {Name: "Bundle1"}}),
				IntBundleMap:    StructMapOf(map[int]*TestBundle{42: {Name: "Bundle1"}}),
				AddrBundleMap:   StructMapOf(map[netip.Addr]*TestBundle{netip.MustParseAddr("127.0.0.1"): {Name: "Bundle1"}}),
				Bundle1:         ItemOf(&TestBundle{Name: "Bundle1"}),
				Bundle2:         ItemOf(&TestBundle{Name: "Bundle2", Nested: &TestValueStruct{Value: 17}}, Managed),
				Group: TestPrefsGroup{
					FloatItem:      ItemOf(1.618),
					TestStringItem: ItemOf(TestStringType("Value")),
				},
			},
			want: `{
				"Int32Item":       {"Value": 101},
				"UInt64Item":      {"Value": 42},
				"StringItem1":     {"Value": "Value1"},
				"StringItem2":     {"ReadOnly": true},
				"BoolItem1":       {"Value": true},
				"BoolItem2":       {"Value": false, "Managed": true},
				"StringSlice":     {"Value": ["1", "2", "3"]},
				"IntSlice":        {"Value": [4, 8, 15, 16, 23], "Managed": true},
				"AddrItem":        {"Value": "127.0.0.1"},
				"StringStringMap": {"Value": {"K1": "V1"}},
				"IntStringMap":    {"Value": {"42": "V1"}},
				"AddrIntMap":      {"Value": {"127.0.0.1": 42}},
				"BundleList":      {"Value": [{"Name": "Bundle1"}]},
				"StringBundleMap": {"Value": {"K1": {"Name": "Bundle1"}}},
				"IntBundleMap":    {"Value": {"42": {"Name": "Bundle1"}}},
				"AddrBundleMap":   {"Value": {"127.0.0.1": {"Name": "Bundle1"}}},
				"Bundle1":         {"Value": {"Name": "Bundle1"}},
				"Bundle2":         {"Value": {"Name": "Bundle2", "Nested": {"Value": 17}}, "Managed": true},
				"Group":           {
				                       "FloatItem":      {"Value": 1.618},
									   "TestStringItem": {"Value": "Value"}
								   }
			}`,
		},
	}

	arshalers := []struct {
		name      string
		marshal   func(in any) (out []byte, err error)
		unmarshal func(in []byte, out any) (err error)
	}{
		{
			name:      "json",
			marshal:   json.Marshal,
			unmarshal: json.Unmarshal,
		},
		{
			name:      "jsonv2",
			marshal:   func(in any) (out []byte, err error) { return jsonv2.Marshal(in) },
			unmarshal: func(in []byte, out any) (err error) { return jsonv2.Unmarshal(in, out) },
		},
	}

	for _, a := range arshalers {
		t.Run(a.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					t.Run("marshal-directly", func(t *testing.T) {
						gotJSON, err := a.marshal(tt.prefs)
						if err != nil {
							t.Fatalf("marshalling failed: %v", err)
						}

						checkJSON(t, gotJSON, jsontext.Value(tt.want))

						var gotPrefs TestPrefs
						if err = a.unmarshal(gotJSON, &gotPrefs); err != nil {
							t.Fatalf("unmarshalling failed: %v", err)
						}

						if diff := cmp.Diff(tt.prefs, &gotPrefs); diff != "" {
							t.Errorf("mismatch (-want +got):\n%s", diff)
						}
					})

					t.Run("marshal-via-view", func(t *testing.T) {
						gotJSON, err := a.marshal(tt.prefs.View())
						if err != nil {
							t.Fatalf("marshalling failed: %v", err)
						}

						checkJSON(t, gotJSON, jsontext.Value(tt.want))

						var gotPrefs TestPrefsView
						if err = a.unmarshal(gotJSON, &gotPrefs); err != nil {
							t.Fatalf("unmarshalling failed: %v", err)
						}

						if diff := cmp.Diff(tt.prefs, gotPrefs.AsStruct()); diff != "" {
							t.Errorf("mismatch (-want +got):\n%s", diff)
						}
					})
				})
			}
		})
	}
}

func TestPreferenceStates(t *testing.T) {
	const (
		zeroValue = 0
		defValue  = 5
		userValue = 42
		mdmValue  = 1001
	)
	i := ItemWithOpts[int]()
	checkIsSet(t, &i, false)
	checkIsManaged(t, &i, false)
	checkIsReadOnly(t, &i, false)
	checkValueOk(t, &i, zeroValue, false)

	i.SetDefaultValue(defValue)
	checkValue(t, &i, defValue)
	checkValueOk(t, &i, defValue, false)

	checkSetValue(t, &i, userValue)
	checkValue(t, &i, userValue)
	checkValueOk(t, &i, userValue, true)

	i2 := ItemOf(userValue)
	checkIsSet(t, &i2, true)
	checkValue(t, &i2, userValue)
	checkValueOk(t, &i2, userValue, true)
	checkEqual(t, i2, i, true)

	i2.SetManagedValue(mdmValue)
	// Setting a managed value should set the value, mark the preference
	// as managed and read-only, and prevent it from being modified with SetValue.
	checkIsSet(t, &i2, true)
	checkIsManaged(t, &i2, true)
	checkIsReadOnly(t, &i2, true)
	checkValue(t, &i2, mdmValue)
	checkValueOk(t, &i2, mdmValue, true)
	checkCanNotSetValue(t, &i2, userValue, ErrManaged)
	checkValue(t, &i2, mdmValue) // the value must not be changed
	checkCanNotClearValue(t, &i2, ErrManaged)

	i2.ClearManaged()
	// Clearing the managed flag should change the IsManaged and IsReadOnly flags...
	checkIsManaged(t, &i2, false)
	checkIsReadOnly(t, &i2, false)
	// ...but not the value.
	checkValue(t, &i2, mdmValue)

	// We should be able to change the value after clearing the managed flag.
	checkSetValue(t, &i2, userValue)
	checkIsSet(t, &i2, true)
	checkValue(t, &i2, userValue)
	checkValueOk(t, &i2, userValue, true)
	checkEqual(t, i2, i, true)

	i2.SetReadOnly(true)
	checkIsReadOnly(t, &i2, true)
	checkIsManaged(t, &i2, false)
	checkCanNotSetValue(t, &i2, userValue, ErrReadOnly)
	checkCanNotClearValue(t, &i2, ErrReadOnly)

	i2.SetReadOnly(false)
	i2.SetDefaultValue(defValue)
	checkClearValue(t, &i2)
	checkIsSet(t, &i2, false)
	checkValue(t, &i2, defValue)
	checkValueOk(t, &i2, defValue, false)
}

func TestItemView(t *testing.T) {
	i := ItemOf(&TestBundle{Name: "B1"})

	iv := ItemViewOf(&i)
	checkIsSet(t, iv, true)
	checkIsManaged(t, iv, false)
	checkIsReadOnly(t, iv, false)
	checkValue(t, iv, TestBundleView{i.Value()})
	checkValueOk(t, iv, TestBundleView{i.Value()}, true)

	i2 := *iv.AsStruct()
	checkEqual(t, i, i2, true)
	i2.SetValue(&TestBundle{Name: "B2"})

	iv2 := ItemViewOf(&i2)
	checkEqual(t, iv, iv2, false)
}

func TestListView(t *testing.T) {
	ls := ListOf([]int{4, 8, 15, 16, 23, 42}, ReadOnly)

	lv := ls.View()
	checkIsSet(t, lv, true)
	checkIsManaged(t, lv, false)
	checkIsReadOnly(t, lv, true)
	checkValue(t, lv, views.SliceOf(ls.Value()))
	checkValueOk(t, lv, views.SliceOf(ls.Value()), true)

	l2 := *lv.AsStruct()
	checkEqual(t, ls, l2, true)
}

func TestStructListView(t *testing.T) {
	ls := StructListOf([]*TestBundle{{Name: "E1"}, {Name: "E2"}}, ReadOnly)

	lv := StructListViewOf(&ls)
	checkIsSet(t, lv, true)
	checkIsManaged(t, lv, false)
	checkIsReadOnly(t, lv, true)
	checkValue(t, lv, views.SliceOfViews(ls.Value()))
	checkValueOk(t, lv, views.SliceOfViews(ls.Value()), true)

	l2 := *lv.AsStruct()
	checkEqual(t, ls, l2, true)
}

func TestStructMapView(t *testing.T) {
	m := StructMapOf(map[string]*TestBundle{
		"K1": {Name: "E1"},
		"K2": {Name: "E2"},
	}, ReadOnly)

	mv := StructMapViewOf(&m)
	checkIsSet(t, mv, true)
	checkIsManaged(t, mv, false)
	checkIsReadOnly(t, mv, true)
	checkValue(t, *mv.AsStruct(), m.Value())
	checkValueOk(t, *mv.AsStruct(), m.Value(), true)

	m2 := *mv.AsStruct()
	checkEqual(t, m, m2, true)
}

// check that the preference types implement the test [pref] interface.
var (
	_ pref[int]                    = (*Item[int])(nil)
	_ pref[*TestBundle]            = (*Item[*TestBundle])(nil)
	_ pref[[]int]                  = (*List[int])(nil)
	_ pref[[]*TestBundle]          = (*StructList[*TestBundle])(nil)
	_ pref[map[string]*TestBundle] = (*StructMap[string, *TestBundle])(nil)
)

// pref is an interface used by [checkSetValue], [checkClearValue], and similar test
// functions that mutate preferences. It is implemented by all preference types, such
// as [Item], [List], [StructList], and [StructMap], and provides both read and write
// access to the preference's value and state.
type pref[T any] interface {
	prefView[T]
	SetValue(v T) error
	ClearValue() error
	SetDefaultValue(v T)
	SetManagedValue(v T)
	ClearManaged()
	SetReadOnly(readonly bool)
}

// check that the preference view types implement the test [prefView] interface.
var (
	_ prefView[int]                                              = (*Item[int])(nil)
	_ prefView[TestBundleView]                                   = (*ItemView[*TestBundle, TestBundleView])(nil)
	_ prefView[views.Slice[int]]                                 = (*ListView[int])(nil)
	_ prefView[views.SliceView[*TestBundle, TestBundleView]]     = (*StructListView[*TestBundle, TestBundleView])(nil)
	_ prefView[views.MapFn[string, *TestBundle, TestBundleView]] = (*StructMapView[string, *TestBundle, TestBundleView])(nil)
)

// prefView is an interface used by [checkIsSet], [checkIsManaged], and similar non-mutating
// test functions. It is implemented by all preference types, such as [Item], [List], [StructList],
// and [StructMap], as well as their corresponding views, such as [ItemView], [ListView], [StructListView],
// and [StructMapView], and provides read-only access to the preference's value and state.
type prefView[T any] interface {
	IsSet() bool
	Value() T
	ValueOk() (T, bool)
	DefaultValue() T
	IsManaged() bool
	IsReadOnly() bool
}

func checkIsSet[T any](tb testing.TB, p prefView[T], wantSet bool) {
	tb.Helper()
	if gotSet := p.IsSet(); gotSet != wantSet {
		tb.Errorf("IsSet: got %v; want %v", gotSet, wantSet)
	}
}

func checkIsManaged[T any](tb testing.TB, p prefView[T], wantManaged bool) {
	tb.Helper()
	if gotManaged := p.IsManaged(); gotManaged != wantManaged {
		tb.Errorf("IsManaged: got %v; want %v", gotManaged, wantManaged)
	}
}

func checkIsReadOnly[T any](tb testing.TB, p prefView[T], wantReadOnly bool) {
	tb.Helper()
	if gotReadOnly := p.IsReadOnly(); gotReadOnly != wantReadOnly {
		tb.Errorf("IsReadOnly: got %v; want %v", gotReadOnly, wantReadOnly)
	}
}

func checkValue[T any](tb testing.TB, p prefView[T], wantValue T) {
	tb.Helper()
	if gotValue := p.Value(); !testComparerFor[T]()(gotValue, wantValue) {
		tb.Errorf("Value: got %v; want %v", gotValue, wantValue)
	}
}

func checkValueOk[T any](tb testing.TB, p prefView[T], wantValue T, wantOk bool) {
	tb.Helper()
	gotValue, gotOk := p.ValueOk()

	if gotOk != wantOk || !testComparerFor[T]()(gotValue, wantValue) {
		tb.Errorf("ValueOk: got (%v, %v); want (%v, %v)", gotValue, gotOk, wantValue, wantOk)
	}
}

func checkEqual[T equatable[T]](tb testing.TB, a, b T, wantEqual bool) {
	tb.Helper()
	if gotEqual := a.Equal(b); gotEqual != wantEqual {
		tb.Errorf("Equal: got %v; want %v", gotEqual, wantEqual)
	}
}

func checkSetValue[T any](tb testing.TB, p pref[T], v T) {
	tb.Helper()
	if err := p.SetValue(v); err != nil {
		tb.Fatalf("SetValue: gotErr %v, wantErr: nil", err)
	}
}

func checkCanNotSetValue[T any](tb testing.TB, p pref[T], v T, wantErr error) {
	tb.Helper()
	if err := p.SetValue(v); err == nil || !errors.Is(err, wantErr) {
		tb.Fatalf("SetValue: gotErr %v, wantErr: %v", err, wantErr)
	}
}

func checkClearValue[T any](tb testing.TB, p pref[T]) {
	tb.Helper()
	if err := p.ClearValue(); err != nil {
		tb.Fatalf("ClearValue: gotErr %v, wantErr: nil", err)
	}
}

func checkCanNotClearValue[T any](tb testing.TB, p pref[T], wantErr error) {
	tb.Helper()
	err := p.ClearValue()
	if err == nil || !errors.Is(err, wantErr) {
		tb.Fatalf("ClearValue: gotErr %v, wantErr: %v", err, wantErr)
	}
}

// testComparerFor is like [comparerFor], but uses [reflect.DeepEqual]
// unless T is [equatable].
func testComparerFor[T any]() func(a, b T) bool {
	return func(a, b T) bool {
		switch a := any(a).(type) {
		case equatable[T]:
			return a.Equal(b)
		default:
			return reflect.DeepEqual(a, b)
		}
	}
}

func checkJSON(tb testing.TB, got, want jsontext.Value) {
	tb.Helper()
	got = got.Clone()
	want = want.Clone()
	// Compare canonical forms.
	if err := got.Canonicalize(); err != nil {
		tb.Error(err)
	}
	if err := want.Canonicalize(); err != nil {
		tb.Error(err)
	}
	if bytes.Equal(got, want) {
		return
	}

	gotMap := make(map[string]any)
	if err := jsonv2.Unmarshal(got, &gotMap); err != nil {
		tb.Fatal(err)
	}
	wantMap := make(map[string]any)
	if err := jsonv2.Unmarshal(want, &wantMap); err != nil {
		tb.Fatal(err)
	}
	tb.Errorf("mismatch (-want +got):\n%s", cmp.Diff(wantMap, gotMap))
}
