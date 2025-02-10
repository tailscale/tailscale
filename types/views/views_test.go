// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package views

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unsafe"

	qt "github.com/frankban/quicktest"
	"tailscale.com/types/structs"
)

type viewStruct struct {
	Int        int
	Addrs      Slice[netip.Prefix]
	Strings    Slice[string]
	AddrsPtr   *Slice[netip.Prefix] `json:",omitempty"`
	StringsPtr *Slice[string]       `json:",omitempty"`
}

type noPtrStruct struct {
	Int int
	Str string
}

type withPtrStruct struct {
	Int    int
	StrPtr *string
}

func BenchmarkSliceIteration(b *testing.B) {
	var data []viewStruct
	for i := range 10000 {
		data = append(data, viewStruct{Int: i})
	}
	b.ResetTimer()
	b.Run("Len", func(b *testing.B) {
		b.ReportAllocs()
		dv := SliceOf(data)
		for it := 0; it < b.N; it++ {
			sum := 0
			for i := range dv.Len() {
				sum += dv.At(i).Int
			}
		}
	})
	b.Run("Cached-Len", func(b *testing.B) {
		b.ReportAllocs()
		dv := SliceOf(data)
		for it := 0; it < b.N; it++ {
			sum := 0
			for i, n := 0, dv.Len(); i < n; i++ {
				sum += dv.At(i).Int
			}
		}
	})
	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		for it := 0; it < b.N; it++ {
			sum := 0
			for _, d := range data {
				sum += d.Int
			}
		}
	})
}

func TestViewsJSON(t *testing.T) {
	mustCIDR := func(cidrs ...string) (out []netip.Prefix) {
		for _, cidr := range cidrs {
			out = append(out, netip.MustParsePrefix(cidr))
		}
		return
	}
	ipp := SliceOf(mustCIDR("192.168.0.0/24"))
	ss := SliceOf([]string{"bar"})
	tests := []struct {
		name     string
		in       viewStruct
		wantJSON string
	}{
		{
			name:     "empty",
			in:       viewStruct{},
			wantJSON: `{"Int":0,"Addrs":null,"Strings":null}`,
		},
		{
			name: "everything",
			in: viewStruct{
				Int:        1234,
				Addrs:      ipp,
				AddrsPtr:   &ipp,
				StringsPtr: &ss,
				Strings:    ss,
			},
			wantJSON: `{"Int":1234,"Addrs":["192.168.0.0/24"],"Strings":["bar"],"AddrsPtr":["192.168.0.0/24"],"StringsPtr":["bar"]}`,
		},
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "")
	for _, tc := range tests {
		buf.Reset()
		if err := encoder.Encode(&tc.in); err != nil {
			t.Fatal(err)
		}
		b := buf.Bytes()
		gotJSON := strings.TrimSpace(string(b))
		if tc.wantJSON != gotJSON {
			t.Fatalf("JSON: %v; want: %v", gotJSON, tc.wantJSON)
		}
		var got viewStruct
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, tc.in) {
			t.Fatalf("unmarshal resulted in different output: %+v; want %+v", got, tc.in)
		}
	}
}

func TestViewUtils(t *testing.T) {
	v := SliceOf([]string{"foo", "bar"})
	c := qt.New(t)

	c.Check(v.ContainsFunc(func(s string) bool { return strings.HasPrefix(s, "f") }), qt.Equals, true)
	c.Check(v.ContainsFunc(func(s string) bool { return strings.HasPrefix(s, "g") }), qt.Equals, false)
	c.Check(v.IndexFunc(func(s string) bool { return strings.HasPrefix(s, "b") }), qt.Equals, 1)
	c.Check(v.IndexFunc(func(s string) bool { return strings.HasPrefix(s, "z") }), qt.Equals, -1)
	c.Check(SliceContains(v, "bar"), qt.Equals, true)
	c.Check(SliceContains(v, "baz"), qt.Equals, false)
	c.Check(SliceEqualAnyOrder(v, v), qt.Equals, true)
	c.Check(SliceEqualAnyOrder(v, SliceOf([]string{"bar", "foo"})), qt.Equals, true)
	c.Check(SliceEqualAnyOrder(v, SliceOf([]string{"foo"})), qt.Equals, false)
	c.Check(SliceEqualAnyOrder(SliceOf([]string{"a", "a", "b"}), SliceOf([]string{"a", "b", "b"})), qt.Equals, false)

	c.Check(SliceEqualAnyOrder(
		SliceOf([]string{"a", "b", "c"}).SliceFrom(1),
		SliceOf([]string{"b", "c"})),
		qt.Equals, true)
	c.Check(SliceEqualAnyOrder(
		SliceOf([]string{"a", "b", "c"}).Slice(1, 2),
		SliceOf([]string{"b", "c"}).SliceTo(1)),
		qt.Equals, true)
}

func TestSliceEqualAnyOrderFunc(t *testing.T) {
	type nc struct {
		_ structs.Incomparable
		v string
	}

	// ncFrom returns a Slice[nc] from a slice of []string
	ncFrom := func(s ...string) Slice[nc] {
		var out []nc
		for _, v := range s {
			out = append(out, nc{v: v})
		}
		return SliceOf(out)
	}

	// cmp returns a comparable value for a nc
	cmp := func(a nc) string { return a.v }

	v := ncFrom("foo", "bar")
	c := qt.New(t)

	// Simple case of slice equal to itself.
	c.Check(SliceEqualAnyOrderFunc(v, v, cmp), qt.Equals, true)

	// Different order.
	c.Check(SliceEqualAnyOrderFunc(v, ncFrom("bar", "foo"), cmp), qt.Equals, true)

	// Different values, same length
	c.Check(SliceEqualAnyOrderFunc(v, ncFrom("foo", "baz"), cmp), qt.Equals, false)

	// Different values, different length
	c.Check(SliceEqualAnyOrderFunc(v, ncFrom("foo"), cmp), qt.Equals, false)

	// Nothing shared
	c.Check(SliceEqualAnyOrderFunc(v, ncFrom("baz", "qux"), cmp), qt.Equals, false)

	// Long slice that matches
	longSlice := ncFrom("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
	longSame := ncFrom("b", "a", "c", "d", "e", "f", "g", "h", "i", "j") // first 2 elems swapped
	c.Check(SliceEqualAnyOrderFunc(longSlice, longSame, cmp), qt.Equals, true)

	// Long difference; past the quadratic limit
	longDiff := ncFrom("b", "a", "c", "d", "e", "f", "g", "h", "i", "k") // differs at end
	c.Check(SliceEqualAnyOrderFunc(longSlice, longDiff, cmp), qt.Equals, false)

	// The short slice optimization had a bug where it wouldn't handle
	// duplicate elements; test various cases here driven by code coverage.
	shortTestCases := []struct {
		name   string
		s1, s2 Slice[nc]
		want   bool
	}{
		{
			name: "duplicates_same_length",
			s1:   ncFrom("a", "a", "b"),
			s2:   ncFrom("a", "b", "b"),
			want: false,
		},
		{
			name: "duplicates_different_matched",
			s1:   ncFrom("x", "y", "a", "a", "b"),
			s2:   ncFrom("x", "y", "b", "a", "a"),
			want: true,
		},
		{
			name: "item_in_a_not_b",
			s1:   ncFrom("x", "y", "a", "b", "c"),
			s2:   ncFrom("x", "y", "b", "c", "q"),
			want: false,
		},
	}
	for _, tc := range shortTestCases {
		t.Run("short_"+tc.name, func(t *testing.T) {
			c.Check(SliceEqualAnyOrderFunc(tc.s1, tc.s2, cmp), qt.Equals, tc.want)
		})
	}
}

func TestSliceEqualAnyOrderAllocs(t *testing.T) {
	ss := func(s ...string) Slice[string] { return SliceOf(s) }
	cmp := func(s string) string { return s }

	t.Run("no-allocs-short-unordered", func(t *testing.T) {
		// No allocations for short comparisons
		short1 := ss("a", "b", "c")
		short2 := ss("c", "b", "a")
		if n := testing.AllocsPerRun(1000, func() {
			if !SliceEqualAnyOrder(short1, short2) {
				t.Fatal("not equal")
			}
			if !SliceEqualAnyOrderFunc(short1, short2, cmp) {
				t.Fatal("not equal")
			}
		}); n > 0 {
			t.Fatalf("allocs = %v; want 0", n)
		}
	})

	t.Run("no-allocs-long-match", func(t *testing.T) {
		long1 := ss("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
		long2 := ss("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")

		if n := testing.AllocsPerRun(1000, func() {
			if !SliceEqualAnyOrder(long1, long2) {
				t.Fatal("not equal")
			}
			if !SliceEqualAnyOrderFunc(long1, long2, cmp) {
				t.Fatal("not equal")
			}
		}); n > 0 {
			t.Fatalf("allocs = %v; want 0", n)
		}
	})

	t.Run("allocs-long-unordered", func(t *testing.T) {
		// We do unfortunately allocate for long comparisons.
		long1 := ss("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
		long2 := ss("c", "b", "a", "e", "d", "f", "g", "h", "i", "j")

		if n := testing.AllocsPerRun(1000, func() {
			if !SliceEqualAnyOrder(long1, long2) {
				t.Fatal("not equal")
			}
			if !SliceEqualAnyOrderFunc(long1, long2, cmp) {
				t.Fatal("not equal")
			}
		}); n == 0 {
			t.Fatalf("unexpectedly didn't allocate")
		}
	})
}

func BenchmarkSliceEqualAnyOrder(b *testing.B) {
	b.Run("short", func(b *testing.B) {
		b.ReportAllocs()
		s1 := SliceOf([]string{"foo", "bar"})
		s2 := SliceOf([]string{"bar", "foo"})
		for range b.N {
			if !SliceEqualAnyOrder(s1, s2) {
				b.Fatal()
			}
		}
	})
	b.Run("long", func(b *testing.B) {
		b.ReportAllocs()
		s1 := SliceOf([]string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"})
		s2 := SliceOf([]string{"c", "b", "a", "e", "d", "f", "g", "h", "i", "j"})
		for range b.N {
			if !SliceEqualAnyOrder(s1, s2) {
				b.Fatal()
			}
		}
	})
}

func TestSliceEqual(t *testing.T) {
	a := SliceOf([]string{"foo", "bar"})
	b := SliceOf([]string{"foo", "bar"})
	if !SliceEqual(a, b) {
		t.Errorf("got a != b")
	}
	if !SliceEqual(a.SliceTo(0), b.SliceTo(0)) {
		t.Errorf("got a[:0] != b[:0]")
	}
	if SliceEqual(a.SliceTo(2), a.SliceTo(1)) {
		t.Error("got a[:2] == a[:1]")
	}
}

// TestSliceMapKey tests that the MapKey method returns the same key for slices
// with the same underlying slice and different keys for different slices or
// with same underlying slice but different bounds.
func TestSliceMapKey(t *testing.T) {
	underlying := []string{"foo", "bar"}
	nilSlice := SliceOf[string](nil)
	empty := SliceOf([]string{})
	u1 := SliceOf(underlying)
	u2 := SliceOf(underlying)
	u3 := SliceOf([]string{"foo", "bar"}) // different underlying slice

	sub1 := u1.Slice(0, 1)
	sub2 := u1.Slice(1, 2)
	sub3 := u1.Slice(0, 2)

	wantSame := []Slice[string]{u1, u2, sub3}
	for i := 1; i < len(wantSame); i++ {
		s0, si := wantSame[0], wantSame[i]
		k0 := s0.MapKey()
		ki := si.MapKey()
		if ki != k0 {
			t.Fatalf("wantSame[%d, %+v, %q) != wantSame[0, %+v, %q)", i, ki, si.AsSlice(), k0, s0.AsSlice())
		}
	}

	wantDiff := []Slice[string]{nilSlice, empty, sub1, sub2, sub3, u3}
	for i := range len(wantDiff) {
		for j := i + 1; j < len(wantDiff); j++ {
			si, sj := wantDiff[i], wantDiff[j]
			ki, kj := wantDiff[i].MapKey(), wantDiff[j].MapKey()
			if ki == kj {
				t.Fatalf("wantDiff[%d, %+v, %q] == wantDiff[%d, %+v, %q] ", i, ki, si.AsSlice(), j, kj, sj.AsSlice())
			}
		}
	}
}

func TestContainsPointers(t *testing.T) {
	tests := []struct {
		name     string
		typ      reflect.Type
		wantPtrs bool
	}{
		{
			name:     "bool",
			typ:      reflect.TypeFor[bool](),
			wantPtrs: false,
		},
		{
			name:     "int",
			typ:      reflect.TypeFor[int](),
			wantPtrs: false,
		},
		{
			name:     "int8",
			typ:      reflect.TypeFor[int8](),
			wantPtrs: false,
		},
		{
			name:     "int16",
			typ:      reflect.TypeFor[int16](),
			wantPtrs: false,
		},
		{
			name:     "int32",
			typ:      reflect.TypeFor[int32](),
			wantPtrs: false,
		},
		{
			name:     "int64",
			typ:      reflect.TypeFor[int64](),
			wantPtrs: false,
		},
		{
			name:     "uint",
			typ:      reflect.TypeFor[uint](),
			wantPtrs: false,
		},
		{
			name:     "uint8",
			typ:      reflect.TypeFor[uint8](),
			wantPtrs: false,
		},
		{
			name:     "uint16",
			typ:      reflect.TypeFor[uint16](),
			wantPtrs: false,
		},
		{
			name:     "uint32",
			typ:      reflect.TypeFor[uint32](),
			wantPtrs: false,
		},
		{
			name:     "uint64",
			typ:      reflect.TypeFor[uint64](),
			wantPtrs: false,
		},
		{
			name:     "uintptr",
			typ:      reflect.TypeFor[uintptr](),
			wantPtrs: false,
		},
		{
			name:     "string",
			typ:      reflect.TypeFor[string](),
			wantPtrs: false,
		},
		{
			name:     "float32",
			typ:      reflect.TypeFor[float32](),
			wantPtrs: false,
		},
		{
			name:     "float64",
			typ:      reflect.TypeFor[float64](),
			wantPtrs: false,
		},
		{
			name:     "complex64",
			typ:      reflect.TypeFor[complex64](),
			wantPtrs: false,
		},
		{
			name:     "complex128",
			typ:      reflect.TypeFor[complex128](),
			wantPtrs: false,
		},
		{
			name:     "netip-Addr",
			typ:      reflect.TypeFor[netip.Addr](),
			wantPtrs: false,
		},
		{
			name:     "netip-Prefix",
			typ:      reflect.TypeFor[netip.Prefix](),
			wantPtrs: false,
		},
		{
			name:     "netip-AddrPort",
			typ:      reflect.TypeFor[netip.AddrPort](),
			wantPtrs: false,
		},
		{
			name:     "bool-ptr",
			typ:      reflect.TypeFor[*bool](),
			wantPtrs: true,
		},
		{
			name:     "string-ptr",
			typ:      reflect.TypeFor[*string](),
			wantPtrs: true,
		},
		{
			name:     "netip-Addr-ptr",
			typ:      reflect.TypeFor[*netip.Addr](),
			wantPtrs: true,
		},
		{
			name:     "unsafe-ptr",
			typ:      reflect.TypeFor[unsafe.Pointer](),
			wantPtrs: true,
		},
		{
			name:     "no-ptr-struct",
			typ:      reflect.TypeFor[noPtrStruct](),
			wantPtrs: false,
		},
		{
			name:     "ptr-struct",
			typ:      reflect.TypeFor[withPtrStruct](),
			wantPtrs: true,
		},
		{
			name:     "string-array",
			typ:      reflect.TypeFor[[5]string](),
			wantPtrs: false,
		},
		{
			name:     "int-ptr-array",
			typ:      reflect.TypeFor[[5]*int](),
			wantPtrs: true,
		},
		{
			name:     "no-ptr-struct-array",
			typ:      reflect.TypeFor[[5]noPtrStruct](),
			wantPtrs: false,
		},
		{
			name:     "with-ptr-struct-array",
			typ:      reflect.TypeFor[[5]withPtrStruct](),
			wantPtrs: true,
		},
		{
			name:     "string-slice",
			typ:      reflect.TypeFor[[]string](),
			wantPtrs: true,
		},
		{
			name:     "int-ptr-slice",
			typ:      reflect.TypeFor[[]int](),
			wantPtrs: true,
		},
		{
			name:     "no-ptr-struct-slice",
			typ:      reflect.TypeFor[[]noPtrStruct](),
			wantPtrs: true,
		},
		{
			name:     "string-map",
			typ:      reflect.TypeFor[map[string]string](),
			wantPtrs: true,
		},
		{
			name:     "int-map",
			typ:      reflect.TypeFor[map[int]int](),
			wantPtrs: true,
		},
		{
			name:     "no-ptr-struct-map",
			typ:      reflect.TypeFor[map[string]noPtrStruct](),
			wantPtrs: true,
		},
		{
			name:     "chan",
			typ:      reflect.TypeFor[chan int](),
			wantPtrs: true,
		},
		{
			name:     "func",
			typ:      reflect.TypeFor[func()](),
			wantPtrs: true,
		},
		{
			name:     "interface",
			typ:      reflect.TypeFor[any](),
			wantPtrs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotPtrs := containsPointers(tt.typ); gotPtrs != tt.wantPtrs {
				t.Errorf("got %v; want %v", gotPtrs, tt.wantPtrs)
			}
		})
	}
}

func TestSliceRange(t *testing.T) {
	sv := SliceOf([]string{"foo", "bar"})
	var got []string
	for i, v := range sv.All() {
		got = append(got, fmt.Sprintf("%d-%s", i, v))
	}
	want := []string{"0-foo", "1-bar"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

type testStruct struct{ value string }

func (p *testStruct) Clone() *testStruct {
	if p == nil {
		return p
	}
	return &testStruct{p.value}
}
func (p *testStruct) View() testStructView { return testStructView{p} }

type testStructView struct{ p *testStruct }

func (v testStructView) Valid() bool { return v.p != nil }
func (v testStructView) AsStruct() *testStruct {
	if v.p == nil {
		return nil
	}
	return v.p.Clone()
}
func (v testStructView) ValueForTest() string { return v.p.value }

func TestSliceViewRange(t *testing.T) {
	vs := SliceOfViews([]*testStruct{{value: "foo"}, {value: "bar"}})
	var got []string
	for i, v := range vs.All() {
		got = append(got, fmt.Sprintf("%d-%s", i, v.AsStruct().value))
	}
	want := []string{"0-foo", "1-bar"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestMapIter(t *testing.T) {
	m := MapOf(map[string]int{"foo": 1, "bar": 2})
	var got []string
	for k, v := range m.All() {
		got = append(got, fmt.Sprintf("%s-%d", k, v))
	}
	slices.Sort(got)
	want := []string{"bar-2", "foo-1"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestMapSliceIter(t *testing.T) {
	m := MapSliceOf(map[string][]int{"foo": {3, 4}, "bar": {1, 2}})
	var got []string
	for k, v := range m.All() {
		got = append(got, fmt.Sprintf("%s-%d", k, v))
	}
	slices.Sort(got)
	want := []string{"bar-{[1 2]}", "foo-{[3 4]}"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestMapFnIter(t *testing.T) {
	m := MapFnOf[string, *testStruct, testStructView](map[string]*testStruct{
		"foo": {value: "fooVal"},
		"bar": {value: "barVal"},
	}, func(p *testStruct) testStructView { return testStructView{p} })
	var got []string
	for k, v := range m.All() {
		got = append(got, fmt.Sprintf("%v-%v", k, v.ValueForTest()))
	}
	slices.Sort(got)
	want := []string{"bar-barVal", "foo-fooVal"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestMapViewsEqual(t *testing.T) {
	testCases := []struct {
		name string
		a, b map[string]string
		want bool
	}{
		{
			name: "both_nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "both_empty",
			a:    map[string]string{},
			b:    map[string]string{},
			want: true,
		},
		{
			name: "one_nil",
			a:    nil,
			b:    map[string]string{"a": "1"},
			want: false,
		},
		{
			name: "different_length",
			a:    map[string]string{"a": "1"},
			b:    map[string]string{"a": "1", "b": "2"},
			want: false,
		},
		{
			name: "different_values",
			a:    map[string]string{"a": "1"},
			b:    map[string]string{"a": "2"},
			want: false,
		},
		{
			name: "different_keys",
			a:    map[string]string{"a": "1"},
			b:    map[string]string{"b": "1"},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := MapViewsEqual(MapOf(tc.a), MapOf(tc.b))
			if got != tc.want {
				t.Errorf("MapViewsEqual: got=%v, want %v", got, tc.want)
			}

			got = MapViewsEqualFunc(MapOf(tc.a), MapOf(tc.b), func(a, b string) bool {
				return a == b
			})
			if got != tc.want {
				t.Errorf("MapViewsEqualFunc: got=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestMapViewsEqualFunc(t *testing.T) {
	// Test that we can compare maps with two different non-comparable
	// values using a custom comparison function.
	type customStruct1 struct {
		_      structs.Incomparable
		Field1 string
	}
	type customStruct2 struct {
		_      structs.Incomparable
		Field2 string
	}

	a := map[string]customStruct1{"a": {Field1: "1"}}
	b := map[string]customStruct2{"a": {Field2: "1"}}

	got := MapViewsEqualFunc(MapOf(a), MapOf(b), func(a customStruct1, b customStruct2) bool {
		return a.Field1 == b.Field2
	})
	if !got {
		t.Errorf("MapViewsEqualFunc: got=%v, want true", got)
	}
}
