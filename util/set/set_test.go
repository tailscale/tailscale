// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package set

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestSet(t *testing.T) {
	s := Set[int]{}
	s.Add(1)
	s.Add(2)
	if !s.Contains(1) {
		t.Error("missing 1")
	}
	if !s.Contains(2) {
		t.Error("missing 2")
	}
	if s.Contains(3) {
		t.Error("shouldn't have 3")
	}
	if s.Len() != 2 {
		t.Errorf("wrong len %d; want 2", s.Len())
	}

	more := []int{3, 4}
	s.AddSlice(more)
	if !s.Contains(3) {
		t.Error("missing 3")
	}
	if !s.Contains(4) {
		t.Error("missing 4")
	}
	if s.Contains(5) {
		t.Error("shouldn't have 5")
	}
	if s.Len() != 4 {
		t.Errorf("wrong len %d; want 4", s.Len())
	}

	es := s.Slice()
	if len(es) != 4 {
		t.Errorf("slice has wrong len %d; want 4", len(es))
	}
	for _, e := range []int{1, 2, 3, 4} {
		if !slices.Contains(es, e) {
			t.Errorf("slice missing %d (%#v)", e, es)
		}
	}
}

func TestSetOf(t *testing.T) {
	s := Of(1, 2, 3, 4, 4, 1)
	if s.Len() != 4 {
		t.Errorf("wrong len %d; want 4", s.Len())
	}
	for _, n := range []int{1, 2, 3, 4} {
		if !s.Contains(n) {
			t.Errorf("should contain %d", n)
		}
	}
}

func TestEqual(t *testing.T) {
	type test struct {
		name     string
		a        Set[int]
		b        Set[int]
		expected bool
	}
	tests := []test{
		{
			"equal",
			Of(1, 2, 3, 4),
			Of(1, 2, 3, 4),
			true,
		},
		{
			"not equal",
			Of(1, 2, 3, 4),
			Of(1, 2, 3, 5),
			false,
		},
		{
			"different lengths",
			Of(1, 2, 3, 4, 5),
			Of(1, 2, 3, 5),
			false,
		},
	}

	for _, tt := range tests {
		if tt.a.Equal(tt.b) != tt.expected {
			t.Errorf("%s: failed", tt.name)
		}
	}
}

func TestClone(t *testing.T) {
	s := Of(1, 2, 3, 4, 4, 1)
	if s.Len() != 4 {
		t.Errorf("wrong len %d; want 4", s.Len())
	}
	s2 := s.Clone()
	if !s.Equal(s2) {
		t.Error("clone not equal to original")
	}
	s.Add(100)
	if s.Equal(s2) {
		t.Error("clone is not distinct from original")
	}
}

func TestSetJSONRoundTrip(t *testing.T) {
	tests := []struct {
		desc    string
		strings Set[string]
		ints    Set[int]
	}{
		{"empty", make(Set[string]), make(Set[int])},
		{"nil", nil, nil},
		{"one-item", Of("one"), Of(1)},
		{"multiple-items", Of("one", "two", "three"), Of(1, 2, 3)},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			t.Run("strings", func(t *testing.T) {
				buf, err := json.Marshal(tt.strings)
				if err != nil {
					t.Fatalf("json.Marshal: %v", err)
				}
				t.Logf("marshaled: %s", buf)
				var s Set[string]
				if err := json.Unmarshal(buf, &s); err != nil {
					t.Fatalf("json.Unmarshal: %v", err)
				}
				if !s.Equal(tt.strings) {
					t.Errorf("set changed after JSON marshal/unmarshal, before: %v, after: %v", tt.strings, s)
				}
			})
			t.Run("ints", func(t *testing.T) {
				buf, err := json.Marshal(tt.ints)
				if err != nil {
					t.Fatalf("json.Marshal: %v", err)
				}
				t.Logf("marshaled: %s", buf)
				var s Set[int]
				if err := json.Unmarshal(buf, &s); err != nil {
					t.Fatalf("json.Unmarshal: %v", err)
				}
				if !s.Equal(tt.ints) {
					t.Errorf("set changed after JSON marshal/unmarshal, before: %v, after: %v", tt.ints, s)
				}
			})
		})
	}
}

func checkSliceSorted[T comparable](t *testing.T, s Set[T], want []T) {
	t.Helper()
	got := s.Slice()
	if !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestSliceSorted(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		checkSliceSorted(t, Of(3, 1, 4, 1, 5), []int{1, 3, 4, 5})
	})
	t.Run("int8", func(t *testing.T) {
		checkSliceSorted(t, Of[int8](-1, 3, -100, 50), []int8{-100, -1, 3, 50})
	})
	t.Run("uint16", func(t *testing.T) {
		checkSliceSorted(t, Of[uint16](300, 1, 65535, 0), []uint16{0, 1, 300, 65535})
	})
	t.Run("float64", func(t *testing.T) {
		checkSliceSorted(t, Of(2.7, 1.0, 3.14), []float64{1.0, 2.7, 3.14})
	})
	t.Run("float32", func(t *testing.T) {
		checkSliceSorted(t, Of[float32](2.5, 1.0, 3.0), []float32{1.0, 2.5, 3.0})
	})
	t.Run("string", func(t *testing.T) {
		checkSliceSorted(t, Of("banana", "apple", "cherry"), []string{"apple", "banana", "cherry"})
	})
	t.Run("named-uint", func(t *testing.T) {
		type Port uint16
		checkSliceSorted(t, Of[Port](443, 80, 8080), []Port{80, 443, 8080})
	})
}

func TestMake(t *testing.T) {
	var s Set[int]
	s.Make()
	s.Add(1)
	if !s.Contains(1) {
		t.Error("missing 1")
	}
}
