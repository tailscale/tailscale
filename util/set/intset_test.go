// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package set

import (
	"maps"
	"math"
	"slices"
	"testing"

	"golang.org/x/exp/constraints"
)

func TestIntSet(t *testing.T) {
	t.Run("Int64", func(t *testing.T) {
		ss := make(Set[int64])
		var si IntSet[int64]
		intValues(t, ss, si)
		deleteInt(t, ss, &si, -5)
		deleteInt(t, ss, &si, 2)
		deleteInt(t, ss, &si, 75)
		intValues(t, ss, si)
		addInt(t, ss, &si, 2)
		addInt(t, ss, &si, 75)
		addInt(t, ss, &si, 75)
		addInt(t, ss, &si, -3)
		addInt(t, ss, &si, -3)
		addInt(t, ss, &si, -3)
		addInt(t, ss, &si, math.MinInt64)
		addInt(t, ss, &si, 8)
		intValues(t, ss, si)
		addInt(t, ss, &si, 77)
		addInt(t, ss, &si, 76)
		addInt(t, ss, &si, 76)
		addInt(t, ss, &si, 76)
		intValues(t, ss, si)
		addInt(t, ss, &si, -5)
		addInt(t, ss, &si, 7)
		addInt(t, ss, &si, -83)
		addInt(t, ss, &si, math.MaxInt64)
		intValues(t, ss, si)
		deleteInt(t, ss, &si, -5)
		deleteInt(t, ss, &si, 2)
		deleteInt(t, ss, &si, 75)
		intValues(t, ss, si)
		deleteInt(t, ss, &si, math.MinInt64)
		deleteInt(t, ss, &si, math.MaxInt64)
		intValues(t, ss, si)
		if !si.Equal(IntsOf(ss.Slice()...)) {
			t.Errorf("{%v}.Equal({%v}) = false, want true", si, ss)
		}
	})

	t.Run("Uint64", func(t *testing.T) {
		ss := make(Set[uint64])
		var si IntSet[uint64]
		intValues(t, ss, si)
		deleteInt(t, ss, &si, 5)
		deleteInt(t, ss, &si, 2)
		deleteInt(t, ss, &si, 75)
		intValues(t, ss, si)
		addInt(t, ss, &si, 2)
		addInt(t, ss, &si, 75)
		addInt(t, ss, &si, 75)
		addInt(t, ss, &si, 3)
		addInt(t, ss, &si, 3)
		addInt(t, ss, &si, 8)
		intValues(t, ss, si)
		addInt(t, ss, &si, 77)
		addInt(t, ss, &si, 76)
		addInt(t, ss, &si, 76)
		addInt(t, ss, &si, 76)
		intValues(t, ss, si)
		addInt(t, ss, &si, 5)
		addInt(t, ss, &si, 7)
		addInt(t, ss, &si, 83)
		addInt(t, ss, &si, math.MaxInt64)
		intValues(t, ss, si)
		deleteInt(t, ss, &si, 5)
		deleteInt(t, ss, &si, 2)
		deleteInt(t, ss, &si, 75)
		intValues(t, ss, si)
		deleteInt(t, ss, &si, math.MaxInt64)
		intValues(t, ss, si)
		if !si.Equal(IntsOf(ss.Slice()...)) {
			t.Errorf("{%v}.Equal({%v}) = false, want true", si, ss)
		}
	})
}

func intValues[T constraints.Integer](t testing.TB, ss Set[T], si IntSet[T]) {
	got := slices.Collect(maps.Keys(ss))
	slices.Sort(got)
	want := slices.Collect(si.Values())
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("Values mismatch:\n\tgot  %v\n\twant %v", got, want)
	}
	if got, want := si.Len(), ss.Len(); got != want {
		t.Fatalf("Len() = %v, want %v", got, want)
	}
}

func addInt[T constraints.Integer](t testing.TB, ss Set[T], si *IntSet[T], v T) {
	t.Helper()
	if got, want := si.Contains(v), ss.Contains(v); got != want {
		t.Fatalf("Contains(%v) = %v, want %v", v, got, want)
	}
	ss.Add(v)
	si.Add(v)
	if !si.Contains(v) {
		t.Fatalf("Contains(%v) = false, want true", v)
	}
	if got, want := si.Len(), ss.Len(); got != want {
		t.Fatalf("Len() = %v, want %v", got, want)
	}
}

func deleteInt[T constraints.Integer](t testing.TB, ss Set[T], si *IntSet[T], v T) {
	t.Helper()
	if got, want := si.Contains(v), ss.Contains(v); got != want {
		t.Fatalf("Contains(%v) = %v, want %v", v, got, want)
	}
	ss.Delete(v)
	si.Delete(v)
	if si.Contains(v) {
		t.Fatalf("Contains(%v) = true, want false", v)
	}
	if got, want := si.Len(), ss.Len(); got != want {
		t.Fatalf("Len() = %v, want %v", got, want)
	}
}

func TestZigZag(t *testing.T) {
	t.Run("Int64", func(t *testing.T) {
		for _, tt := range []struct {
			decoded int64
			encoded uint64
		}{
			{math.MinInt64, math.MaxUint64},
			{-2, 3},
			{-1, 1},
			{0, 0},
			{1, 2},
			{2, 4},
			{math.MaxInt64, math.MaxUint64 - 1},
		} {
			encoded := encodeZigZag(tt.decoded)
			if encoded != tt.encoded {
				t.Errorf("encodeZigZag(%v) = %v, want %v", tt.decoded, encoded, tt.encoded)
			}
			decoded := decodeZigZag[int64](tt.encoded)
			if decoded != tt.decoded {
				t.Errorf("decodeZigZag(%v) = %v, want %v", tt.encoded, decoded, tt.decoded)
			}
		}
	})
	t.Run("Uint64", func(t *testing.T) {
		for _, tt := range []struct {
			decoded uint64
			encoded uint64
		}{
			{0, 0},
			{1, 1},
			{2, 2},
			{math.MaxInt64, math.MaxInt64},
			{math.MaxUint64, math.MaxUint64},
		} {
			encoded := encodeZigZag(tt.decoded)
			if encoded != tt.encoded {
				t.Errorf("encodeZigZag(%v) = %v, want %v", tt.decoded, encoded, tt.encoded)
			}
			decoded := decodeZigZag[uint64](tt.encoded)
			if decoded != tt.decoded {
				t.Errorf("decodeZigZag(%v) = %v, want %v", tt.encoded, decoded, tt.decoded)
			}
		}
	})
}
