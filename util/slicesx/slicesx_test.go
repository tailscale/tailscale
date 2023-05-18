// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package slicesx

import (
	"reflect"
	"testing"

	"golang.org/x/exp/slices"
)

func TestInterleave(t *testing.T) {
	testCases := []struct {
		name string
		a, b []int
		want []int
	}{
		{name: "equal", a: []int{1, 3, 5}, b: []int{2, 4, 6}, want: []int{1, 2, 3, 4, 5, 6}},
		{name: "short_b", a: []int{1, 3, 5}, b: []int{2, 4}, want: []int{1, 2, 3, 4, 5}},
		{name: "short_a", a: []int{1, 3}, b: []int{2, 4, 6}, want: []int{1, 2, 3, 4, 6}},
		{name: "len_1", a: []int{1}, b: []int{2, 4, 6}, want: []int{1, 2, 4, 6}},
		{name: "nil_a", a: nil, b: []int{2, 4, 6}, want: []int{2, 4, 6}},
		{name: "nil_all", a: nil, b: nil, want: nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			merged := Interleave(tc.a, tc.b)
			if !reflect.DeepEqual(merged, tc.want) {
				t.Errorf("got %v; want %v", merged, tc.want)
			}
		})
	}
}

func BenchmarkInterleave(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Interleave(
			[]int{1, 2, 3},
			[]int{9, 8, 7},
		)
	}
}

func TestShuffle(t *testing.T) {
	var sl []int
	for i := 0; i < 100; i++ {
		sl = append(sl, i)
	}

	var wasShuffled bool
	for try := 0; try < 10; try++ {
		shuffled := slices.Clone(sl)
		Shuffle(shuffled)
		if !reflect.DeepEqual(shuffled, sl) {
			wasShuffled = true
			break
		}
	}

	if !wasShuffled {
		t.Errorf("expected shuffle after 10 tries")
	}
}

func TestDeduplicate(t *testing.T) {
	testCases := []struct {
		name string
		ss   []int
		want []int
	}{
		{name: "no_dupes", ss: []int{1, 2, 3, 4}, want: []int{1, 2, 3, 4}},
		{name: "ordered_dupes", ss: []int{1, 1, 2, 2, 3, 1}, want: []int{1, 2, 3}},
		{name: "unordered_dupes", ss: []int{1, 2, 3, 1, 2, 3}, want: []int{1, 2, 3}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := Deduplicate(tc.ss)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v; want %v", got, tc.want)
			}
		})
	}
}

func TestDeduplicateFunc(t *testing.T) {
	type uncomparable struct {
		_   [0]map[string]int
		key string
	}

	testCases := []struct {
		name string
		ss   []uncomparable
		want []uncomparable
	}{
		{
			name: "no_dupes",
			ss:   []uncomparable{{key: "one"}, {key: "two"}},
			want: []uncomparable{{key: "one"}, {key: "two"}},
		},
		{
			name: "ordered_dupes",
			ss:   []uncomparable{{key: "one"}, {key: "one"}, {key: "two"}, {key: "two"}, {key: "two"}},
			want: []uncomparable{{key: "one"}, {key: "two"}},
		},
		{
			name: "unordered_dupes",
			ss:   []uncomparable{{key: "one"}, {key: "two"}, {key: "one"}, {key: "two"}, {key: "one"}},
			want: []uncomparable{{key: "one"}, {key: "two"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeduplicateFunc(tc.ss, func(uu uncomparable) string {
				return uu.key
			})
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v; want %v", got, tc.want)
			}
		})
	}
}
