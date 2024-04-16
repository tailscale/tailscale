// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package topk

import (
	"encoding/binary"
	"fmt"
	"slices"
	"testing"
)

func TestCountMinSketch(t *testing.T) {
	cms := NewCountMinSketch(4, 10)
	items := []string{"foo", "bar", "baz", "asdf", "quux"}
	for _, item := range items {
		cms.Add([]byte(item))
	}
	for _, item := range items {
		count := cms.Get([]byte(item))
		if count < 1 {
			t.Errorf("item %q should have count >= 1", item)
		} else if count > 1 {
			t.Logf("item %q has count > 1: %d", item, count)
		}
	}

	// Test that an item that's *not* in the set has a value lower than the
	// total number of items we inserted (in the case that all items
	// collided).
	noItemCount := cms.Get([]byte("doesn't exist"))
	if noItemCount > uint64(len(items)) {
		t.Errorf("expected nonexistent item to have value < %d; got %d", len(items), noItemCount)
	}
}

func TestTopK(t *testing.T) {
	// This is probabilistic, so we're going to try 10 times to get the
	// "right" value; the likelihood that we fail on all attempts is
	// vanishingly small since the number of hash buckets is drastically
	// larger than the number of items we're inserting.
	var (
		got  []int
		want = []int{5, 6, 7, 8, 9}
	)
	for try := 0; try < 10; try++ {
		topk := NewWithParams[int](5, func(in []byte, val int) []byte {
			return binary.LittleEndian.AppendUint64(in, uint64(val))
		}, 4, 1000)

		// Add the first 10 integers with counts equal to 2x their value
		for i := range 10 {
			topk.AddN(i, uint64(i*2))
		}

		got = topk.Top()
		t.Logf("top K items: %+v", got)
		slices.Sort(got)

		if slices.Equal(got, want) {
			// All good!
			return
		}

		// continue and retry or fail
	}

	t.Errorf("top K mismatch\ngot: %v\nwant: %v", got, want)
}

func TestPickParams(t *testing.T) {
	hashes, buckets := PickParams(
		0.001, // 0.1% error rate
		0.001, // 0.1% chance of having an error, or 99.9% chance of not having an error
	)
	t.Logf("hashes = %d, buckets = %d", hashes, buckets)
}

func BenchmarkCountMinSketch(b *testing.B) {
	cms := NewCountMinSketch(PickParams(0.001, 0.001))
	b.ResetTimer()
	b.ReportAllocs()

	var enc [8]byte
	for i := range b.N {
		binary.LittleEndian.PutUint64(enc[:], uint64(i))
		cms.Add(enc[:])
	}
}

func BenchmarkTopK(b *testing.B) {
	for _, n := range []int{
		10,
		128,
		256,
		1024,
		8192,
	} {
		b.Run(fmt.Sprintf("Top%d", n), func(b *testing.B) {
			out := make([]int, 0, n)
			topk := New[int](n, func(in []byte, val int) []byte {
				return binary.LittleEndian.AppendUint64(in, uint64(val))
			})
			b.ResetTimer()
			b.ReportAllocs()

			for i := range b.N {
				topk.Add(i)
			}
			out = topk.AppendTop(out[:0]) // should not allocate
			_ = out                       // appease linter
		})
	}
}

func TestMultiplyHigh64(t *testing.T) {
	testCases := []struct {
		x, y uint64
		want uint64
	}{
		{0, 0, 0},
		{0xffffffff, 0xffffffff, 0},
		{0x2, 0xf000000000000000, 1},
		{0x3, 0xf000000000000000, 2},
		{0x3, 0xf000000000000001, 2},
		{0x3, 0xffffffffffffffff, 2},
		{0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffffffffffe},
	}
	for _, tc := range testCases {
		got := multiplyHigh64(tc.x, tc.y)
		if got != tc.want {
			t.Errorf("got multiplyHigh64(%x, %x) = %x, want %x", tc.x, tc.y, got, tc.want)
		}
	}
}
