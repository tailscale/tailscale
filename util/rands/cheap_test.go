// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package rands

import (
	"slices"
	"testing"

	randv2 "math/rand/v2"
)

func TestShuffleNoAllocs(t *testing.T) {
	seed := randv2.Uint64()
	data := make([]int, 100)
	for i := range data {
		data[i] = i
	}
	if n := testing.AllocsPerRun(1000, func() {
		Shuffle(seed, data)
	}); n > 0 {
		t.Errorf("Rand got %v allocs per run", n)
	}
}

func BenchmarkStdRandV2Shuffle(b *testing.B) {
	seed := randv2.Uint64()
	data := make([]int, 100)
	for i := range data {
		data[i] = i
	}
	b.ReportAllocs()
	for range b.N {
		// PCG is the lightest source, taking just two uint64s, the chacha8
		// source has much larger state.
		rng := randv2.New(randv2.NewPCG(seed, seed))
		rng.Shuffle(len(data), func(i, j int) { data[i], data[j] = data[j], data[i] })
	}
}

func BenchmarkLocalShuffle(b *testing.B) {
	seed := randv2.Uint64()
	data := make([]int, 100)
	for i := range data {
		data[i] = i
	}
	b.ReportAllocs()
	for range b.N {
		Shuffle(seed, data)
	}
}

func TestPerm(t *testing.T) {
	seed := uint64(12345)
	p := Perm(seed, 100)
	if len(p) != 100 {
		t.Errorf("got %v; want 100", len(p))
	}
	expect := [][]int{
		{5, 7, 1, 4, 0, 9, 2, 3, 6, 8},
		{0, 5, 9, 8, 1, 6, 2, 4, 3, 7},
		{5, 2, 3, 1, 9, 7, 6, 8, 4, 0},
		{4, 5, 7, 1, 6, 3, 8, 2, 0, 9},
		{5, 7, 0, 9, 2, 1, 8, 4, 6, 3},
	}
	for i := range 5 {
		got := Perm(seed+uint64(i), 10)
		want := expect[i]
		if !slices.Equal(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}
	}
}

func TestShuffle(t *testing.T) {
	seed := uint64(12345)
	p := Perm(seed, 10)
	if len(p) != 10 {
		t.Errorf("got %v; want 10", len(p))
	}

	expect := [][]int{
		{9, 3, 7, 0, 5, 8, 1, 4, 2, 6},
		{9, 8, 6, 2, 3, 1, 7, 5, 0, 4},
		{1, 6, 2, 8, 4, 5, 7, 0, 3, 9},
		{4, 5, 0, 6, 7, 8, 3, 2, 1, 9},
		{8, 2, 4, 9, 0, 5, 1, 7, 3, 6},
	}
	for i := range 5 {
		Shuffle(seed+uint64(i), p)
		want := expect[i]
		if !slices.Equal(p, want) {
			t.Errorf("got %v; want %v", p, want)
		}
	}
}
