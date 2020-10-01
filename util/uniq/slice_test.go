// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uniq_test

import (
	"reflect"
	"strconv"
	"testing"

	"tailscale.com/util/uniq"
)

func TestModifySlice(t *testing.T) {
	tests := []struct {
		in   []int
		want []int
	}{
		{in: []int{0, 1, 2}, want: []int{0, 1, 2}},
		{in: []int{0, 1, 2, 2}, want: []int{0, 1, 2}},
		{in: []int{0, 0, 1, 2}, want: []int{0, 1, 2}},
		{in: []int{0, 1, 0, 2}, want: []int{0, 1, 0, 2}},
		{in: []int{0}, want: []int{0}},
		{in: []int{0, 0}, want: []int{0}},
		{in: []int{}, want: []int{}},
	}

	for _, test := range tests {
		in := make([]int, len(test.in))
		copy(in, test.in)
		uniq.ModifySlice(&test.in, func(i, j int) bool { return test.in[i] == test.in[j] })
		if !reflect.DeepEqual(test.in, test.want) {
			t.Errorf("uniq.Slice(%v) = %v, want %v", in, test.in, test.want)
		}
		start := len(test.in)
		test.in = test.in[:cap(test.in)]
		for i := start; i < len(in); i++ {
			if test.in[i] != 0 {
				t.Errorf("uniq.Slice(%v): non-0 in tail of %v at index %v", in, test.in, i)
			}
		}
	}
}

func Benchmark(b *testing.B) {
	benches := []struct {
		name  string
		reset func(s []byte)
	}{
		{name: "AllDups",
			reset: func(s []byte) {
				for i := range s {
					s[i] = '*'
				}
			},
		},
		{name: "NoDups",
			reset: func(s []byte) {
				for i := range s {
					s[i] = byte(i)
				}
			},
		},
	}

	for _, bb := range benches {
		b.Run(bb.name, func(b *testing.B) {
			for size := 1; size <= 4096; size *= 16 {
				b.Run(strconv.Itoa(size), func(b *testing.B) {
					benchmark(b, 64, bb.reset)
				})
			}
		})
	}
}

func benchmark(b *testing.B, size int64, reset func(s []byte)) {
	b.ReportAllocs()
	b.SetBytes(size)
	s := make([]byte, size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s = s[:size]
		reset(s)
		uniq.ModifySlice(&s, func(i, j int) bool { return s[i] == s[j] })
	}
}
