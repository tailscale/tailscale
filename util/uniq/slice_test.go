// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uniq_test

import (
	"reflect"
	"testing"

	"tailscale.com/util/uniq"
)

func TestSlice(t *testing.T) {
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
		uniq.Slice(&test.in, func(i, j int) bool { return test.in[i] == test.in[j] })
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
