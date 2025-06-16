// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"reflect"
	"testing"

	"tailscale.com/cmd/cloner/clonerex"
)

func TestSliceContainer(t *testing.T) {
	num := 5
	examples := []struct {
		name string
		in   *clonerex.SliceContainer
	}{
		{
			name: "nil",
			in:   nil,
		},
		{
			name: "zero",
			in:   &clonerex.SliceContainer{},
		},
		{
			name: "empty",
			in: &clonerex.SliceContainer{
				Slice: []*int{},
			},
		},
		{
			name: "nils",
			in: &clonerex.SliceContainer{
				Slice: []*int{nil, nil, nil, nil, nil},
			},
		},
		{
			name: "one",
			in: &clonerex.SliceContainer{
				Slice: []*int{&num},
			},
		},
		{
			name: "several",
			in: &clonerex.SliceContainer{
				Slice: []*int{&num, &num, &num, &num, &num},
			},
		},
	}

	for _, ex := range examples {
		t.Run(ex.name, func(t *testing.T) {
			out := ex.in.Clone()
			if !reflect.DeepEqual(ex.in, out) {
				t.Errorf("Clone() = %v, want %v", out, ex.in)
			}
		})
	}
}
