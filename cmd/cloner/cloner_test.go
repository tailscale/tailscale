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
		in   *clonerex.SliceContianer
	}{
		{
			name: "nil",
			in:   nil,
		},
		{
			name: "zero",
			in:   &clonerex.SliceContianer{},
		},
		{
			name: "empty",
			in: &clonerex.SliceContianer{
				Slice: []*int{},
			},
		},
		{
			name: "nils",
			in: &clonerex.SliceContianer{
				Slice: []*int{nil, nil, nil, nil, nil},
			},
		},
		{
			name: "one",
			in: &clonerex.SliceContianer{
				Slice: []*int{&num},
			},
		},
		{
			name: "several",
			in: &clonerex.SliceContianer{
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
