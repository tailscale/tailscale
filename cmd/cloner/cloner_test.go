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

func TestInterfaceContainer(t *testing.T) {
	examples := []struct {
		name string
		in   *clonerex.InterfaceContainer
	}{
		{
			name: "nil",
			in:   nil,
		},
		{
			name: "zero",
			in:   &clonerex.InterfaceContainer{},
		},
		{
			name: "with_interface",
			in: &clonerex.InterfaceContainer{
				Interface: &clonerex.CloneableImpl{Value: 42},
			},
		},
		{
			name: "with_nil_interface",
			in: &clonerex.InterfaceContainer{
				Interface: nil,
			},
		},
	}

	for _, ex := range examples {
		t.Run(ex.name, func(t *testing.T) {
			out := ex.in.Clone()
			if !reflect.DeepEqual(ex.in, out) {
				t.Errorf("Clone() = %v, want %v", out, ex.in)
			}

			// Verify no aliasing: modifying the clone should not affect the original
			if ex.in != nil && ex.in.Interface != nil {
				if impl, ok := out.Interface.(*clonerex.CloneableImpl); ok {
					impl.Value = 999
					if origImpl, ok := ex.in.Interface.(*clonerex.CloneableImpl); ok {
						if origImpl.Value == 999 {
							t.Errorf("Clone() aliased memory with original")
						}
					}
				}
			}
		})
	}
}

func TestMapWithPointers(t *testing.T) {
	num1, num2 := 42, 100
	orig := &clonerex.MapWithPointers{
		Nested: map[string]*int{
			"foo": &num1,
			"bar": &num2,
		},
		WithCloneMethod: map[string]*clonerex.SliceContainer{
			"container1": {Slice: []*int{&num1, &num2}},
			"container2": {Slice: []*int{&num1}},
		},
		CloneInterface: map[string]clonerex.Cloneable{
			"impl1": &clonerex.CloneableImpl{Value: 123},
			"impl2": &clonerex.CloneableImpl{Value: 456},
		},
	}

	cloned := orig.Clone()
	if !reflect.DeepEqual(orig, cloned) {
		t.Errorf("Clone() = %v, want %v", cloned, orig)
	}

	// Mutate cloned.Nested pointer values
	*cloned.Nested["foo"] = 999
	if *orig.Nested["foo"] == 999 {
		t.Errorf("Clone() aliased memory in Nested: original was modified")
	}

	// Mutate cloned.WithCloneMethod slice values
	*cloned.WithCloneMethod["container1"].Slice[0] = 888
	if *orig.WithCloneMethod["container1"].Slice[0] == 888 {
		t.Errorf("Clone() aliased memory in WithCloneMethod: original was modified")
	}

	// Mutate cloned.CloneInterface values
	if impl, ok := cloned.CloneInterface["impl1"].(*clonerex.CloneableImpl); ok {
		impl.Value = 777
		if origImpl, ok := orig.CloneInterface["impl1"].(*clonerex.CloneableImpl); ok {
			if origImpl.Value == 777 {
				t.Errorf("Clone() aliased memory in CloneInterface: original was modified")
			}
		}
	}
}

func TestDeeplyNestedMap(t *testing.T) {
	num := 123
	orig := &clonerex.DeeplyNestedMap{
		ThreeLevels: map[string]map[string]map[string]int{
			"a": {
				"b": {"c": 1, "d": 2},
				"e": {"f": 3},
			},
			"g": {
				"h": {"i": 4},
			},
		},
		FourLevels: map[string]map[string]map[string]map[string]*clonerex.SliceContainer{
			"l1a": {
				"l2a": {
					"l3a": {
						"l4a": {Slice: []*int{&num}},
						"l4b": {Slice: []*int{&num, &num}},
					},
				},
			},
		},
	}

	cloned := orig.Clone()
	if !reflect.DeepEqual(orig, cloned) {
		t.Errorf("Clone() = %v, want %v", cloned, orig)
	}

	// Mutate the clone's ThreeLevels map
	cloned.ThreeLevels["a"]["b"]["c"] = 777
	if orig.ThreeLevels["a"]["b"]["c"] == 777 {
		t.Errorf("Clone() aliased memory in ThreeLevels: original was modified")
	}

	// Mutate the clone's FourLevels map at the deepest pointer level
	*cloned.FourLevels["l1a"]["l2a"]["l3a"]["l4a"].Slice[0] = 666
	if *orig.FourLevels["l1a"]["l2a"]["l3a"]["l4a"].Slice[0] == 666 {
		t.Errorf("Clone() aliased memory in FourLevels: original was modified")
	}

	// Add a new top-level key to the clone's FourLevels map
	newNum := 999
	cloned.FourLevels["l1b"] = map[string]map[string]map[string]*clonerex.SliceContainer{
		"l2b": {
			"l3b": {
				"l4c": {Slice: []*int{&newNum}},
			},
		},
	}
	if _, exists := orig.FourLevels["l1b"]; exists {
		t.Errorf("Clone() aliased FourLevels map: new top-level key appeared in original")
	}

	// Add a new nested key to the clone's FourLevels map
	cloned.FourLevels["l1a"]["l2a"]["l3a"]["l4c"] = &clonerex.SliceContainer{Slice: []*int{&newNum}}
	if _, exists := orig.FourLevels["l1a"]["l2a"]["l3a"]["l4c"]; exists {
		t.Errorf("Clone() aliased FourLevels map: new nested key appeared in original")
	}
}
