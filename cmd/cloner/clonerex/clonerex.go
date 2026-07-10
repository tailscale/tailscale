// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:generate go run tailscale.com/cmd/cloner  -clonefunc=true -type SliceContainer,InterfaceContainer,MapWithPointers,DeeplyNestedMap,NamedMapContainer,MapSlicePointerContainer,MapWithNamedSliceValues

// Package clonerex is an example package for the cloner tool.
package clonerex

import "maps"

type SliceContainer struct {
	Slice []*int
}

// Cloneable is an interface with a Clone method.
type Cloneable interface {
	Clone() Cloneable
}

// CloneableImpl is a concrete type that implements Cloneable.
type CloneableImpl struct {
	Value int
}

func (c *CloneableImpl) Clone() Cloneable {
	if c == nil {
		return nil
	}
	return &CloneableImpl{Value: c.Value}
}

// InterfaceContainer has a pointer to an interface field, which tests
// the special handling for interface types in the cloner.
type InterfaceContainer struct {
	Interface Cloneable
}

type MapWithPointers struct {
	Nested          map[string]*int
	WithCloneMethod map[string]*SliceContainer
	CloneInterface  map[string]Cloneable
}

// NamedMap is a named map type with its own Clone method.
// This tests that the cloner uses the type's Clone method
// rather than trying to descend into the map's value type.
type NamedMap map[string]any

func (m NamedMap) Clone() NamedMap {
	if m == nil {
		return nil
	}
	m2 := make(NamedMap, len(m))
	maps.Copy(m2, m)
	return m2
}

// NamedMapContainer has a field whose type is a named map with a Clone method.
type NamedMapContainer struct {
	Attrs NamedMap
}

// MapSlicePointerContainer has a map whose values are slices of pointers.
// This tests that the cloner deep-clones the pointer elements in the slice,
// not just the slice itself (which would leave aliased pointers).
type MapSlicePointerContainer struct {
	Routes map[string][]*SliceContainer
}

// DeeplyNestedMap tests arbitrary depth of map nesting (3+ levels)
type DeeplyNestedMap struct {
	ThreeLevels map[string]map[string]map[string]int
	FourLevels  map[string]map[string]map[string]map[string]*SliceContainer
}

// MapWithNamedSliceValues has a map with a named slice type for values. This
// tests that the generator treats these values like any other slice and not a
// struct.
type MapWithNamedSliceValues struct {
	M map[string]NamedSlice
}

type NamedSlice []string
