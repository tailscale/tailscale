// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tests serves a list of tests for tailscale.com/cmd/viewer.
package tests

import (
	"fmt"
	"net/netip"

	"golang.org/x/exp/constraints"
	"tailscale.com/types/views"
)

//go:generate go run tailscale.com/cmd/viewer --type=StructWithPtrs,StructWithoutPtrs,Map,StructWithSlices,OnlyGetClone,StructWithEmbedded,GenericIntStruct,GenericNoPtrsStruct,GenericCloneableStruct --clone-only-type=OnlyGetClone

type StructWithoutPtrs struct {
	Int int
	Pfx netip.Prefix
}

type Map struct {
	Int                 map[string]int
	SliceInt            map[string][]int
	StructPtrWithPtr    map[string]*StructWithPtrs
	StructPtrWithoutPtr map[string]*StructWithoutPtrs
	StructWithoutPtr    map[string]StructWithoutPtrs
	SlicesWithPtrs      map[string][]*StructWithPtrs
	SlicesWithoutPtrs   map[string][]*StructWithoutPtrs
	StructWithoutPtrKey map[StructWithoutPtrs]int `json:"-"`
	StructWithPtr       map[string]StructWithPtrs

	// Unsupported views.
	SliceIntPtr      map[string][]*int
	PointerKey       map[*string]int        `json:"-"`
	StructWithPtrKey map[StructWithPtrs]int `json:"-"`
}

type StructWithPtrs struct {
	Value *StructWithoutPtrs
	Int   *int

	NoCloneValue *StructWithoutPtrs `codegen:"noclone"`
}

func (v *StructWithPtrs) String() string { return fmt.Sprintf("%v", v.Int) }

func (v *StructWithPtrs) Equal(v2 *StructWithPtrs) bool {
	return v.Value == v2.Value
}

type StructWithSlices struct {
	Values         []StructWithoutPtrs
	ValuePointers  []*StructWithoutPtrs
	StructPointers []*StructWithPtrs

	Slice    []string
	Prefixes []netip.Prefix
	Data     []byte

	// Unsupported views.
	Structs []StructWithPtrs
	Ints    []*int
}

type OnlyGetClone struct {
	SinViewerPorFavor bool
}

type StructWithEmbedded struct {
	A *StructWithPtrs
	StructWithSlices
}

type GenericIntStruct[T constraints.Integer] struct {
	Value   T
	Pointer *T
	Slice   []T
	Map     map[string]T

	// Unsupported views.
	PtrSlice    []*T
	PtrKeyMap   map[*T]string `json:"-"`
	PtrValueMap map[string]*T
	SliceMap    map[string][]T
}

type BasicType interface {
	~bool | constraints.Integer | constraints.Float | constraints.Complex | ~string
}

type GenericNoPtrsStruct[T StructWithoutPtrs | netip.Prefix | BasicType] struct {
	Value   T
	Pointer *T
	Slice   []T
	Map     map[string]T

	// Unsupported views.
	PtrSlice    []*T
	PtrKeyMap   map[*T]string `json:"-"`
	PtrValueMap map[string]*T
	SliceMap    map[string][]T
}

type GenericCloneableStruct[T views.ViewCloner[T, V], V views.StructView[T]] struct {
	Value T
	Slice []T
	Map   map[string]T

	// Unsupported views.
	Pointer     *T
	PtrSlice    []*T
	PtrKeyMap   map[*T]string `json:"-"`
	PtrValueMap map[string]*T
	SliceMap    map[string][]T
}
