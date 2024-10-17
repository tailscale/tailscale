// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tests serves a list of tests for tailscale.com/cmd/viewer.
package tests

import (
	"fmt"
	"net/netip"

	"golang.org/x/exp/constraints"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
)

//go:generate go run tailscale.com/cmd/viewer --type=StructWithPtrs,StructWithoutPtrs,Map,StructWithSlices,OnlyGetClone,StructWithEmbedded,GenericIntStruct,GenericNoPtrsStruct,GenericCloneableStruct,StructWithContainers,StructWithTypeAliasFields,GenericTypeAliasStruct --clone-only-type=OnlyGetClone

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

// Container is a pre-defined container type, such as a collection, an optional
// value or a generic wrapper.
type Container[T any] struct {
	Item T
}

func (c *Container[T]) Clone() *Container[T] {
	if c == nil {
		return nil
	}
	if cloner, ok := any(c.Item).(views.Cloner[T]); ok {
		return &Container[T]{cloner.Clone()}
	}
	if !views.ContainsPointers[T]() {
		return ptr.To(*c)
	}
	panic(fmt.Errorf("%T contains pointers, but is not cloneable", c.Item))
}

// ContainerView is a pre-defined readonly view of a Container[T].
type ContainerView[T views.ViewCloner[T, V], V views.StructView[T]] struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *Container[T]
}

func (cv ContainerView[T, V]) Item() V {
	return cv.ж.Item.View()
}

func ContainerViewOf[T views.ViewCloner[T, V], V views.StructView[T]](c *Container[T]) ContainerView[T, V] {
	return ContainerView[T, V]{c}
}

// MapContainer is a predefined map-like container type.
// Unlike [Container], it has two type parameters, where the value
// is the second parameter.
type MapContainer[K comparable, V views.Cloner[V]] struct {
	Items map[K]V
}

func (c *MapContainer[K, V]) Clone() *MapContainer[K, V] {
	if c == nil {
		return nil
	}
	var m map[K]V
	if c.Items != nil {
		m = make(map[K]V, len(c.Items))
		for i := range m {
			m[i] = c.Items[i].Clone()
		}
	}
	return &MapContainer[K, V]{m}
}

// MapContainerView is a pre-defined readonly view of a [MapContainer][K, T].
type MapContainerView[K comparable, T views.ViewCloner[T, V], V views.StructView[T]] struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *MapContainer[K, T]
}

func (cv MapContainerView[K, T, V]) Items() views.MapFn[K, T, V] {
	return views.MapFnOf(cv.ж.Items, func(t T) V { return t.View() })
}

func MapContainerViewOf[K comparable, T views.ViewCloner[T, V], V views.StructView[T]](c *MapContainer[K, T]) MapContainerView[K, T, V] {
	return MapContainerView[K, T, V]{c}
}

type GenericBasicStruct[T BasicType] struct {
	Value T
}

type StructWithContainers struct {
	IntContainer              Container[int]
	CloneableContainer        Container[*StructWithPtrs]
	BasicGenericContainer     Container[GenericBasicStruct[int]]
	CloneableGenericContainer Container[*GenericNoPtrsStruct[int]]
	CloneableMap              MapContainer[int, *StructWithPtrs]
	CloneableGenericMap       MapContainer[int, *GenericNoPtrsStruct[int]]
}

type (
	StructWithPtrsAlias        = StructWithPtrs
	StructWithoutPtrsAlias     = StructWithoutPtrs
	StructWithPtrsAliasView    = StructWithPtrsView
	StructWithoutPtrsAliasView = StructWithoutPtrsView
)

type StructWithTypeAliasFields struct {
	WithPtr    StructWithPtrsAlias
	WithoutPtr StructWithoutPtrsAlias

	WithPtrByPtr    *StructWithPtrsAlias
	WithoutPtrByPtr *StructWithoutPtrsAlias

	SliceWithPtrs    []*StructWithPtrsAlias
	SliceWithoutPtrs []*StructWithoutPtrsAlias

	MapWithPtrs    map[string]*StructWithPtrsAlias
	MapWithoutPtrs map[string]*StructWithoutPtrsAlias

	MapOfSlicesWithPtrs    map[string][]*StructWithPtrsAlias
	MapOfSlicesWithoutPtrs map[string][]*StructWithoutPtrsAlias
}

type integer = constraints.Integer

type GenericTypeAliasStruct[T integer, T2 views.ViewCloner[T2, V2], V2 views.StructView[T2]] struct {
	NonCloneable T
	Cloneable    T2
}
