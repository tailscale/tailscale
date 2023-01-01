// Copyright (c) Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by tailscale/cmd/viewer; DO NOT EDIT.

package tests

import (
	"encoding/json"
	"errors"
	"net/netip"

	"go4.org/mem"
	"tailscale.com/types/views"
)

//go:generate go run tailscale.com/cmd/cloner  -clonefunc=false -type=StructWithPtrs,StructWithoutPtrs,Map,StructWithSlices,OnlyGetClone

// View returns a readonly view of StructWithPtrs.
func (p *StructWithPtrs) View() StructWithPtrsView {
	return StructWithPtrsView{ж: p}
}

// StructWithPtrsView provides a read-only view over StructWithPtrs.
//
// Its methods should only be called if `Valid()` returns true.
type StructWithPtrsView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *StructWithPtrs
}

// Valid reports whether underlying value is non-nil.
func (v StructWithPtrsView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v StructWithPtrsView) AsStruct() *StructWithPtrs {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v StructWithPtrsView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *StructWithPtrsView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x StructWithPtrs
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v StructWithPtrsView) Value() *StructWithoutPtrs {
	if v.ж.Value == nil {
		return nil
	}
	x := *v.ж.Value
	return &x
}

func (v StructWithPtrsView) Int() *int {
	if v.ж.Int == nil {
		return nil
	}
	x := *v.ж.Int
	return &x
}

func (v StructWithPtrsView) NoCloneValue() *StructWithoutPtrs { return v.ж.NoCloneValue }
func (v StructWithPtrsView) String() string                   { return v.ж.String() }
func (v StructWithPtrsView) Equal(v2 StructWithPtrsView) bool { return v.ж.Equal(v2.ж) }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _StructWithPtrsViewNeedsRegeneration = StructWithPtrs(struct {
	Value        *StructWithoutPtrs
	Int          *int
	NoCloneValue *StructWithoutPtrs
}{})

// View returns a readonly view of StructWithoutPtrs.
func (p *StructWithoutPtrs) View() StructWithoutPtrsView {
	return StructWithoutPtrsView{ж: p}
}

// StructWithoutPtrsView provides a read-only view over StructWithoutPtrs.
//
// Its methods should only be called if `Valid()` returns true.
type StructWithoutPtrsView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *StructWithoutPtrs
}

// Valid reports whether underlying value is non-nil.
func (v StructWithoutPtrsView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v StructWithoutPtrsView) AsStruct() *StructWithoutPtrs {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v StructWithoutPtrsView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *StructWithoutPtrsView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x StructWithoutPtrs
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v StructWithoutPtrsView) Int() int          { return v.ж.Int }
func (v StructWithoutPtrsView) Pfx() netip.Prefix { return v.ж.Pfx }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _StructWithoutPtrsViewNeedsRegeneration = StructWithoutPtrs(struct {
	Int int
	Pfx netip.Prefix
}{})

// View returns a readonly view of Map.
func (p *Map) View() MapView {
	return MapView{ж: p}
}

// MapView provides a read-only view over Map.
//
// Its methods should only be called if `Valid()` returns true.
type MapView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *Map
}

// Valid reports whether underlying value is non-nil.
func (v MapView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v MapView) AsStruct() *Map {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v MapView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *MapView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x Map
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v MapView) Int() views.Map[string, int] { return views.MapOf(v.ж.Int) }

func (v MapView) SliceInt() views.MapFn[string, []int, views.Slice[int]] {
	return views.MapFnOf(v.ж.SliceInt, func(t []int) views.Slice[int] {
		return views.SliceOf(t)
	})
}

func (v MapView) StructPtrWithPtr() views.MapFn[string, *StructWithPtrs, StructWithPtrsView] {
	return views.MapFnOf(v.ж.StructPtrWithPtr, func(t *StructWithPtrs) StructWithPtrsView {
		return t.View()
	})
}

func (v MapView) StructPtrWithoutPtr() views.MapFn[string, *StructWithoutPtrs, StructWithoutPtrsView] {
	return views.MapFnOf(v.ж.StructPtrWithoutPtr, func(t *StructWithoutPtrs) StructWithoutPtrsView {
		return t.View()
	})
}

func (v MapView) StructWithoutPtr() views.Map[string, StructWithoutPtrs] {
	return views.MapOf(v.ж.StructWithoutPtr)
}

func (v MapView) SlicesWithPtrs() views.MapFn[string, []*StructWithPtrs, views.SliceView[*StructWithPtrs, StructWithPtrsView]] {
	return views.MapFnOf(v.ж.SlicesWithPtrs, func(t []*StructWithPtrs) views.SliceView[*StructWithPtrs, StructWithPtrsView] {
		return views.SliceOfViews[*StructWithPtrs, StructWithPtrsView](t)
	})
}

func (v MapView) SlicesWithoutPtrs() views.MapFn[string, []*StructWithoutPtrs, views.SliceView[*StructWithoutPtrs, StructWithoutPtrsView]] {
	return views.MapFnOf(v.ж.SlicesWithoutPtrs, func(t []*StructWithoutPtrs) views.SliceView[*StructWithoutPtrs, StructWithoutPtrsView] {
		return views.SliceOfViews[*StructWithoutPtrs, StructWithoutPtrsView](t)
	})
}

func (v MapView) StructWithoutPtrKey() views.Map[StructWithoutPtrs, int] {
	return views.MapOf(v.ж.StructWithoutPtrKey)
}
func (v MapView) SliceIntPtr() map[string][]*int           { panic("unsupported") }
func (v MapView) PointerKey() map[*string]int              { panic("unsupported") }
func (v MapView) StructWithPtrKey() map[StructWithPtrs]int { panic("unsupported") }

func (v MapView) StructWithPtr() views.MapFn[string, StructWithPtrs, StructWithPtrsView] {
	return views.MapFnOf(v.ж.StructWithPtr, func(t StructWithPtrs) StructWithPtrsView {
		return t.View()
	})
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _MapViewNeedsRegeneration = Map(struct {
	Int                 map[string]int
	SliceInt            map[string][]int
	StructPtrWithPtr    map[string]*StructWithPtrs
	StructPtrWithoutPtr map[string]*StructWithoutPtrs
	StructWithoutPtr    map[string]StructWithoutPtrs
	SlicesWithPtrs      map[string][]*StructWithPtrs
	SlicesWithoutPtrs   map[string][]*StructWithoutPtrs
	StructWithoutPtrKey map[StructWithoutPtrs]int
	SliceIntPtr         map[string][]*int
	PointerKey          map[*string]int
	StructWithPtrKey    map[StructWithPtrs]int
	StructWithPtr       map[string]StructWithPtrs
}{})

// View returns a readonly view of StructWithSlices.
func (p *StructWithSlices) View() StructWithSlicesView {
	return StructWithSlicesView{ж: p}
}

// StructWithSlicesView provides a read-only view over StructWithSlices.
//
// Its methods should only be called if `Valid()` returns true.
type StructWithSlicesView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *StructWithSlices
}

// Valid reports whether underlying value is non-nil.
func (v StructWithSlicesView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v StructWithSlicesView) AsStruct() *StructWithSlices {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v StructWithSlicesView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *StructWithSlicesView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x StructWithSlices
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v StructWithSlicesView) Values() views.Slice[StructWithoutPtrs] {
	return views.SliceOf(v.ж.Values)
}
func (v StructWithSlicesView) ValuePointers() views.SliceView[*StructWithoutPtrs, StructWithoutPtrsView] {
	return views.SliceOfViews[*StructWithoutPtrs, StructWithoutPtrsView](v.ж.ValuePointers)
}
func (v StructWithSlicesView) StructPointers() views.SliceView[*StructWithPtrs, StructWithPtrsView] {
	return views.SliceOfViews[*StructWithPtrs, StructWithPtrsView](v.ж.StructPointers)
}
func (v StructWithSlicesView) Structs() StructWithPtrs    { panic("unsupported") }
func (v StructWithSlicesView) Ints() *int                 { panic("unsupported") }
func (v StructWithSlicesView) Slice() views.Slice[string] { return views.SliceOf(v.ж.Slice) }
func (v StructWithSlicesView) Prefixes() views.IPPrefixSlice {
	return views.IPPrefixSliceOf(v.ж.Prefixes)
}
func (v StructWithSlicesView) Data() mem.RO { return mem.B(v.ж.Data) }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _StructWithSlicesViewNeedsRegeneration = StructWithSlices(struct {
	Values         []StructWithoutPtrs
	ValuePointers  []*StructWithoutPtrs
	StructPointers []*StructWithPtrs
	Structs        []StructWithPtrs
	Ints           []*int
	Slice          []string
	Prefixes       []netip.Prefix
	Data           []byte
}{})
