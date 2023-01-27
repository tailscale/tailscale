// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package deephash

import (
	"net/netip"
	"reflect"
	"time"
	"unsafe"
)

// unsafePointer is an untyped pointer.
// It is the caller's responsibility to call operations on the correct type.
//
// This pointer only ever points to a small set of kinds or types:
// time.Time, netip.Addr, string, array, slice, struct, map, pointer, interface,
// or a pointer to memory that is directly hashable.
//
// Arrays are represented as pointers to the first element.
// Structs are represented as pointers to the first field.
// Slices are represented as pointers to a slice header.
// Pointers are represented as pointers to a pointer.
//
// We do not support direct operations on maps and interfaces, and instead
// rely on pointer.asValue to convert the pointer back to a reflect.Value.
// Conversion of an unsafe.Pointer to reflect.Value guarantees that the
// read-only flag in the reflect.Value is unpopulated, avoiding panics that may
// otherwise have occurred since the value was obtained from an unexported field.
type unsafePointer struct{ p unsafe.Pointer }

func unsafePointerOf(v reflect.Value) unsafePointer {
	return unsafePointer{v.UnsafePointer()}
}
func (p unsafePointer) isNil() bool {
	return p.p == nil
}

// pointerElem dereferences a pointer.
// p must point to a pointer.
func (p unsafePointer) pointerElem() unsafePointer {
	return unsafePointer{*(*unsafe.Pointer)(p.p)}
}

// sliceLen returns the slice length.
// p must point to a slice.
func (p unsafePointer) sliceLen() int {
	return (*reflect.SliceHeader)(p.p).Len
}

// sliceArray returns a pointer to the underlying slice array.
// p must point to a slice.
func (p unsafePointer) sliceArray() unsafePointer {
	return unsafePointer{unsafe.Pointer((*reflect.SliceHeader)(p.p).Data)}
}

// arrayIndex returns a pointer to an element in the array.
// p must point to an array.
func (p unsafePointer) arrayIndex(index int, size uintptr) unsafePointer {
	return unsafePointer{unsafe.Add(p.p, uintptr(index)*size)}
}

// structField returns a pointer to a field in a struct.
// p must pointer to a struct.
func (p unsafePointer) structField(index int, offset, size uintptr) unsafePointer {
	return unsafePointer{unsafe.Add(p.p, offset)}
}

// asString casts p as a *string.
func (p unsafePointer) asString() *string {
	return (*string)(p.p)
}

// asTime casts p as a *time.Time.
func (p unsafePointer) asTime() *time.Time {
	return (*time.Time)(p.p)
}

// asAddr casts p as a *netip.Addr.
func (p unsafePointer) asAddr() *netip.Addr {
	return (*netip.Addr)(p.p)
}

// asValue casts p as a reflect.Value containing a pointer to value of t.
func (p unsafePointer) asValue(typ reflect.Type) reflect.Value {
	return reflect.NewAt(typ, p.p)
}

// asMemory returns the memory pointer at by p for a specified size.
func (p unsafePointer) asMemory(size uintptr) []byte {
	return unsafe.Slice((*byte)(p.p), size)
}

// visitStack is a stack of pointers visited.
// Pointers are pushed onto the stack when visited, and popped when leaving.
// The integer value is the depth at which the pointer was visited.
// The length of this stack should be zero after every hashing operation.
type visitStack map[unsafe.Pointer]int

func (v visitStack) seen(p unsafe.Pointer) (int, bool) {
	idx, ok := v[p]
	return idx, ok
}

func (v *visitStack) push(p unsafe.Pointer) {
	if *v == nil {
		*v = make(map[unsafe.Pointer]int)
	}
	(*v)[p] = len(*v)
}

func (v visitStack) pop(p unsafe.Pointer) {
	delete(v, p)
}
