// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build race

package deephash

import (
	"fmt"
	"net/netip"
	"reflect"
	"time"
)

// pointer is a typed pointer that performs safety checks for every operation.
type pointer struct {
	unsafePointer
	t reflect.Type // type of pointed-at value; may be nil
	n uintptr      // size of valid memory after p
}

// pointerOf returns a pointer from v, which must be a reflect.Pointer.
func pointerOf(v reflect.Value) pointer {
	assert(v.Kind() == reflect.Pointer, "got %v, want pointer", v.Kind())
	te := v.Type().Elem()
	return pointer{unsafePointerOf(v), te, te.Size()}
}

func (p pointer) pointerElem() pointer {
	assert(p.t.Kind() == reflect.Pointer, "got %v, want pointer", p.t.Kind())
	te := p.t.Elem()
	return pointer{p.unsafePointer.pointerElem(), te, te.Size()}
}

func (p pointer) sliceLen() int {
	assert(p.t.Kind() == reflect.Slice, "got %v, want slice", p.t.Kind())
	return p.unsafePointer.sliceLen()
}

func (p pointer) sliceArray() pointer {
	assert(p.t.Kind() == reflect.Slice, "got %v, want slice", p.t.Kind())
	n := p.sliceLen()
	assert(n >= 0, "got negative slice length %d", n)
	ta := reflect.ArrayOf(n, p.t.Elem())
	return pointer{p.unsafePointer.sliceArray(), ta, ta.Size()}
}

func (p pointer) arrayIndex(index int, size uintptr) pointer {
	assert(p.t.Kind() == reflect.Array, "got %v, want array", p.t.Kind())
	assert(0 <= index && index < p.t.Len(), "got array of size %d, want to access element %d", p.t.Len(), index)
	assert(p.t.Elem().Size() == size, "got element size of %d, want %d", p.t.Elem().Size(), size)
	te := p.t.Elem()
	return pointer{p.unsafePointer.arrayIndex(index, size), te, te.Size()}
}

func (p pointer) structField(index int, offset, size uintptr) pointer {
	assert(p.t.Kind() == reflect.Struct, "got %v, want struct", p.t.Kind())
	assert(p.n >= offset, "got size of %d, want excessive start offset of %d", p.n, offset)
	assert(p.n >= offset+size, "got size of %d, want excessive end offset of %d", p.n, offset+size)
	if index < 0 {
		return pointer{p.unsafePointer.structField(index, offset, size), nil, size}
	}
	sf := p.t.Field(index)
	t := sf.Type
	assert(sf.Offset == offset, "got offset of %d, want offset %d", sf.Offset, offset)
	assert(t.Size() == size, "got size of %d, want size %d", t.Size(), size)
	return pointer{p.unsafePointer.structField(index, offset, size), t, t.Size()}
}

func (p pointer) asString() *string {
	assert(p.t.Kind() == reflect.String, "got %v, want string", p.t)
	return p.unsafePointer.asString()
}

func (p pointer) asTime() *time.Time {
	assert(p.t == timeTimeType, "got %v, want %v", p.t, timeTimeType)
	return p.unsafePointer.asTime()
}

func (p pointer) asAddr() *netip.Addr {
	assert(p.t == netipAddrType, "got %v, want %v", p.t, netipAddrType)
	return p.unsafePointer.asAddr()
}

func (p pointer) asValue(typ reflect.Type) reflect.Value {
	assert(p.t == typ, "got %v, want %v", p.t, typ)
	return p.unsafePointer.asValue(typ)
}

func (p pointer) asMemory(size uintptr) []byte {
	assert(p.n >= size, "got size of %d, want excessive size of %d", p.n, size)
	return p.unsafePointer.asMemory(size)
}

func assert(b bool, f string, a ...any) {
	if !b {
		panic(fmt.Sprintf(f, a...))
	}
}
