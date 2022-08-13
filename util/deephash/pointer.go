// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package deephash

import (
	"net/netip"
	"reflect"
	"time"
	"unsafe"
)

// unsafePointer is an untyped pointer.
// It is the caller's responsibility to call operations on the correct type.
type unsafePointer struct{ p unsafe.Pointer }

func unsafePointerOf(v reflect.Value) unsafePointer {
	return unsafePointer{v.UnsafePointer()}
}
func (p unsafePointer) isNil() bool {
	return p.p == nil
}
func (p unsafePointer) pointerElem() unsafePointer {
	return unsafePointer{*(*unsafe.Pointer)(p.p)}
}
func (p unsafePointer) sliceLen() int {
	return (*reflect.SliceHeader)(p.p).Len
}
func (p unsafePointer) sliceArray() unsafePointer {
	return unsafePointer{unsafe.Pointer((*reflect.SliceHeader)(p.p).Data)}
}
func (p unsafePointer) arrayIndex(index int, size uintptr) unsafePointer {
	return unsafePointer{unsafe.Add(p.p, uintptr(index)*size)}
}
func (p unsafePointer) structField(index int, offset, size uintptr) unsafePointer {
	return unsafePointer{unsafe.Add(p.p, offset)}
}
func (p unsafePointer) asString() *string {
	return (*string)(p.p)
}
func (p unsafePointer) asTime() *time.Time {
	return (*time.Time)(p.p)
}
func (p unsafePointer) asAddr() *netip.Addr {
	return (*netip.Addr)(p.p)
}
func (p unsafePointer) asValue(typ reflect.Type) reflect.Value {
	return reflect.NewAt(typ, p.p)
}
func (p unsafePointer) asMemory(size uintptr) []byte {
	return unsafe.Slice((*byte)(p.p), size)
}
