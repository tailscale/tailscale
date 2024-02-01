// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package deephash

import (
	"io"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"tailscale.com/tailcfg"
	"tailscale.com/types/structs"
)

func TestTypeIsMemHashable(t *testing.T) {
	tests := []struct {
		val  any
		want bool
	}{
		{true, true},
		{uint(1), true},
		{uint8(1), true},
		{uint16(1), true},
		{uint32(1), true},
		{uint64(1), true},
		{uintptr(1), true},
		{int(1), true},
		{int8(1), true},
		{int16(1), true},
		{int32(1), true},
		{int64(1), true},
		{float32(1), true},
		{float64(1), true},
		{complex64(1), true},
		{complex128(1), true},
		{[32]byte{}, true},
		{func() {}, false},
		{make(chan int), false},
		{struct{ io.Writer }{nil}, false},
		{unsafe.Pointer(nil), false},
		{new(int), false},
		{TwoInts{}, true},
		{[4]TwoInts{}, true},
		{IntThenByte{}, false},
		{[4]IntThenByte{}, false},
		{tailcfg.PortRange{}, true},
		{int16(0), true},
		{struct {
			_ int
			_ int
		}{}, true},
		{struct {
			_ int
			_ uint8
			_ int
		}{}, false}, // gap
		{struct {
			_ structs.Incomparable // if not last, zero-width
			x int
		}{}, true},
		{struct {
			x int
			_ structs.Incomparable // zero-width last: has space, can't memhash
		}{},
			false},
		{[0]chan bool{}, true},
		{struct{ f [0]func() }{}, true},
		{&selfHasherPointerRecv{}, false},
	}
	for _, tt := range tests {
		got := typeIsMemHashable(reflect.TypeOf(tt.val))
		if got != tt.want {
			t.Errorf("for type %T: got %v, want %v", tt.val, got, tt.want)
		}
	}
}

func TestTypeIsRecursive(t *testing.T) {
	type RecursiveStruct struct {
		_ *RecursiveStruct
	}
	type RecursiveChan chan *RecursiveChan

	tests := []struct {
		val  any
		want bool
	}{
		{val: 42, want: false},
		{val: "string", want: false},
		{val: 1 + 2i, want: false},
		{val: struct{}{}, want: false},
		{val: (*RecursiveStruct)(nil), want: true},
		{val: RecursiveStruct{}, want: true},
		{val: time.Unix(0, 0), want: false},
		{val: structs.Incomparable{}, want: false}, // ignore its [0]func()
		{val: tailcfg.NetPortRange{}, want: false}, // uses structs.Incomparable
		{val: (*tailcfg.Node)(nil), want: false},
		{val: map[string]bool{}, want: false},
		{val: func() {}, want: false},
		{val: make(chan int), want: false},
		{val: unsafe.Pointer(nil), want: false},
		{val: make(RecursiveChan), want: true},
		{val: make(chan int), want: false},
		{val: (*selfHasherPointerRecv)(nil), want: false},
	}
	for _, tt := range tests {
		got := typeIsRecursive(reflect.TypeOf(tt.val))
		if got != tt.want {
			t.Errorf("for type %T: got %v, want %v", tt.val, got, tt.want)
		}
	}
}
