// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package codegen

import (
	"log"
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/exp/constraints"
)

type AnyParam[T any] struct {
	V T
}

type AnyParamPhantom[T any] struct {
}

type IntegerParam[T constraints.Integer] struct {
	V T
}

type FloatParam[T constraints.Float] struct {
	V T
}

type StringLikeParam[T ~string] struct {
	V T
}

type BasicType interface {
	~bool | constraints.Integer | constraints.Float | constraints.Complex | ~string
}

type BasicTypeParam[T BasicType] struct {
	V T
}

type IntPtr *int

type IntPtrParam[T IntPtr] struct {
	V T
}

type IntegerPtr interface {
	*int | *int32 | *int64
}

type IntegerPtrParam[T IntegerPtr] struct {
	V T
}

type IntegerParamPtr[T constraints.Integer] struct {
	V *T
}

type IntegerSliceParam[T constraints.Integer] struct {
	V []T
}

type IntegerMapParam[T constraints.Integer] struct {
	V []T
}

type UnsafePointerParam[T unsafe.Pointer] struct {
	V T
}

type ValueUnionParam[T netip.Prefix | BasicType] struct {
	V T
}

type ValueUnionParamPtr[T netip.Prefix | BasicType] struct {
	V *T
}

type PointerUnionParam[T netip.Prefix | BasicType | IntPtr] struct {
	V T
}

type Interface interface {
	Method()
}

type InterfaceParam[T Interface] struct {
	V T
}

func TestGenericContainsPointers(t *testing.T) {
	tests := []struct {
		typ         string
		wantPointer bool
	}{
		{
			typ:         "AnyParam",
			wantPointer: true,
		},
		{
			typ:         "AnyParamPhantom",
			wantPointer: false, // has a pointer type parameter, but no pointer fields
		},
		{
			typ:         "IntegerParam",
			wantPointer: false,
		},
		{
			typ:         "FloatParam",
			wantPointer: false,
		},
		{
			typ:         "StringLikeParam",
			wantPointer: false,
		},
		{
			typ:         "BasicTypeParam",
			wantPointer: false,
		},
		{
			typ:         "IntPtrParam",
			wantPointer: true,
		},
		{
			typ:         "IntegerPtrParam",
			wantPointer: true,
		},
		{
			typ:         "IntegerParamPtr",
			wantPointer: true,
		},
		{
			typ:         "IntegerSliceParam",
			wantPointer: true,
		},
		{
			typ:         "IntegerMapParam",
			wantPointer: true,
		},
		{
			typ:         "UnsafePointerParam",
			wantPointer: true,
		},
		{
			typ:         "InterfaceParam",
			wantPointer: true,
		},
		{
			typ:         "ValueUnionParam",
			wantPointer: false,
		},
		{
			typ:         "ValueUnionParamPtr",
			wantPointer: true,
		},
		{
			typ:         "PointerUnionParam",
			wantPointer: true,
		},
	}

	_, namedTypes, err := LoadTypes("test", ".")
	if err != nil {
		log.Fatal(err)
	}

	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			typ := namedTypes[tt.typ]
			if isPointer := ContainsPointers(typ); isPointer != tt.wantPointer {
				t.Fatalf("ContainsPointers: got %v, want: %v", isPointer, tt.wantPointer)
			}
		})
	}
}
