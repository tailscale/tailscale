// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package codegen

import (
	"go/types"
	"log"
	"net/netip"
	"strings"
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

func TestAssertStructUnchanged(t *testing.T) {
	type args struct {
		t      *types.Struct
		tname  string
		params *types.TypeParamList
		ctx    string
		it     *ImportTracker
	}

	// package t1 with a struct T1 with two fields
	p1 := types.NewPackage("t1", "t1")
	t1 := types.NewNamed(types.NewTypeName(0, p1, "T1", nil), types.NewStruct([]*types.Var{
		types.NewField(0, nil, "P1", types.Typ[types.Int], false),
		types.NewField(0, nil, "P2", types.Typ[types.String], false),
	}, nil), nil)
	p1.Scope().Insert(t1.Obj())

	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "t1-internally_defined",
			args: args{
				t:      t1.Underlying().(*types.Struct),
				tname:  "prefix_",
				params: nil,
				ctx:    "",
				it:     NewImportTracker(p1),
			},
			want: []byte("var _prefix_NeedsRegeneration = prefix_(struct {\n\tP1 int \n\tP2 string \n}{})"),
		},
		{
			name: "t2-with_named_field",
			args: args{
				t: types.NewStruct([]*types.Var{
					types.NewField(0, nil, "T1", t1, false),
					types.NewField(0, nil, "P1", types.Typ[types.Int], false),
					types.NewField(0, nil, "P2", types.Typ[types.String], false),
				}, nil),
				tname:  "prefix_",
				params: nil,
				ctx:    "",
				it:     NewImportTracker(types.NewPackage("t2", "t2")),
			},
			// the struct should be regenerated with the named field
			want: []byte("var _prefix_NeedsRegeneration = prefix_(struct {\n\tT1 t1.T1 \n\tP1 int \n\tP2 string \n}{})"),
		},
		{
			name: "t3-with_embedded_field",
			args: args{
				t: types.NewStruct([]*types.Var{
					types.NewField(0, nil, "T1", t1, true),
					types.NewField(0, nil, "P1", types.Typ[types.Int], false),
					types.NewField(0, nil, "P2", types.Typ[types.String], false),
				}, nil),
				tname:  "prefix_",
				params: nil,
				ctx:    "",
				it:     NewImportTracker(types.NewPackage("t3", "t3")),
			},
			// the struct should be regenerated with the embedded field
			want: []byte("var _prefix_NeedsRegeneration = prefix_(struct {\n\tt1.T1 \n\tP1 int \n\tP2 string \n}{})"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AssertStructUnchanged(tt.args.t, tt.args.tname, tt.args.params, tt.args.ctx, tt.args.it); !strings.Contains(string(got), string(tt.want)) {
				t.Errorf("AssertStructUnchanged() = \n%s\nwant: \n%s", string(got), string(tt.want))
			}
		})
	}
}
