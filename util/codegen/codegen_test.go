// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package codegen

import (
	"cmp"
	"go/types"
	"net/netip"
	"strings"
	"sync"
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

	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			typ := lookupTestType(t, tt.typ)
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

type NamedType struct{}

func (NamedType) Method() {}

type NamedTypeAlias = NamedType

type NamedInterface interface {
	Method()
}

type NamedInterfaceAlias = NamedInterface

type GenericType[T NamedInterface] struct {
	TypeParamField    T
	TypeParamPtrField *T
}

type GenericTypeWithAliasConstraint[T NamedInterfaceAlias] struct {
	TypeParamField    T
	TypeParamPtrField *T
}

func TestLookupMethod(t *testing.T) {
	tests := []struct {
		name          string
		typ           types.Type
		methodName    string
		wantHasMethod bool
		wantReceiver  types.Type
	}{
		{
			name:          "NamedType/HasMethod",
			typ:           lookupTestType(t, "NamedType"),
			methodName:    "Method",
			wantHasMethod: true,
		},
		{
			name:          "NamedType/NoMethod",
			typ:           lookupTestType(t, "NamedType"),
			methodName:    "NoMethod",
			wantHasMethod: false,
		},
		{
			name:          "NamedTypeAlias/HasMethod",
			typ:           lookupTestType(t, "NamedTypeAlias"),
			methodName:    "Method",
			wantHasMethod: true,
			wantReceiver:  lookupTestType(t, "NamedType"),
		},
		{
			name:          "NamedTypeAlias/NoMethod",
			typ:           lookupTestType(t, "NamedTypeAlias"),
			methodName:    "NoMethod",
			wantHasMethod: false,
		},
		{
			name:          "PtrToNamedType/HasMethod",
			typ:           types.NewPointer(lookupTestType(t, "NamedType")),
			methodName:    "Method",
			wantHasMethod: true,
			wantReceiver:  lookupTestType(t, "NamedType"),
		},
		{
			name:          "PtrToNamedType/NoMethod",
			typ:           types.NewPointer(lookupTestType(t, "NamedType")),
			methodName:    "NoMethod",
			wantHasMethod: false,
		},
		{
			name:          "PtrToNamedTypeAlias/HasMethod",
			typ:           types.NewPointer(lookupTestType(t, "NamedTypeAlias")),
			methodName:    "Method",
			wantHasMethod: true,
			wantReceiver:  lookupTestType(t, "NamedType"),
		},
		{
			name:          "PtrToNamedTypeAlias/NoMethod",
			typ:           types.NewPointer(lookupTestType(t, "NamedTypeAlias")),
			methodName:    "NoMethod",
			wantHasMethod: false,
		},
		{
			name:          "NamedInterface/HasMethod",
			typ:           lookupTestType(t, "NamedInterface"),
			methodName:    "Method",
			wantHasMethod: true,
		},
		{
			name:          "NamedInterface/NoMethod",
			typ:           lookupTestType(t, "NamedInterface"),
			methodName:    "NoMethod",
			wantHasMethod: false,
		},
		{
			name:          "Interface/HasMethod",
			typ:           types.NewInterfaceType([]*types.Func{types.NewFunc(0, nil, "Method", types.NewSignatureType(nil, nil, nil, nil, nil, false))}, nil),
			methodName:    "Method",
			wantHasMethod: true,
		},
		{
			name:          "Interface/NoMethod",
			typ:           types.NewInterfaceType(nil, nil),
			methodName:    "NoMethod",
			wantHasMethod: false,
		},
		{
			name:          "TypeParam/HasMethod",
			typ:           lookupTestType(t, "GenericType").Underlying().(*types.Struct).Field(0).Type(),
			methodName:    "Method",
			wantHasMethod: true,
			wantReceiver:  lookupTestType(t, "NamedInterface"),
		},
		{
			name:          "TypeParam/NoMethod",
			typ:           lookupTestType(t, "GenericType").Underlying().(*types.Struct).Field(0).Type(),
			methodName:    "NoMethod",
			wantHasMethod: false,
		},
		{
			name:          "TypeParamPtr/HasMethod",
			typ:           lookupTestType(t, "GenericType").Underlying().(*types.Struct).Field(1).Type(),
			methodName:    "Method",
			wantHasMethod: true,
			wantReceiver:  lookupTestType(t, "NamedInterface"),
		},
		{
			name:          "TypeParamPtr/NoMethod",
			typ:           lookupTestType(t, "GenericType").Underlying().(*types.Struct).Field(1).Type(),
			methodName:    "NoMethod",
			wantHasMethod: false,
		},
		{
			name:          "TypeParamWithAlias/HasMethod",
			typ:           lookupTestType(t, "GenericTypeWithAliasConstraint").Underlying().(*types.Struct).Field(0).Type(),
			methodName:    "Method",
			wantHasMethod: true,
			wantReceiver:  lookupTestType(t, "NamedInterface"),
		},
		{
			name:          "TypeParamWithAlias/NoMethod",
			typ:           lookupTestType(t, "GenericTypeWithAliasConstraint").Underlying().(*types.Struct).Field(0).Type(),
			methodName:    "NoMethod",
			wantHasMethod: false,
		},
		{
			name:          "TypeParamWithAliasPtr/HasMethod",
			typ:           lookupTestType(t, "GenericTypeWithAliasConstraint").Underlying().(*types.Struct).Field(1).Type(),
			methodName:    "Method",
			wantHasMethod: true,
			wantReceiver:  lookupTestType(t, "NamedInterface"),
		},
		{
			name:          "TypeParamWithAliasPtr/NoMethod",
			typ:           lookupTestType(t, "GenericTypeWithAliasConstraint").Underlying().(*types.Struct).Field(1).Type(),
			methodName:    "NoMethod",
			wantHasMethod: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMethod := LookupMethod(tt.typ, tt.methodName)
			if gotHasMethod := gotMethod != nil; gotHasMethod != tt.wantHasMethod {
				t.Fatalf("HasMethod: got %v; want %v", gotMethod, tt.wantHasMethod)
			}
			if gotMethod == nil {
				return
			}
			if gotMethod.Name() != tt.methodName {
				t.Errorf("Name: got %v; want %v", gotMethod.Name(), tt.methodName)
			}
			if gotRecv, wantRecv := gotMethod.Signature().Recv().Type(), cmp.Or(tt.wantReceiver, tt.typ); !types.Identical(gotRecv, wantRecv) {
				t.Errorf("Recv: got %v; want %v", gotRecv, wantRecv)
			}
		})
	}
}

var namedTestTypes = sync.OnceValues(func() (map[string]types.Type, error) {
	_, namedTypes, err := LoadTypes("test", ".")
	return namedTypes, err
})

func lookupTestType(t *testing.T, name string) types.Type {
	t.Helper()
	types, err := namedTestTypes()
	if err != nil {
		t.Fatal(err)
	}
	typ, ok := types[name]
	if !ok {
		t.Fatalf("type %q is not declared in the current package", name)
	}
	return typ
}
