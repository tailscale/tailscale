// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package jsontags checks for incompatible usage of JSON struct tags.
package jsontags

import (
	"go/ast"
	"go/types"
	"reflect"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var Analyzer = &analysis.Analyzer{
	Name:     "jsonvet",
	Doc:      "check for incompatible usages of JSON struct tags",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	// TODO: Report byte arrays fields without an explicit `format` tag option.

	inspect.Preorder([]ast.Node{(*ast.StructType)(nil)}, func(n ast.Node) {
		structType, ok := pass.TypesInfo.Types[n.(*ast.StructType)].Type.(*types.Struct)
		if !ok {
			return // type information may be incomplete
		}
		for i := range structType.NumFields() {
			fieldVar := structType.Field(i)
			tag := reflect.StructTag(structType.Tag(i)).Get("json")
			if tag == "" {
				continue
			}
			var seenName, hasFormat bool
			for opt := range strings.SplitSeq(tag, ",") {
				if !seenName {
					seenName = true
					continue
				}
				switch opt {
				case "omitempty":
					// For bools, ints, uints, floats, strings, and interfaces,
					// it is always safe to migrate from `omitempty` to `omitzero`
					// so long as the type does not have an IsZero method or
					// the IsZero method is identical to reflect.Value.IsZero.
					//
					// For pointers, it is only safe to migrate from `omitempty` to `omitzero`
					// so long as the type does not have an IsZero method, regardless of
					// whether the IsZero method is identical to reflect.Value.IsZero.
					//
					// For pointers, `omitempty` behaves identically on both v1 and v2
					// so long as the type does not implement a Marshal method that
					// might serialize as an empty JSON value (i.e., null, "", [], or {}).
					hasIsZero := hasIsZeroMethod(fieldVar.Type()) && !hasPureIsZeroMethod(fieldVar.Type())
					underType := fieldVar.Type().Underlying()
					basic, isBasic := underType.(*types.Basic)
					array, isArrayKind := underType.(*types.Array)
					_, isMapKind := underType.(*types.Map)
					_, isSliceKind := underType.(*types.Slice)
					_, isPointerKind := underType.(*types.Pointer)
					_, isInterfaceKind := underType.(*types.Interface)
					supportedInV1 := isNumericKind(underType) ||
						isBasic && basic.Kind() == types.Bool ||
						isBasic && basic.Kind() == types.String ||
						isArrayKind && array.Len() == 0 ||
						isMapKind || isSliceKind || isPointerKind || isInterfaceKind
					notSupportedInV2 := isNumericKind(underType) ||
						isBasic && basic.Kind() == types.Bool
					switch {
					case isMapKind, isSliceKind:
						// This operates the same under both v1 and v2 so long as
						// the map or slice type does not implement Marshal
						// that could emit an empty JSON value for cases
						// other than when the map or slice are empty.
						// This is very rare.
					case isString(fieldVar.Type()):
						// This operates the same under both v1 and v2.
						// These are safe to migrate to `omitzero`,
						// but doing so is probably unnecessary churn.
						// Note that this is only for a unnamed string type.
					case !supportedInV1:
						// This never worked in v1. Switching to `omitzero`
						// may lead to unexpected behavior changes.
						report(pass, structType, fieldVar, OmitEmptyUnsupportedInV1)
					case notSupportedInV2:
						// This does not work in v2. Switching to `omitzero`
						// may lead to unexpected behavior changes.
						report(pass, structType, fieldVar, OmitEmptyUnsupportedInV2)
					case !hasIsZero:
						// These are safe to migrate to `omitzero` such that
						// it behaves identically under v1 and v2.
						report(pass, structType, fieldVar, OmitEmptyShouldBeOmitZero)
					case isPointerKind:
						// This operates the same under both v1 and v2 so long as
						// the pointer type does not implement Marshal that
						// could emit an empty JSON value.
						// For example, time.Time is safe since the zero value
						// never marshals as an empty JSON string.
					default:
						// This is a non-pointer type with an IsZero method.
						// If IsZero is not identical to reflect.Value.IsZero,
						// omission may behave slightly differently when using
						// `omitzero` instead of `omitempty`.
						// Thus the finding uses the word "should".
						report(pass, structType, fieldVar, OmitEmptyShouldBeOmitZeroButHasIsZero)
					}
				case "string":
					if !isNumericKind(fieldVar.Type()) {
						report(pass, structType, fieldVar, StringOnNonNumericKind)
					}
				default:
					key, _, ok := strings.Cut(opt, ":")
					hasFormat = key == "format" && ok
				}
			}
			if !hasFormat && isTimeDuration(mayPointerElem(fieldVar.Type())) {
				report(pass, structType, fieldVar, FormatMissingOnTimeDuration)
			}
		}
	})
	return nil, nil
}

// hasIsZeroMethod reports whether t has an IsZero method.
func hasIsZeroMethod(t types.Type) bool {
	for method := range types.NewMethodSet(t).Methods() {
		if fn, ok := method.Type().(*types.Signature); ok && method.Obj().Name() == "IsZero" {
			if fn.Params().Len() == 0 && fn.Results().Len() == 1 && isBool(fn.Results().At(0).Type()) {
				return true
			}
		}
	}
	return false
}

// isBool reports whether t is a bool type.
func isBool(t types.Type) bool {
	basic, ok := t.(*types.Basic)
	return ok && basic.Kind() == types.Bool
}

// isString reports whether t is a string type.
func isString(t types.Type) bool {
	basic, ok := t.(*types.Basic)
	return ok && basic.Kind() == types.String
}

// isTimeDuration reports whether t is a time.Duration type.
func isTimeDuration(t types.Type) bool {
	return isNamed(t, "time", "Duration")
}

// mayPointerElem returns the pointed-at type if t is a pointer,
// otherwise it returns t as-is.
func mayPointerElem(t types.Type) types.Type {
	if pointer, ok := t.(*types.Pointer); ok {
		return pointer.Elem()
	}
	return t
}

// isNamed reports t is a named typed of the given path and name.
func isNamed(t types.Type, path, name string) bool {
	gotPath, gotName := typeName(t)
	return gotPath == path && gotName == name
}

// typeName reports the pkgPath and name of the type.
// It recursively follows type aliases to get the underlying named type.
func typeName(t types.Type) (pkgPath, name string) {
	if named, ok := types.Unalias(t).(*types.Named); ok {
		obj := named.Obj()
		if pkg := obj.Pkg(); pkg != nil {
			return pkg.Path(), obj.Name()
		}
		return "", obj.Name()
	}
	return "", ""
}

// isNumericKind reports whether t is a numeric kind.
func isNumericKind(t types.Type) bool {
	if basic, ok := t.Underlying().(*types.Basic); ok {
		switch basic.Kind() {
		case types.Int, types.Int8, types.Int16, types.Int32, types.Int64:
		case types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64, types.Uintptr:
		case types.Float32, types.Float64:
		default:
			return false
		}
		return true
	}
	return false
}
