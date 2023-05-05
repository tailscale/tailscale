// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Equaler is a tool to automate the creation of an Equals method.
//
// This tool assumes that if a type you give it contains another named struct
// type, that type will also have an Equal method, and that all fields are
// comparable unless explicitly excluded.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/token"
	"go/types"
	"log"
	"os"
	"strings"

	"golang.org/x/exp/slices"
	"tailscale.com/util/codegen"
)

var (
	flagTypes     = flag.String("type", "", "comma-separated list of types; required")
	flagBuildTags = flag.String("tags", "", "compiler build tags to apply")
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("equaler: ")
	flag.Parse()
	if len(*flagTypes) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	typeNames := strings.Split(*flagTypes, ",")

	pkg, namedTypes, err := codegen.LoadTypes(*flagBuildTags, ".")
	if err != nil {
		log.Fatal(err)
	}
	it := codegen.NewImportTracker(pkg.Types)
	buf := new(bytes.Buffer)
	for _, typeName := range typeNames {
		typ, ok := namedTypes[typeName]
		if !ok {
			log.Fatalf("could not find type %s", typeName)
		}
		gen(buf, it, typ, typeNames)
	}

	cloneOutput := pkg.Name + "_equal.go"
	if err := codegen.WritePackageFile("tailscale.com/cmd/equaler", pkg, cloneOutput, it, buf); err != nil {
		log.Fatal(err)
	}
}

func gen(buf *bytes.Buffer, it *codegen.ImportTracker, typ *types.Named, typeNames []string) {
	t, ok := typ.Underlying().(*types.Struct)
	if !ok {
		return
	}

	name := typ.Obj().Name()
	fmt.Fprintf(buf, "// Equal reports whether a and b are equal.\n")
	fmt.Fprintf(buf, "func (a *%s) Equal(b *%s) bool {\n", name, name)
	writef := func(format string, args ...any) {
		fmt.Fprintf(buf, "\t"+format+"\n", args...)
	}
	writef("if a == b {")
	writef("\treturn true")
	writef("}")

	writef("return a != nil && b != nil &&")
	for i := 0; i < t.NumFields(); i++ {
		fname := t.Field(i).Name()
		ft := t.Field(i).Type()

		// Fields which are explicitly ignored are skipped.
		if codegen.HasNoEqual(t.Tag(i)) {
			writef("\t// Skipping %s because of codegen:noequal", fname)
			continue
		}

		// Fields which are named types that have an Equal() method, get that method used
		if named, _ := ft.(*types.Named); named != nil {
			if implementsEqual(ft) || slices.Contains(typeNames, named.Obj().Name()) {
				writef("\ta.%s.Equal(b.%s) &&", fname, fname)
				continue
			}
		}

		// Fields which are just values are directly compared, unless they have an Equal() method.
		if !codegen.ContainsPointers(ft) {
			writef("\ta.%s == b.%s &&", fname, fname)
			continue
		}

		switch ft := ft.Underlying().(type) {
		case *types.Pointer:
			if named, _ := ft.Elem().(*types.Named); named != nil {
				if slices.Contains(typeNames, named.Obj().Name()) || implementsEqual(ft) {
					writef("\t((a.%s == nil) == (b.%s == nil)) && (a.%s == nil || a.%s.Equal(b.%s)) &&", fname, fname, fname, fname, fname)
					continue
				}
				if implementsEqual(ft.Elem()) {
					writef("\t((a.%s == nil) == (b.%s == nil)) && (a.%s == nil || a.%s.Equal(*b.%s)) &&", fname, fname, fname, fname, fname)
					continue
				}
			}
			if !codegen.ContainsPointers(ft.Elem()) {
				writef("\t((a.%s == nil) == (b.%s == nil)) && (a.%s == nil || *a.%s == *b.%s) &&", fname, fname, fname, fname, fname)
				continue
			}
			log.Fatalf("unimplemented: %s (%T)", fname, ft)
		case *types.Slice:
			// Empty slices and nil slices are different.
			writef("\t((a.%s == nil) == (b.%s == nil)) &&", fname, fname)
			if named, _ := ft.Elem().(*types.Named); named != nil {
				if implementsEqual(ft.Elem()) {
					it.Import("golang.org/x/exp/slices")
					writef("\tslices.EqualFunc(a.%s, b.%s, func(aa %s, bb %s) bool {return aa.Equal(bb)}) &&", fname, fname, named.Obj().Name(), named.Obj().Name())
					continue
				}
				if slices.Contains(typeNames, named.Obj().Name()) || implementsEqual(types.NewPointer(ft.Elem())) {
					it.Import("golang.org/x/exp/slices")
					writef("\tslices.EqualFunc(a.%s, b.%s, func(aa %s, bb %s) bool {return aa.Equal(&bb)}) &&", fname, fname, named.Obj().Name(), named.Obj().Name())
					continue
				}
			}
			if !codegen.ContainsPointers(ft.Elem()) {
				it.Import("golang.org/x/exp/slices")
				writef("\tslices.Equal(a.%s, b.%s) &&", fname, fname)
				continue
			}
			log.Fatalf("unimplemented: %s (%T)", fname, ft)
		case *types.Map:
			if !codegen.ContainsPointers(ft.Elem()) {
				it.Import("golang.org/x/exp/maps")
				writef("\tmaps.Equal(a.%s, b.%s) &&", fname, fname)
				continue
			}
			log.Fatalf("unimplemented: %s (%T)", fname, ft)
		default:
			log.Fatalf("unimplemented: %s (%T)", fname, ft)
		}
	}
	writef("\ttrue")
	fmt.Fprintf(buf, "}\n\n")

	buf.Write(codegen.AssertStructUnchanged(t, name, "Equal", it))
}

// hasBasicUnderlying reports true when typ.Underlying() is a slice or a map.
func hasBasicUnderlying(typ types.Type) bool {
	switch typ.Underlying().(type) {
	case *types.Slice, *types.Map:
		return true
	default:
		return false
	}
}

// implementsEqual reports whether typ has an Equal(typ) bool method.
func implementsEqual(typ types.Type) bool {
	return types.Implements(typ, types.NewInterfaceType(
		[]*types.Func{types.NewFunc(
			token.NoPos, nil, "Equal", types.NewSignatureType(
				types.NewVar(token.NoPos, nil, "a", typ),
				nil, nil,
				types.NewTuple(types.NewVar(token.NoPos, nil, "b", typ)),
				types.NewTuple(types.NewVar(token.NoPos, nil, "", types.Typ[types.Bool])), false))},
		[]types.Type{},
	))
}
