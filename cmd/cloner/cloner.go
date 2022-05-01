// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Cloner is a tool to automate the creation of a Clone method.
//
// The result of the Clone method aliases no memory that can be edited
// with the original.
//
// This tool makes lots of implicit assumptions about the types you feed it.
// In particular, it can only write relatively "shallow" Clone methods.
// That is, if a type contains another named struct type, cloner assumes that
// named type will also have a Clone method.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/types"
	"log"
	"os"
	"strings"

	"tailscale.com/util/codegen"
)

var (
	flagTypes     = flag.String("type", "", "comma-separated list of types; required")
	flagBuildTags = flag.String("tags", "", "compiler build tags to apply")
	flagCloneFunc = flag.Bool("clonefunc", false, "add a top-level Clone func")
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("cloner: ")
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
		gen(buf, it, typ)
	}

	w := func(format string, args ...any) {
		fmt.Fprintf(buf, format+"\n", args...)
	}
	if *flagCloneFunc {
		w("// Clone duplicates src into dst and reports whether it succeeded.")
		w("// To succeed, <src, dst> must be of types <*T, *T> or <*T, **T>,")
		w("// where T is one of %s.", *flagTypes)
		w("func Clone(dst, src any) bool {")
		w("	switch src := src.(type) {")
		for _, typeName := range typeNames {
			w("	case *%s:", typeName)
			w("		switch dst := dst.(type) {")
			w("		case *%s:", typeName)
			w("			*dst = *src.Clone()")
			w("			return true")
			w("		case **%s:", typeName)
			w("			*dst = src.Clone()")
			w("			return true")
			w("		}")
		}
		w("	}")
		w("	return false")
		w("}")
	}
	cloneOutput := pkg.Name + "_clone.go"
	if err := codegen.WritePackageFile("tailscale.com/cmd/cloner", pkg, cloneOutput, it, buf); err != nil {
		log.Fatal(err)
	}
}

func gen(buf *bytes.Buffer, it *codegen.ImportTracker, typ *types.Named) {
	t, ok := typ.Underlying().(*types.Struct)
	if !ok {
		return
	}

	name := typ.Obj().Name()
	fmt.Fprintf(buf, "// Clone makes a deep copy of %s.\n", name)
	fmt.Fprintf(buf, "// The result aliases no memory with the original.\n")
	fmt.Fprintf(buf, "func (src *%s) Clone() *%s {\n", name, name)
	writef := func(format string, args ...any) {
		fmt.Fprintf(buf, "\t"+format+"\n", args...)
	}
	writef("if src == nil {")
	writef("\treturn nil")
	writef("}")
	writef("dst := new(%s)", name)
	writef("*dst = *src")
	for i := 0; i < t.NumFields(); i++ {
		fname := t.Field(i).Name()
		ft := t.Field(i).Type()
		if !codegen.ContainsPointers(ft) || codegen.HasNoClone(t.Tag(i)) {
			continue
		}
		if named, _ := ft.(*types.Named); named != nil {
			if codegen.IsViewType(ft) {
				writef("dst.%s = src.%s", fname, fname)
				continue
			}
			if !hasBasicUnderlying(ft) {
				writef("dst.%s = *src.%s.Clone()", fname, fname)
				continue
			}
		}
		switch ft := ft.Underlying().(type) {
		case *types.Slice:
			if codegen.ContainsPointers(ft.Elem()) {
				n := it.QualifiedName(ft.Elem())
				writef("dst.%s = make([]%s, len(src.%s))", fname, n, fname)
				writef("for i := range dst.%s {", fname)
				if ptr, isPtr := ft.Elem().(*types.Pointer); isPtr {
					if _, isBasic := ptr.Elem().Underlying().(*types.Basic); isBasic {
						writef("\tx := *src.%s[i]", fname)
						writef("\tdst.%s[i] = &x", fname)
					} else {
						writef("\tdst.%s[i] = src.%s[i].Clone()", fname, fname)
					}
				} else {
					writef("\tdst.%s[i] = *src.%s[i].Clone()", fname, fname)
				}
				writef("}")
			} else {
				writef("dst.%s = append(src.%s[:0:0], src.%s...)", fname, fname, fname)
			}
		case *types.Pointer:
			if named, _ := ft.Elem().(*types.Named); named != nil && codegen.ContainsPointers(ft.Elem()) {
				writef("dst.%s = src.%s.Clone()", fname, fname)
				continue
			}
			n := it.QualifiedName(ft.Elem())
			writef("if dst.%s != nil {", fname)
			writef("\tdst.%s = new(%s)", fname, n)
			writef("\t*dst.%s = *src.%s", fname, fname)
			if codegen.ContainsPointers(ft.Elem()) {
				writef("\t" + `panic("TODO pointers in pointers")`)
			}
			writef("}")
		case *types.Map:
			writef("if dst.%s != nil {", fname)
			writef("\tdst.%s = map[%s]%s{}", fname, it.QualifiedName(ft.Key()), it.QualifiedName(ft.Elem()))
			if sliceType, isSlice := ft.Elem().(*types.Slice); isSlice {
				n := it.QualifiedName(sliceType.Elem())
				writef("\tfor k := range src.%s {", fname)
				// use zero-length slice instead of nil to ensure
				// the key is always copied.
				writef("\t\tdst.%s[k] = append([]%s{}, src.%s[k]...)", fname, n, fname)
				writef("\t}")
			} else if codegen.ContainsPointers(ft.Elem()) {
				writef("\tfor k, v := range src.%s {", fname)
				writef("\t\tdst.%s[k] = v.Clone()", fname)
				writef("\t}")
			} else {
				writef("\tfor k, v := range src.%s {", fname)
				writef("\t\tdst.%s[k] = v", fname)
				writef("\t}")
			}
			writef("}")
		default:
			writef(`panic("TODO: %s (%T)")`, fname, ft)
		}
	}
	writef("return dst")
	fmt.Fprintf(buf, "}\n\n")

	buf.Write(codegen.AssertStructUnchanged(t, name, "Clone", it))
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
