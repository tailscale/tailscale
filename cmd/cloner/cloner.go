// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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
		typ, ok := namedTypes[typeName].(*types.Named)
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
	cloneOutput := pkg.Name + "_clone"
	if *flagBuildTags == "test" {
		cloneOutput += "_test"
	}
	cloneOutput += ".go"
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
	typeParams := typ.Origin().TypeParams()
	_, typeParamNames := codegen.FormatTypeParams(typeParams, it)
	nameWithParams := name + typeParamNames
	fmt.Fprintf(buf, "// Clone makes a deep copy of %s.\n", name)
	fmt.Fprintf(buf, "// The result aliases no memory with the original.\n")
	fmt.Fprintf(buf, "func (src *%s) Clone() *%s {\n", nameWithParams, nameWithParams)
	writef := func(format string, args ...any) {
		fmt.Fprintf(buf, "\t"+format+"\n", args...)
	}
	writef("if src == nil {")
	writef("\treturn nil")
	writef("}")
	writef("dst := new(%s)", nameWithParams)
	writef("*dst = *src")
	for i := range t.NumFields() {
		fname := t.Field(i).Name()
		ft := t.Field(i).Type()
		if !codegen.ContainsPointers(ft) || codegen.HasNoClone(t.Tag(i)) {
			continue
		}
		if named, _ := codegen.NamedTypeOf(ft); named != nil {
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
				writef("if src.%s != nil {", fname)
				writef("dst.%s = make([]%s, len(src.%s))", fname, n, fname)
				writef("for i := range dst.%s {", fname)
				if ptr, isPtr := ft.Elem().(*types.Pointer); isPtr {
					writef("if src.%s[i] == nil { dst.%s[i] = nil } else {", fname, fname)
					if codegen.ContainsPointers(ptr.Elem()) {
						if _, isIface := ptr.Elem().Underlying().(*types.Interface); isIface {
							it.Import("", "tailscale.com/types/ptr")
							writef("\tdst.%s[i] = ptr.To((*src.%s[i]).Clone())", fname, fname)
						} else {
							writef("\tdst.%s[i] = src.%s[i].Clone()", fname, fname)
						}
					} else {
						it.Import("", "tailscale.com/types/ptr")
						writef("\tdst.%s[i] = ptr.To(*src.%s[i])", fname, fname)
					}
					writef("}")
				} else if ft.Elem().String() == "encoding/json.RawMessage" {
					writef("\tdst.%s[i] = append(src.%s[i][:0:0], src.%s[i]...)", fname, fname, fname)
				} else if _, isIface := ft.Elem().Underlying().(*types.Interface); isIface {
					writef("\tdst.%s[i] = src.%s[i].Clone()", fname, fname)
				} else {
					writef("\tdst.%s[i] = *src.%s[i].Clone()", fname, fname)
				}
				writef("}")
				writef("}")
			} else {
				writef("dst.%s = append(src.%s[:0:0], src.%s...)", fname, fname, fname)
			}
		case *types.Pointer:
			base := ft.Elem()
			hasPtrs := codegen.ContainsPointers(base)
			if named, _ := codegen.NamedTypeOf(base); named != nil && hasPtrs {
				writef("dst.%s = src.%s.Clone()", fname, fname)
				continue
			}
			it.Import("", "tailscale.com/types/ptr")
			writef("if dst.%s != nil {", fname)
			if _, isIface := base.Underlying().(*types.Interface); isIface && hasPtrs {
				writef("\tdst.%s = ptr.To((*src.%s).Clone())", fname, fname)
			} else if !hasPtrs {
				writef("\tdst.%s = ptr.To(*src.%s)", fname, fname)
			} else {
				writef("\t" + `panic("TODO pointers in pointers")`)
			}
			writef("}")
		case *types.Map:
			elem := ft.Elem()
			if sliceType, isSlice := elem.(*types.Slice); isSlice {
				n := it.QualifiedName(sliceType.Elem())
				writef("if dst.%s != nil {", fname)
				writef("\tdst.%s = map[%s]%s{}", fname, it.QualifiedName(ft.Key()), it.QualifiedName(elem))
				writef("\tfor k := range src.%s {", fname)
				// use zero-length slice instead of nil to ensure
				// the key is always copied.
				writef("\t\tdst.%s[k] = append([]%s{}, src.%s[k]...)", fname, n, fname)
				writef("\t}")
				writef("}")
			} else if codegen.ContainsPointers(elem) {
				writef("if dst.%s != nil {", fname)
				writef("\tdst.%s = map[%s]%s{}", fname, it.QualifiedName(ft.Key()), it.QualifiedName(elem))
				writef("\tfor k, v := range src.%s {", fname)

				switch elem := elem.Underlying().(type) {
				case *types.Pointer:
					writef("\t\tif v == nil { dst.%s[k] = nil } else {", fname)
					if base := elem.Elem().Underlying(); codegen.ContainsPointers(base) {
						if _, isIface := base.(*types.Interface); isIface {
							it.Import("", "tailscale.com/types/ptr")
							writef("\t\t\tdst.%s[k] = ptr.To((*v).Clone())", fname)
						} else {
							writef("\t\t\tdst.%s[k] = v.Clone()", fname)
						}
					} else {
						it.Import("", "tailscale.com/types/ptr")
						writef("\t\t\tdst.%s[k] = ptr.To(*v)", fname)
					}
					writef("}")
				case *types.Interface:
					if cloneResultType := methodResultType(elem, "Clone"); cloneResultType != nil {
						if _, isPtr := cloneResultType.(*types.Pointer); isPtr {
							writef("\t\tdst.%s[k] = *(v.Clone())", fname)
						} else {
							writef("\t\tdst.%s[k] = v.Clone()", fname)
						}
					} else {
						writef(`panic("%s (%v) does not have a Clone method")`, fname, elem)
					}
				default:
					writef("\t\tdst.%s[k] = *(v.Clone())", fname)
				}

				writef("\t}")
				writef("}")
			} else {
				it.Import("", "maps")
				writef("\tdst.%s = maps.Clone(src.%s)", fname, fname)
			}
		case *types.Interface:
			// If ft is an interface with a "Clone() ft" method, it can be used to clone the field.
			// This includes scenarios where ft is a constrained type parameter.
			if cloneResultType := methodResultType(ft, "Clone"); cloneResultType.Underlying() == ft {
				writef("dst.%s = src.%s.Clone()", fname, fname)
				continue
			}
			writef(`panic("%s (%v) does not have a compatible Clone method")`, fname, ft)
		default:
			writef(`panic("TODO: %s (%T)")`, fname, ft)
		}
	}
	writef("return dst")
	fmt.Fprintf(buf, "}\n\n")

	buf.Write(codegen.AssertStructUnchanged(t, name, typeParams, "Clone", it))
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

func methodResultType(typ types.Type, method string) types.Type {
	viewMethod := codegen.LookupMethod(typ, method)
	if viewMethod == nil {
		return nil
	}
	sig, ok := viewMethod.Type().(*types.Signature)
	if !ok || sig.Results().Len() != 1 {
		return nil
	}
	return sig.Results().At(0).Type()
}
