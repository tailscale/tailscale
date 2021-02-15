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
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"golang.org/x/tools/go/packages"
)

var (
	flagTypes     = flag.String("type", "", "comma-separated list of types; required")
	flagOutput    = flag.String("output", "", "output file; required")
	flagBuildTags = flag.String("tags", "", "compiler build tags to apply")
	flagCloneFunc = flag.Bool("clonefunc", false, "add a top-level Clone func")
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("cloner: ")
	flag.Parse()
	if *flagTypes == "" {
		flag.Usage()
		os.Exit(2)
	}
	typeNames := strings.Split(*flagTypes, ",")

	cfg := &packages.Config{
		Mode:  packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax | packages.NeedName,
		Tests: false,
	}
	if *flagBuildTags != "" {
		cfg.BuildFlags = []string{"-tags=" + *flagBuildTags}
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		log.Fatal(err)
	}
	if len(pkgs) != 1 {
		log.Fatalf("wrong number of packages: %d", len(pkgs))
	}
	pkg := pkgs[0]
	buf := new(bytes.Buffer)
	imports := make(map[string]struct{})
	for _, typeName := range typeNames {
		found := false
		for _, file := range pkg.Syntax {
			//var fbuf bytes.Buffer
			//ast.Fprint(&fbuf, pkg.Fset, file, nil)
			//fmt.Println(fbuf.String())

			for _, d := range file.Decls {
				decl, ok := d.(*ast.GenDecl)
				if !ok || decl.Tok != token.TYPE {
					continue
				}
				for _, s := range decl.Specs {
					spec, ok := s.(*ast.TypeSpec)
					if !ok || spec.Name.Name != typeName {
						continue
					}
					typeNameObj := pkg.TypesInfo.Defs[spec.Name]
					typ, ok := typeNameObj.Type().(*types.Named)
					if !ok {
						continue
					}
					pkg := typeNameObj.Pkg()
					gen(buf, imports, typeName, typ, pkg)
					found = true
				}
			}
		}
		if !found {
			log.Fatalf("could not find type %s", typeName)
		}
	}

	w := func(format string, args ...interface{}) {
		fmt.Fprintf(buf, format+"\n", args...)
	}
	if *flagCloneFunc {
		w("// Clone duplicates src into dst and reports whether it succeeded.")
		w("// To succeed, <src, dst> must be of types <*T, *T> or <*T, **T>,")
		w("// where T is one of %s.", *flagTypes)
		w("func Clone(dst, src interface{}) bool {")
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

	contents := new(bytes.Buffer)
	fmt.Fprintf(contents, header, *flagTypes, pkg.Name)
	fmt.Fprintf(contents, "import (\n")
	for s := range imports {
		fmt.Fprintf(contents, "\t%q\n", s)
	}
	fmt.Fprintf(contents, ")\n\n")
	contents.Write(buf.Bytes())

	out, err := format.Source(contents.Bytes())
	if err != nil {
		log.Fatalf("%s, in source:\n%s", err, contents.Bytes())
	}

	output := *flagOutput
	if output == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := ioutil.WriteFile(output, out, 0644); err != nil {
		log.Fatal(err)
	}
}

const header = `// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by tailscale.com/cmd/cloner -type %s; DO NOT EDIT.

package %s

`

func gen(buf *bytes.Buffer, imports map[string]struct{}, name string, typ *types.Named, thisPkg *types.Package) {
	pkgQual := func(pkg *types.Package) string {
		if thisPkg == pkg {
			return ""
		}
		imports[pkg.Path()] = struct{}{}
		return pkg.Name()
	}
	importedName := func(t types.Type) string {
		return types.TypeString(t, pkgQual)
	}

	switch t := typ.Underlying().(type) {
	case *types.Struct:
		// We generate two bits of code simultaneously while we walk the struct.
		// One is the Clone method itself, which we write directly to buf.
		// The other is a variable assignment that will fail if the struct
		// changes without the Clone method getting regenerated.
		// We write that to regenBuf, and then append it to buf at the end.
		regenBuf := new(bytes.Buffer)
		writeRegen := func(format string, args ...interface{}) {
			fmt.Fprintf(regenBuf, format+"\n", args...)
		}
		writeRegen("// A compilation failure here means this code must be regenerated, with command:")
		writeRegen("//   tailscale.com/cmd/cloner -type %s", *flagTypes)
		writeRegen("var _%sNeedsRegeneration = %s(struct {", name, name)

		name := typ.Obj().Name()
		fmt.Fprintf(buf, "// Clone makes a deep copy of %s.\n", name)
		fmt.Fprintf(buf, "// The result aliases no memory with the original.\n")
		fmt.Fprintf(buf, "func (src *%s) Clone() *%s {\n", name, name)
		writef := func(format string, args ...interface{}) {
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

			writeRegen("\t%s %s", fname, importedName(ft))

			if !containsPointers(ft) {
				continue
			}
			if named, _ := ft.(*types.Named); named != nil && !hasBasicUnderlying(ft) {
				writef("dst.%s = *src.%s.Clone()", fname, fname)
				continue
			}
			switch ft := ft.Underlying().(type) {
			case *types.Slice:
				if containsPointers(ft.Elem()) {
					n := importedName(ft.Elem())
					writef("dst.%s = make([]%s, len(src.%s))", fname, n, fname)
					writef("for i := range dst.%s {", fname)
					if _, isPtr := ft.Elem().(*types.Pointer); isPtr {
						writef("\tdst.%s[i] = src.%s[i].Clone()", fname, fname)
					} else {
						writef("\tdst.%s[i] = *src.%s[i].Clone()", fname, fname)
					}
					writef("}")
				} else {
					writef("dst.%s = append(src.%s[:0:0], src.%s...)", fname, fname, fname)
				}
			case *types.Pointer:
				if named, _ := ft.Elem().(*types.Named); named != nil && containsPointers(ft.Elem()) {
					writef("dst.%s = src.%s.Clone()", fname, fname)
					continue
				}
				n := importedName(ft.Elem())
				writef("if dst.%s != nil {", fname)
				writef("\tdst.%s = new(%s)", fname, n)
				writef("\t*dst.%s = *src.%s", fname, fname)
				if containsPointers(ft.Elem()) {
					writef("\t" + `panic("TODO pointers in pointers")`)
				}
				writef("}")
			case *types.Map:
				writef("if dst.%s != nil {", fname)
				writef("\tdst.%s = map[%s]%s{}", fname, importedName(ft.Key()), importedName(ft.Elem()))
				if sliceType, isSlice := ft.Elem().(*types.Slice); isSlice {
					n := importedName(sliceType.Elem())
					writef("\tfor k := range src.%s {", fname)
					// use zero-length slice instead of nil to ensure
					// the key is always copied.
					writef("\t\tdst.%s[k] = append([]%s{}, src.%s[k]...)", fname, n, fname)
					writef("\t}")
				} else if containsPointers(ft.Elem()) {
					writef("\t\t" + `panic("TODO map value pointers")`)
				} else {
					writef("\tfor k, v := range src.%s {", fname)
					writef("\t\tdst.%s[k] = v", fname)
					writef("\t}")
				}
				writef("}")
			case *types.Struct:
				writef(`panic("TODO struct %s")`, fname)
			default:
				writef(`panic(fmt.Sprintf("TODO: %T", ft))`)
			}
		}
		writef("return dst")
		fmt.Fprintf(buf, "}\n\n")

		writeRegen("}{})\n")

		buf.Write(regenBuf.Bytes())
	}
}

func hasBasicUnderlying(typ types.Type) bool {
	switch typ.Underlying().(type) {
	case *types.Slice, *types.Map:
		return true
	default:
		return false
	}
}

func containsPointers(typ types.Type) bool {
	switch typ.String() {
	case "time.Time":
		// time.Time contains a pointer that does not need copying
		return false
	case "inet.af/netaddr.IP":
		return false
	}
	switch ft := typ.Underlying().(type) {
	case *types.Array:
		return containsPointers(ft.Elem())
	case *types.Chan:
		return true
	case *types.Interface:
		return true // a little too broad
	case *types.Map:
		return true
	case *types.Pointer:
		return true
	case *types.Slice:
		return true
	case *types.Struct:
		for i := 0; i < ft.NumFields(); i++ {
			if containsPointers(ft.Field(i).Type()) {
				return true
			}
		}
	}
	return false
}
