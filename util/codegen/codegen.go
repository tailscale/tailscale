// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package codegen contains shared utilities for generating code.
package codegen

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"os"

	"golang.org/x/tools/go/packages"
)

// WriteFormatted writes code to path.
// It runs gofmt on it before writing;
// if gofmt fails, it writes code unchanged.
// Errors can include I/O errors and gofmt errors.
//
// The advantage of always writing code to path,
// even if gofmt fails, is that it makes debugging easier.
// The code can be long, but you need it in order to debug.
// It is nicer to work with it in a file than a terminal.
// It is also easier to interpret gofmt errors
// with an editor providing file and line numbers.
func WriteFormatted(code []byte, path string) error {
	out, fmterr := format.Source(code)
	if fmterr != nil {
		out = code
	}
	ioerr := os.WriteFile(path, out, 0644)
	// Prefer I/O errors. They're usually easier to fix,
	// and until they're fixed you can't do much else.
	if ioerr != nil {
		return ioerr
	}
	if fmterr != nil {
		return fmt.Errorf("%s:%v", path, fmterr)
	}
	return nil
}

// NamedTypes returns all named types in pkg, keyed by their type name.
func NamedTypes(pkg *packages.Package) map[string]*types.Named {
	nt := make(map[string]*types.Named)
	for _, file := range pkg.Syntax {
		for _, d := range file.Decls {
			decl, ok := d.(*ast.GenDecl)
			if !ok || decl.Tok != token.TYPE {
				continue
			}
			for _, s := range decl.Specs {
				spec, ok := s.(*ast.TypeSpec)
				if !ok {
					continue
				}
				typeNameObj := pkg.TypesInfo.Defs[spec.Name]
				typ, ok := typeNameObj.Type().(*types.Named)
				if !ok {
					continue
				}
				nt[spec.Name.Name] = typ
			}
		}
	}
	return nt
}

// AssertStructUnchanged generates code that asserts at compile time that type t is unchanged.
// thisPkg is the package containing t.
// tname is the named type corresponding to t.
// ctx is a single-word context for this assertion, such as "Clone".
// If non-nil, AssertStructUnchanged will add elements to imports
// for each package path that the caller must import for the returned code to compile.
func AssertStructUnchanged(t *types.Struct, thisPkg *types.Package, tname, ctx string, imports map[string]struct{}) []byte {
	buf := new(bytes.Buffer)
	w := func(format string, args ...interface{}) {
		fmt.Fprintf(buf, format+"\n", args...)
	}
	w("// A compilation failure here means this code must be regenerated, with the command at the top of this file.")
	w("var _%s%sNeedsRegeneration = %s(struct {", tname, ctx, tname)

	for i := 0; i < t.NumFields(); i++ {
		fname := t.Field(i).Name()
		ft := t.Field(i).Type()
		qname, imppath := importedName(ft, thisPkg)
		if imppath != "" && imports != nil {
			imports[imppath] = struct{}{}
		}
		w("\t%s %s", fname, qname)
	}

	w("}{})\n")
	return buf.Bytes()
}

func importedName(t types.Type, thisPkg *types.Package) (qualifiedName, importPkg string) {
	qual := func(pkg *types.Package) string {
		if thisPkg == pkg {
			return ""
		}
		importPkg = pkg.Path()
		return pkg.Name()
	}
	return types.TypeString(t, qual), importPkg
}

// ContainsPointers reports whether typ contains any pointers,
// either explicitly or implicitly.
// It has special handling for some types that contain pointers
// that we know are free from memory aliasing/mutation concerns.
func ContainsPointers(typ types.Type) bool {
	switch typ.String() {
	case "time.Time":
		// time.Time contains a pointer that does not need copying
		return false
	case "inet.af/netaddr.IP":
		return false
	}
	switch ft := typ.Underlying().(type) {
	case *types.Array:
		return ContainsPointers(ft.Elem())
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
			if ContainsPointers(ft.Field(i).Type()) {
				return true
			}
		}
	}
	return false
}
