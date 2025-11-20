// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"slices"
	"strconv"
	"strings"

	"tailscale.com/util/must"
)

// mustFormatFile formats a Go source file and adjust "json" imports.
// It panics if there are any parsing errors.
//
//   - "encoding/json" is imported under the name "jsonv1" or "jsonv1std"
//   - "encoding/json/v2" is rewritten to import "github.com/go-json-experiment/json" instead
//   - "encoding/json/jsontext" is rewritten to import "github.com/go-json-experiment/json/jsontext" instead
//   - "github.com/go-json-experiment/json" is imported under the name "jsonv2"
//   - "github.com/go-json-experiment/json/v1" is imported under the name "jsonv1"
//
// If no changes to the file is made, it returns input.
func mustFormatFile(in []byte) (out []byte) {
	fset := token.NewFileSet()
	f := must.Get(parser.ParseFile(fset, "", in, parser.ParseComments))

	// Check for the existence of "json" imports.
	jsonImports := make(map[string][]*ast.ImportSpec)
	for _, imp := range f.Imports {
		switch pkgPath := must.Get(strconv.Unquote(imp.Path.Value)); pkgPath {
		case
			"encoding/json",
			"encoding/json/v2",
			"encoding/json/jsontext",
			"github.com/go-json-experiment/json",
			"github.com/go-json-experiment/json/v1",
			"github.com/go-json-experiment/json/jsontext":
			jsonImports[pkgPath] = append(jsonImports[pkgPath], imp)
		}
	}
	if len(jsonImports) == 0 {
		return in
	}

	// Best-effort local type-check of the file
	// to resolve local declarations to detect shadowed variables.
	typeInfo := &types.Info{Uses: make(map[*ast.Ident]types.Object)}
	(&types.Config{
		Error: func(err error) {},
	}).Check("", fset, []*ast.File{f}, typeInfo)

	// Rewrite imports to instead use "github.com/go-json-experiment/json".
	// This ensures that code continues to build even if
	// goexperiment.jsonv2 is *not* specified.
	// As of https://github.com/go-json-experiment/json/pull/186,
	// imports to "github.com/go-json-experiment/json" are identical
	// to the standard library if built with goexperiment.jsonv2.
	for fromPath, toPath := range map[string]string{
		"encoding/json/v2":       "github.com/go-json-experiment/json",
		"encoding/json/jsontext": "github.com/go-json-experiment/json/jsontext",
	} {
		for _, imp := range jsonImports[fromPath] {
			imp.Path.Value = strconv.Quote(toPath)
			jsonImports[toPath] = append(jsonImports[toPath], imp)
		}
		delete(jsonImports, fromPath)
	}

	// While in a transitory state, where both v1 and v2 json imports
	// may exist in our codebase, always explicitly import with
	// either jsonv1 or jsonv2 in the package name to avoid ambiguities
	// when looking at a particular Marshal or Unmarshal call site.
	renames := make(map[string]string)        // mapping of old names to new names
	deletes := make(map[*ast.ImportSpec]bool) // set of imports to delete
	for pkgPath, imps := range jsonImports {
		var newName string
		switch pkgPath {
		case "encoding/json":
			newName = "jsonv1"
			// If "github.com/go-json-experiment/json/v1" is also imported,
			// then use jsonv1std for "encoding/json" to avoid a conflict.
			if len(jsonImports["github.com/go-json-experiment/json/v1"]) > 0 {
				newName += "std"
			}
		case "github.com/go-json-experiment/json":
			newName = "jsonv2"
		case "github.com/go-json-experiment/json/v1":
			newName = "jsonv1"
		}

		// Rename the import if different than expected.
		if oldName := importName(imps[0]); oldName != newName && newName != "" {
			renames[oldName] = newName
			pos := imps[0].Pos() // preserve original positioning
			imps[0].Name = ast.NewIdent(newName)
			imps[0].Name.NamePos = pos
		}

		// For all redundant imports, use the first imported name.
		for _, imp := range imps[1:] {
			renames[importName(imp)] = importName(imps[0])
			deletes[imp] = true
		}
	}
	if len(deletes) > 0 {
		f.Imports = slices.DeleteFunc(f.Imports, func(imp *ast.ImportSpec) bool {
			return deletes[imp]
		})
		for _, decl := range f.Decls {
			if genDecl, ok := decl.(*ast.GenDecl); ok && genDecl.Tok == token.IMPORT {
				genDecl.Specs = slices.DeleteFunc(genDecl.Specs, func(spec ast.Spec) bool {
					return deletes[spec.(*ast.ImportSpec)]
				})
			}
		}
	}
	if len(renames) > 0 {
		ast.Walk(astVisitor(func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok {
					// Just because the selector looks like "json.Marshal"
					// does not mean that it is referencing the "json" package.
					// There could be a local "json" declaration that shadows
					// the package import. Check partial type information
					// to see if there was a local declaration.
					if obj, ok := typeInfo.Uses[id]; ok {
						if _, ok := obj.(*types.PkgName); !ok {
							return true
						}
					}

					if newName, ok := renames[id.String()]; ok {
						id.Name = newName
					}
				}
			}
			return true
		}), f)
	}

	bb := new(bytes.Buffer)
	must.Do(format.Node(bb, fset, f))
	return must.Get(format.Source(bb.Bytes()))
}

// importName is the local package name used for an import.
// If no explicit local name is used, then it uses string parsing
// to derive the package name from the path, relying on the convention
// that the package name is the base name of the package path.
func importName(imp *ast.ImportSpec) string {
	if imp.Name != nil {
		return imp.Name.String()
	}
	pkgPath, _ := strconv.Unquote(imp.Path.Value)
	pkgPath = strings.TrimRight(pkgPath, "/v0123456789") // exclude version directories
	return path.Base(pkgPath)
}

// astVisitor is a function that implements [ast.Visitor].
type astVisitor func(ast.Node) bool

func (f astVisitor) Visit(node ast.Node) ast.Visitor {
	if !f(node) {
		return nil
	}
	return f
}
