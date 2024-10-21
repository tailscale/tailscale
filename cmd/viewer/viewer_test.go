// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"tailscale.com/util/codegen"
)

func TestViewerImports(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		typeNames   []string
		wantImports []string
	}{
		{
			name:        "Map",
			content:     `type Test struct { Map map[string]int }`,
			typeNames:   []string{"Test"},
			wantImports: []string{"tailscale.com/types/views"},
		},
		{
			name:        "Slice",
			content:     `type Test struct { Slice []int }`,
			typeNames:   []string{"Test"},
			wantImports: []string{"tailscale.com/types/views"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "test.go", "package test\n\n"+tt.content, 0)
			if err != nil {
				fmt.Println("Error parsing:", err)
				return
			}

			info := &types.Info{
				Types: make(map[ast.Expr]types.TypeAndValue),
			}

			conf := types.Config{}
			pkg, err := conf.Check("", fset, []*ast.File{f}, info)
			if err != nil {
				t.Fatal(err)
			}

			var output bytes.Buffer
			tracker := codegen.NewImportTracker(pkg)
			for i := range tt.typeNames {
				typeName, ok := pkg.Scope().Lookup(tt.typeNames[i]).(*types.TypeName)
				if !ok {
					t.Fatalf("type %q does not exist", tt.typeNames[i])
				}
				namedType, ok := typeName.Type().(*types.Named)
				if !ok {
					t.Fatalf("%q is not a named type", tt.typeNames[i])
				}
				genView(&output, tracker, namedType, pkg)
			}

			for _, pkgName := range tt.wantImports {
				if !tracker.Has(pkgName) {
					t.Errorf("missing import %q", pkgName)
				}
			}
		})
	}
}
