// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netns

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// verifies tailscaleBypassMark is in sync with wgengine.
func TestBypassMarkInSync(t *testing.T) {
	want := fmt.Sprintf("%q", fmt.Sprintf("0x%x", tailscaleBypassMark))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../../wgengine/router/router_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != "tailscaleBypassMark" {
					continue
				}
				valExpr := vs.Values[i]
				lit, ok := valExpr.(*ast.BasicLit)
				if !ok {
					t.Errorf("tailscaleBypassMark = %T, expected *ast.BasicLit", valExpr)
				}
				if lit.Value == want {
					// Pass.
					return
				}
				t.Fatalf("router_linux.go's tailscaleBypassMark = %s; not in sync with netns's %s", lit.Value, want)
			}
		}
	}
	t.Errorf("tailscaleBypassMark not found in router_linux.go")
}
