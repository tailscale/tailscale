// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"tailscale.com/util/codegen"
)

// TestNamedMapWithView tests that a named map type with a user-supplied
// View() method causes the generated view accessor to call .View() and
// return the user-defined view type. Without the View() method the
// generator should reject the field as unsupported.
func TestNamedMapWithView(t *testing.T) {
	const src = `
package test

// AttrMap is a named map whose values are opaque (any).
// It provides its own Clone and View methods.
type AttrMap map[string]any

func (m AttrMap) Clone() AttrMap {
	m2 := make(AttrMap, len(m))
	for k, v := range m { m2[k] = v }
	return m2
}

// AttrMapView is a hand-written read-only view of AttrMap.
type AttrMapView struct{ m AttrMap }

func (m AttrMap) View() AttrMapView { return AttrMapView{m} }

// Container holds an AttrMap field.
type Container struct {
	Attrs AttrMap
}
`
	output := genViewOutput(t, src, "Container")

	// The generated accessor must call .View() and return the
	// user-defined AttrMapView, not views.Map or the raw AttrMap.
	const want = "func (v ContainerView) Attrs() AttrMapView { return v.ж.Attrs.View() }"
	if !strings.Contains(output, want) {
		t.Errorf("generated output missing expected accessor\nwant: %s\ngot:\n%s", want, output)
	}
}

// TestNamedMapWithoutView tests that a named map[string]any WITHOUT a
// View() method does NOT generate an accessor that calls .View().
func TestNamedMapWithoutView(t *testing.T) {
	const src = `
package test

type AttrMap map[string]any

func (m AttrMap) Clone() AttrMap {
	m2 := make(AttrMap, len(m))
	for k, v := range m { m2[k] = v }
	return m2
}

type Container struct {
	Attrs AttrMap
}
`
	output := genViewOutput(t, src, "Container")

	// Must not generate an accessor that calls .Attrs.View(),
	// since AttrMap doesn't have a View() method.
	if strings.Contains(output, "Attrs.View()") {
		t.Errorf("generated code calls .Attrs.View() but AttrMap has no View method:\n%s", output)
	}
	// Must not return AttrMapView (which doesn't exist).
	if strings.Contains(output, "AttrMapView") {
		t.Errorf("generated code references AttrMapView but it doesn't exist:\n%s", output)
	}
}

// genViewOutput parses src, runs genView on the named type, and returns
// the generated Go source.
func genViewOutput(t *testing.T, src string, typeName string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	conf := types.Config{}
	pkg, err := conf.Check("test", fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj := pkg.Scope().Lookup(typeName)
	if obj == nil {
		t.Fatalf("type %q not found", typeName)
	}
	named, ok := obj.(*types.TypeName).Type().(*types.Named)
	if !ok {
		t.Fatalf("%q is not a named type", typeName)
	}
	var buf bytes.Buffer
	tracker := codegen.NewImportTracker(pkg)
	genView(&buf, tracker, named, nil)
	return buf.String()
}

func TestViewerImports(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		typeNames   []string
		wantImports [][2]string
	}{
		{
			name:        "Map",
			content:     `type Test struct { Map map[string]int }`,
			typeNames:   []string{"Test"},
			wantImports: [][2]string{{"", "tailscale.com/types/views"}},
		},
		{
			name:        "Slice",
			content:     `type Test struct { Slice []int }`,
			typeNames:   []string{"Test"},
			wantImports: [][2]string{{"", "tailscale.com/types/views"}},
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
			var fieldComments map[fieldNameKey]string // don't need it for this test.

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
				genView(&output, tracker, namedType, fieldComments)
			}

			for _, pkg := range tt.wantImports {
				if !tracker.Has(pkg[0], pkg[1]) {
					t.Errorf("missing import %q", pkg)
				}
			}
		})
	}
}
