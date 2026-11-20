// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlknobs

import (
	"go/ast"
	"go/constant"
	"go/types"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"testing"

	gcmp "github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages"

	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/logger"
)

func TestKnobContainsNodeCapDocComment(t *testing.T) {
	cfg := &packages.Config{Mode: packages.NeedSyntax | packages.NeedTypes}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("loaded too many packages: %v", pkgs)
	}
	pkg := pkgs[0]

	if len(pkg.Errors) != 0 {
		t.Fatalf("loading package: %v", pkg.Errors)
	}

	var nodecaps *types.Scope
	for _, imp := range pkg.Types.Imports() {
		if imp.Path() == reflect.TypeFor[nodecap.Cap]().PkgPath() {
			nodecaps = imp.Scope()
			break
		}
	}
	if nodecaps == nil {
		t.Fatal("nodecap package not imported")
	}

	var fields []*ast.Field
Fields:
	for _, f := range pkg.Syntax {
		for n := range ast.Preorder(f) {
			if ts, ok := n.(*ast.TypeSpec); ok && ts.Name.Name == "Knobs" {
				fields = ts.Type.(*ast.StructType).Fields.List
				break Fields
			}
		}
	}
	if fields == nil {
		t.Fatal("Knobs fields not found")
	}

	base := new(Knobs)
	base.UpdateFromNodeAttributes(nil)
	baseJSON := base.AsDebugJSON()

	docRef := regexp.MustCompile(`\[nodecap\.(\w+)\]`)
	for _, f := range fields {
		for _, id := range f.Names {
			refs := docRef.FindAllStringSubmatch(f.Doc.Text(), -1)
			if len(refs) == 0 {
				t.Errorf("%s: doc comment missing link to [nodecap.Cap] for this knob", id.Name)
				break
			}

			for _, ref := range refs {
				nc, ok := nodecaps.Lookup(ref[1]).(*types.Const)
				if !ok {
					t.Errorf("%s: doc comment names unknown nodecap.%s", id.Name, ref[1])
					continue
				}

				k := new(Knobs)
				k.UpdateFromNodeAttributes(tailcfg.NodeCapMap{
					nodecap.Cap(constant.StringVal(nc.Val())): nil,
				})
				if got := k.AsDebugJSON()[id.Name]; got == baseJSON[id.Name] {
					t.Errorf("%s: nodecap.%s did not affect this knob; still %v", id.Name, ref[1], got)
				}
			}
		}
	}
}

func TestAsDebugJSON(t *testing.T) {
	var nilPtr *Knobs
	if got := nilPtr.AsDebugJSON(); got != nil {
		t.Errorf("AsDebugJSON(nil) = %v; want nil", got)
	}

	var wantKeys []string
	for f := range reflect.TypeFor[Knobs]().Fields() {
		wantKeys = append(wantKeys, f.Name)
	}
	slices.Sort(wantKeys)

	k := new(Knobs)
	got := k.AsDebugJSON()
	gotKeys := slices.Sorted(maps.Keys(got))

	if diff := gcmp.Diff(wantKeys, gotKeys); diff != "" {
		t.Errorf("AsDebugJSON keys (-want +got)\n%s", diff)
	}
	t.Logf("Got: %v", logger.AsJSON(got))
}
