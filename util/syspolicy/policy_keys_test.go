// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"reflect"
	"strconv"
	"testing"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/setting"
)

func TestKnownKeysRegistered(t *testing.T) {
	const file = "pkey/pkey.go"
	keyConsts, err := listStringConsts[pkey.Key](file)
	if err != nil {
		t.Fatalf("listStringConsts failed: %v", err)
	}
	if len(keyConsts) == 0 {
		t.Fatalf("no key constants found in %s", file)
	}

	m, err := setting.DefinitionMapOf(implicitDefinitions)
	if err != nil {
		t.Fatalf("definitionMapOf failed: %v", err)
	}

	for _, key := range keyConsts {
		t.Run(string(key), func(t *testing.T) {
			d := m[key]
			if d == nil {
				t.Fatalf("%q was not registered", key)
			}
			if d.Key() != key {
				t.Fatalf("d.Key got: %s, want %s", d.Key(), key)
			}
		})
	}
}

func listStringConsts[T ~string](filename string) (map[string]T, error) {
	fset := token.NewFileSet()
	src, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}

	consts := make(map[string]T)
	typeName := reflect.TypeFor[T]().Name()
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}

		for _, s := range g.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok || len(vs.Names) != len(vs.Values) {
				continue
			}
			if typ, ok := vs.Type.(*ast.Ident); !ok || typ.Name != typeName {
				continue
			}

			for i, n := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok {
					return nil, fmt.Errorf("unexpected string literal: %v = %v", n.Name, types.ExprString(vs.Values[i]))
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					return nil, fmt.Errorf("unexpected string literal: %v = %v", n.Name, lit.Value)
				}
				consts[n.Name] = T(val)
			}
		}
	}

	return consts, nil
}
