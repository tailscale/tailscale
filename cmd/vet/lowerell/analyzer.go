// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package lowerell forbids variables named "l" (lowercase ell) or "I"
// (uppercase i), because they are hard to distinguish from the digit
// "1" and from each other in too many fonts.
package lowerell

import (
	"go/ast"
	"go/token"

	"golang.org/x/tools/go/analysis"
)

// Analyzer reports variables named "l" (lowercase ell) or "I" (uppercase i).
var Analyzer = &analysis.Analyzer{
	Name: "lowerell",
	Doc:  `forbid variables named "l" (lowercase ell) or "I" (uppercase i), which are hard to distinguish from "1"`,
	Run:  run,
}

// messages maps a banned identifier name to the diagnostic shown to users.
// Each message names the specific symbol that triggered it, so the
// reader does not have to guess which of "l" or "I" they typed.
var messages = map[string]string{
	"l": `do not use "l" (lowercase ell) as a variable name; it is hard to distinguish from "1" and "I" in too many fonts; see https://github.com/tailscale/tailscale/issues/19631`,
	"I": `do not use "I" (uppercase i) as a variable name; it is hard to distinguish from "1" and "l" in too many fonts; see https://github.com/tailscale/tailscale/issues/19631`,
}

// reported tracks identifier positions already reported, to avoid duplicate
// diagnostics when the same declaration is reachable from multiple AST nodes.
type reportedSet map[token.Pos]bool

func (rs reportedSet) check(pass *analysis.Pass, ident *ast.Ident) {
	if ident == nil {
		return
	}
	msg, ok := messages[ident.Name]
	if !ok {
		return
	}
	if rs[ident.Pos()] {
		return
	}
	rs[ident.Pos()] = true
	pass.Reportf(ident.Pos(), "%s", msg)
}

func (rs reportedSet) checkFieldList(pass *analysis.Pass, fl *ast.FieldList) {
	if fl == nil {
		return
	}
	for _, f := range fl.List {
		for _, n := range f.Names {
			rs.check(pass, n)
		}
	}
}

func run(pass *analysis.Pass) (any, error) {
	rs := reportedSet{}

	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				// Receiver name.
				rs.checkFieldList(pass, n.Recv)
				// Parameters, results, and type parameters
				// are checked via the FuncType case below.

			case *ast.FuncType:
				rs.checkFieldList(pass, n.TypeParams)
				rs.checkFieldList(pass, n.Params)
				rs.checkFieldList(pass, n.Results)

			case *ast.StructType:
				rs.checkFieldList(pass, n.Fields)

			case *ast.GenDecl:
				if n.Tok != token.VAR && n.Tok != token.CONST {
					return true
				}
				for _, spec := range n.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range vs.Names {
						rs.check(pass, name)
					}
				}

			case *ast.AssignStmt:
				if n.Tok != token.DEFINE {
					return true
				}
				for _, lhs := range n.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						rs.check(pass, id)
					}
				}

			case *ast.RangeStmt:
				if n.Tok != token.DEFINE {
					return true
				}
				if id, ok := n.Key.(*ast.Ident); ok {
					rs.check(pass, id)
				}
				if id, ok := n.Value.(*ast.Ident); ok {
					rs.check(pass, id)
				}

			case *ast.TypeSwitchStmt:
				// switch l := x.(type) { ... }
				as, ok := n.Assign.(*ast.AssignStmt)
				if !ok || as.Tok != token.DEFINE {
					return true
				}
				for _, lhs := range as.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						rs.check(pass, id)
					}
				}
			}
			return true
		})
	}
	return nil, nil
}
