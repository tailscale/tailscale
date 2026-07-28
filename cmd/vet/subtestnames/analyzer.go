// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package subtestnames checks that t.Run subtest names don't contain characters
// that require quoting or escaping when re-running via "go test -run".
//
// Go's testing package rewrites subtest names: spaces become underscores,
// non-printable characters get escaped, and regex metacharacters require
// escaping in -run patterns. This makes it hard to re-run specific subtests
// or search for them in code.
//
// This analyzer flags:
//   - Direct t.Run calls with string literal names containing bad characters
//   - t.Run calls using tt.name (or similar) where tt ranges over a slice/map
//     of test cases with string literal names containing bad characters
package subtestnames

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Analyzer checks that t.Run subtest names are clean for use with "go test -run".
var Analyzer = &analysis.Analyzer{
	Name:     "subtestnames",
	Doc:      "check that t.Run subtest names don't require quoting when re-running via go test -run",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

// badChars are characters that are problematic in subtest names.
// Spaces are rewritten to underscores by testing.rewrite, and regex
// metacharacters require escaping in -run patterns.
const badChars = " \t\n\r^$.*+?()[]{}|\\'\"#"

// hasBadChar reports whether s contains any character that would be
// problematic in a subtest name.
func hasBadChar(s string) bool {
	return strings.ContainsAny(s, badChars) || strings.ContainsFunc(s, func(r rune) bool {
		return !unicode.IsPrint(r)
	})
}

// hasBadDash reports whether s starts or ends with a dash, which is
// problematic in subtest names because "go test -run" may interpret a
// leading dash as a flag, and trailing dashes are confusing.
func hasBadDash(s string) bool {
	return strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-")
}

func run(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	// Build a stack of enclosing nodes so we can find the RangeStmt
	// enclosing a given t.Run call.
	nodeFilter := []ast.Node{
		(*ast.RangeStmt)(nil),
		(*ast.CallExpr)(nil),
	}

	var rangeStack []*ast.RangeStmt

	insp.Nodes(nodeFilter, func(n ast.Node, push bool) bool {
		switch n := n.(type) {
		case *ast.RangeStmt:
			if push {
				rangeStack = append(rangeStack, n)
			} else {
				rangeStack = rangeStack[:len(rangeStack)-1]
			}
			return true
		case *ast.CallExpr:
			if !push {
				return true
			}
			checkCallExpr(pass, n, rangeStack)
			return true
		}
		return true
	})

	return nil, nil
}

func checkCallExpr(pass *analysis.Pass, call *ast.CallExpr, rangeStack []*ast.RangeStmt) {
	// Check if this is a t.Run(...) or b.Run(...) call.
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Run" || len(call.Args) < 2 {
		return
	}

	// Verify the receiver is *testing.T, *testing.B, or *testing.F.
	if !isTestingTBF(pass, sel) {
		return
	}

	nameArg := call.Args[0]

	// Case 1: Direct string literal, e.g. t.Run("foo bar", ...)
	if lit, ok := nameArg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		val, err := strconv.Unquote(lit.Value)
		if err != nil {
			return
		}
		if hasBadChar(val) {
			pass.Reportf(lit.Pos(), "subtest name %s contains characters that require quoting in go test -run patterns", lit.Value)
		} else if hasBadDash(val) {
			pass.Reportf(lit.Pos(), "subtest name %s starts or ends with '-' which is problematic in go test -run patterns", lit.Value)
		}
		return
	}

	// Case 2: Selector expression like tt.name, tc.name, etc.
	// where tt is a range variable over a slice/map of test cases.
	selExpr, ok := nameArg.(*ast.SelectorExpr)
	if !ok {
		return
	}
	ident, ok := selExpr.X.(*ast.Ident)
	if !ok {
		return
	}

	// Find the enclosing range statement where ident is the value variable.
	for i := len(rangeStack) - 1; i >= 0; i-- {
		rs := rangeStack[i]
		valIdent, ok := rs.Value.(*ast.Ident)
		if !ok || valIdent.Obj != ident.Obj {
			continue
		}
		// Found the range statement. Check the source being iterated.
		checkRangeSource(pass, rs.X, selExpr.Sel)
		return
	}
}

// isTestingTBF checks whether sel looks like a method call on *testing.T, *testing.B, or *testing.F.
func isTestingTBF(pass *analysis.Pass, sel *ast.SelectorExpr) bool {
	typ := pass.TypesInfo.TypeOf(sel.X)
	if typ != nil {
		s := typ.String()
		return s == "*testing.T" || s == "*testing.B" || s == "*testing.F"
	}
	return false
}

// checkRangeSource examines the expression being ranged over and checks
// composite literal elements for bad subtest name fields.
func checkRangeSource(pass *analysis.Pass, rangeExpr ast.Expr, fieldName *ast.Ident) {
	switch x := rangeExpr.(type) {
	case *ast.Ident:
		if x.Obj == nil {
			return
		}
		switch decl := x.Obj.Decl.(type) {
		case *ast.AssignStmt:
			// e.g. tests := []struct{...}{...}
			for _, rhs := range decl.Rhs {
				checkCompositeLit(pass, rhs, fieldName)
			}
		case *ast.ValueSpec:
			// e.g. var tests = []struct{...}{...}
			for _, val := range decl.Values {
				checkCompositeLit(pass, val, fieldName)
			}
		}
	case *ast.CompositeLit:
		checkCompositeLit(pass, x, fieldName)
	}
}

// checkCompositeLit checks a composite literal (slice/map) for elements
// that have a field with a bad subtest name.
func checkCompositeLit(pass *analysis.Pass, expr ast.Expr, fieldName *ast.Ident) {
	comp, ok := expr.(*ast.CompositeLit)
	if !ok {
		return
	}

	for _, elt := range comp.Elts {
		// For map literals, check the value.
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			elt = kv.Value
		}
		checkStructLitField(pass, elt, fieldName)
	}
}

// checkStructLitField checks a struct literal for a field with the given name
// that contains a bad subtest name string.
func checkStructLitField(pass *analysis.Pass, expr ast.Expr, fieldName *ast.Ident) {
	comp, ok := expr.(*ast.CompositeLit)
	if !ok {
		return
	}

	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != fieldName.Name {
			continue
		}
		lit, ok := kv.Value.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		val, err := strconv.Unquote(lit.Value)
		if err != nil {
			continue
		}
		if hasBadChar(val) {
			pass.Reportf(lit.Pos(), "subtest name %s contains characters that require quoting in go test -run patterns", lit.Value)
		} else if hasBadDash(val) {
			pass.Reportf(lit.Pos(), "subtest name %s starts or ends with '-' which is problematic in go test -run patterns", lit.Value)
		}
	}
}
