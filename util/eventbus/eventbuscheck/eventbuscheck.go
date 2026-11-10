// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package eventbuscheck statically finds event types that are used with an
// [tailscale.com/util/eventbus.Bus] both by value and by pointer.
//
// The eventbus routes events by exact type, so a subscriber of *T never sees
// events published as T. Pointer event types are fine, but a program must use
// each event type in only one form. Because the publisher and subscriber of a
// type are often in packages that don't import each other, this is a
// whole-program check rather than a vet analyzer.
package eventbuscheck

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"
	"tailscale.com/util/set"
)

const (
	eventbusPath     = "tailscale.com/util/eventbus"
	eventbustestPath = "tailscale.com/util/eventbus/eventbustest"
)

// typeArgFuncs are the generic functions whose first type argument is an event
// type.
var typeArgFuncs = map[string]bool{
	eventbusPath + ".Publish":       true,
	eventbusPath + ".Subscribe":     true,
	eventbusPath + ".SubscribeFunc": true,
	eventbustestPath + ".Inject":    true,
	eventbustestPath + ".Type":      true,
	eventbustestPath + ".EqualTo":   true,
}

// filterFuncs are the functions whose variadic arguments are event filter
// funcs whose first parameter is an event type.
var filterFuncs = map[string]bool{
	eventbustestPath + ".Expect":        true,
	eventbustestPath + ".ExpectExactly": true,
}

// Site is a use of an event type in an eventbus call.
type Site struct {
	Pos  token.Position
	Func string // name of the eventbus or eventbustest func, like "eventbus.Publish"
	Type string // event type, fully qualified, like "*tailscale.com/tailcfg.ClientVersion"
}

// Mismatch is an event type that is used both by value and by pointer.
type Mismatch struct {
	Type  string // the non-pointer form of the event type
	Sites []Site // all uses of the type in either form, sorted by position
}

func (m Mismatch) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "eventbus event type %s is used both by value and by pointer:", m.Type)
	for _, s := range m.Sites {
		fmt.Fprintf(&sb, "\n\t%s: %s[%s]", s.Pos, s.Func, s.Type)
	}
	return sb.String()
}

// Check loads the packages matching patterns from dir, along with their tests
// and dependencies, once for each GOOS in goos with GOARCH=amd64. It returns
// the event types used both by value and by pointer across all of them.
func Check(dir string, goos []string, patterns ...string) ([]Mismatch, error) {
	var sites []Site
	for _, g := range goos {
		s, err := loadSites(dir, g, patterns)
		if err != nil {
			return nil, fmt.Errorf("GOOS=%s: %w", g, err)
		}
		sites = append(sites, s...)
	}
	return mismatches(sites), nil
}

// loadSites returns the uses of event types in the packages matching
// patterns and all their dependencies, type-checked from source for goos.
func loadSites(dir, goos string, patterns []string) ([]Site, error) {
	env := append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0")

	// Find the packages that import eventbus or eventbustest, which are the
	// only ones that can use an event type, without type-checking anything.
	pkgs, err := packages.Load(&packages.Config{
		Mode:  packages.NeedName | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps,
		Dir:   dir,
		Tests: true,
		Env:   env,
	}, patterns...)
	if err != nil {
		return nil, err
	}
	usesBus := set.Set[string]{}    // IDs of packages that import eventbus or eventbustest
	keepBodies := set.Set[string]{} // filenames of the files in usesBus packages
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		if pkg.Imports[eventbusPath] == nil && pkg.Imports[eventbustestPath] == nil {
			return
		}
		if pkg.Name == "main" && strings.HasSuffix(pkg.PkgPath, ".test") {
			// A generated test main, whose files are in the build
			// cache and have no event types.
			return
		}
		usesBus.Add(pkg.ID)
		keepBodies.AddSlice(pkg.CompiledGoFiles)
	})

	// Type-check everything, but drop the function bodies from files that
	// can't use an event type. The other packages only need their
	// declarations, and their bodies are most of the memory use.
	pkgs, err = packages.Load(&packages.Config{
		Mode:  packages.LoadAllSyntax,
		Dir:   dir,
		Tests: true,
		Env:   env,
		ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
			if keepBodies.Contains(filename) {
				return parser.ParseFile(fset, filename, src, parser.AllErrors|parser.ParseComments|parser.SkipObjectResolution)
			}
			f, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
			if f != nil {
				for _, d := range f.Decls {
					if fd, ok := d.(*ast.FuncDecl); ok {
						fd.Body = nil
					}
				}
			}
			return f, err
		},
	}, patterns...)
	if err != nil {
		return nil, err
	}
	var errs []string
	var sites []Site
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		if !usesBus.Contains(pkg.ID) {
			// Errors are expected here, like imports only used by the
			// dropped bodies.
			return
		}
		for _, e := range pkg.Errors {
			errs = append(errs, e.Error())
		}
		if pkg.TypesInfo == nil {
			return
		}
		for _, f := range pkg.Syntax {
			sites = append(sites, fileSites(pkg.Fset, pkg.TypesInfo, f)...)
		}
	})
	if len(errs) > 0 {
		return nil, fmt.Errorf("package errors:\n%s", strings.Join(errs, "\n"))
	}
	return sites, nil
}

// fileSites returns the uses of event types in f.
func fileSites(fset *token.FileSet, info *types.Info, f *ast.File) []Site {
	var sites []Site
	add := func(pos token.Pos, fn *types.Func, t types.Type) {
		if containsTypeParam(t) {
			// A generic wrapper like eventbustest.Inject. Its callers'
			// instantiations are recorded at their own call sites.
			return
		}
		sites = append(sites, Site{
			Pos:  fset.Position(pos),
			Func: fn.Pkg().Name() + "." + fn.Name(),
			Type: types.TypeString(t, nil),
		})
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			fn := eventbusFunc(info, n)
			if fn == nil || !typeArgFuncs[fn.FullName()] {
				return true
			}
			if inst, ok := info.Instances[n]; ok && inst.TypeArgs.Len() > 0 {
				add(n.Pos(), fn, inst.TypeArgs.At(0))
			}
		case *ast.CallExpr:
			fn := eventbusFunc(info, calleeIdent(n.Fun))
			if fn == nil || !filterFuncs[fn.FullName()] {
				return true
			}
			for _, arg := range n.Args {
				if c, ok := arg.(*ast.CallExpr); ok && eventbusFunc(info, calleeIdent(c.Fun)) != nil {
					// Already recorded as a type argument of
					// eventbustest.Type or EqualTo.
					continue
				}
				sig, ok := info.TypeOf(arg).(*types.Signature)
				if !ok || sig.Params().Len() == 0 {
					continue
				}
				add(arg.Pos(), fn, sig.Params().At(0).Type())
			}
		}
		return true
	})
	return sites
}

// calleeIdent returns the identifier naming the function in a call's Fun
// expression, or nil if there isn't one.
func calleeIdent(fun ast.Expr) *ast.Ident {
	for {
		switch e := fun.(type) {
		case *ast.Ident:
			return e
		case *ast.SelectorExpr:
			return e.Sel
		case *ast.IndexExpr:
			fun = e.X
		case *ast.IndexListExpr:
			fun = e.X
		case *ast.ParenExpr:
			fun = e.X
		default:
			return nil
		}
	}
}

// eventbusFunc returns the package-level func in the eventbus or eventbustest
// package that id refers to, or nil if it doesn't refer to one.
func eventbusFunc(info *types.Info, id *ast.Ident) *types.Func {
	if id == nil {
		return nil
	}
	fn, ok := info.Uses[id].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return nil
	}
	if p := fn.Pkg().Path(); p != eventbusPath && p != eventbustestPath {
		return nil
	}
	if fn.Signature().Recv() != nil {
		return nil
	}
	return fn
}

func containsTypeParam(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	_, ok := t.(*types.TypeParam)
	return ok
}

// mismatches groups sites by the non-pointer form of their event type and
// returns the groups that use both forms.
func mismatches(sites []Site) []Mismatch {
	type key struct {
		pos token.Position
		typ string
	}
	seen := map[key]bool{}
	byBase := map[string][]Site{}
	for _, s := range sites {
		// The same file is loaded multiple times: for each GOOS, and as both
		// a package and its test variant.
		k := key{s.Pos, s.Type}
		if seen[k] {
			continue
		}
		seen[k] = true
		base := strings.TrimPrefix(s.Type, "*")
		byBase[base] = append(byBase[base], s)
	}
	var ret []Mismatch
	for base, ss := range byBase {
		hasValue := slices.ContainsFunc(ss, func(s Site) bool { return s.Type == base })
		hasPtr := slices.ContainsFunc(ss, func(s Site) bool { return s.Type != base })
		if !hasValue || !hasPtr {
			continue
		}
		slices.SortFunc(ss, func(a, b Site) int {
			return cmp.Or(
				cmp.Compare(a.Pos.Filename, b.Pos.Filename),
				cmp.Compare(a.Pos.Line, b.Pos.Line),
				cmp.Compare(a.Pos.Column, b.Pos.Column),
			)
		})
		ret = append(ret, Mismatch{Type: base, Sites: ss})
	}
	slices.SortFunc(ret, func(a, b Mismatch) int { return cmp.Compare(a.Type, b.Type) })
	return ret
}
