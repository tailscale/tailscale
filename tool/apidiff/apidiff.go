// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// apidiff checks packages marked with packageAPIIsStable for incompatible API
// changes relative to another checkout of this module.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/exp/apidiff"
	"golang.org/x/tools/go/packages"
)

const stableAPIMarker = "packageAPIIsStable"

var baseDir = flag.String("base", "", "path to the base checkout to compare against")

func main() {
	flag.Parse()
	if *baseDir == "" {
		flag.Usage()
		os.Exit(2)
	}

	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	incompatible, err := checkCompatible(*baseDir, currentDir)
	if err != nil {
		log.Fatal(err)
	}
	if len(incompatible) == 0 {
		return
	}

	fmt.Fprintln(os.Stderr, "incompatible stable API changes:")
	for _, change := range incompatible {
		fmt.Fprintf(os.Stderr, "  - %s\n", change)
	}
	os.Exit(1)
}

type packageTree struct {
	all    map[string]bool
	stable map[string]bool
}

func checkCompatible(oldDir, newDir string) ([]string, error) {
	oldTree, err := discoverPackages(oldDir)
	if err != nil {
		return nil, fmt.Errorf("discover base packages: %w", err)
	}
	newTree, err := discoverPackages(newDir)
	if err != nil {
		return nil, fmt.Errorf("discover current packages: %w", err)
	}

	var incompatible []string
	for pkgPath := range oldTree.stable {
		switch {
		case !newTree.all[pkgPath]:
			incompatible = append(incompatible, fmt.Sprintf("removed package %s", pkgPath))
		case !newTree.stable[pkgPath]:
			incompatible = append(incompatible,
				fmt.Sprintf("%s no longer declares %s", pkgPath, stableAPIMarker))
		}
	}

	for pkgPath := range newTree.stable {
		if !oldTree.all[pkgPath] {
			continue // A new package cannot break the previous API.
		}
		oldPkg, err := loadPackage(oldDir, pkgPath)
		if err != nil {
			return nil, fmt.Errorf("load base package %s: %w", pkgPath, err)
		}
		newPkg, err := loadPackage(newDir, pkgPath)
		if err != nil {
			return nil, fmt.Errorf("load current package %s: %w", pkgPath, err)
		}
		for _, change := range apidiff.Changes(oldPkg.Types, newPkg.Types).Changes {
			if !change.Compatible {
				incompatible = append(incompatible, pkgPath+": "+change.Message)
			}
		}
	}

	slices.Sort(incompatible)
	return incompatible, nil
}

func discoverPackages(dir string) (packageTree, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return packageTree{}, err
	}
	pkgs, err := packages.Load(&packages.Config{
		Dir:  dir,
		Mode: packages.NeedName | packages.NeedCompiledGoFiles,
	}, "./...")
	if err != nil {
		return packageTree{}, err
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		return packageTree{}, fmt.Errorf("%d package loading errors", n)
	}

	tree := packageTree{
		all:    make(map[string]bool),
		stable: make(map[string]bool),
	}
	for _, pkg := range pkgs {
		tree.all[pkg.PkgPath] = true
		marked, err := hasStableAPIMarker(pkg.CompiledGoFiles)
		if err != nil {
			return packageTree{}, fmt.Errorf("%s: %w", pkg.PkgPath, err)
		}
		if marked {
			tree.stable[pkg.PkgPath] = true
		}
	}
	return tree, nil
}

func hasStableAPIMarker(files []string) (bool, error) {
	for _, filename := range files {
		f, err := parser.ParseFile(token.NewFileSet(), filename, nil, parser.SkipObjectResolution)
		if err != nil {
			return false, err
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				values := spec.(*ast.ValueSpec)
				for _, name := range values.Names {
					if name.Name == stableAPIMarker {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}

func loadPackage(dir, pkgPath string) (*packages.Package, error) {
	pkgs, err := packages.Load(&packages.Config{
		Dir: dir,
		Mode: packages.NeedName |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedTypes |
			packages.NeedTypesSizes,
	}, pkgPath)
	if err != nil {
		return nil, err
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		return nil, fmt.Errorf("%d package loading errors", n)
	}
	if len(pkgs) != 1 {
		return nil, fmt.Errorf("loaded %d packages, want 1", len(pkgs))
	}
	if strings.TrimSpace(pkgs[0].PkgPath) == "" || pkgs[0].Types == nil {
		return nil, fmt.Errorf("package has incomplete type information")
	}
	return pkgs[0], nil
}
