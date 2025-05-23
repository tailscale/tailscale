// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"log"
	"maps"
	"os"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/tools/go/packages"
	_ "tailscale.com/version"
)

func TestCgo(t *testing.T) {
	t.Logf("Go %s", runtime.Version())
	const pkg = "tailscale.com/tool/gocross/testcgoprog"
	ipaths, err := pkgPaths(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ipaths) != 1 || ipaths[0] != pkg {
		t.Fatalf("ipaths: %q; want just %q", ipaths, pkg)
	}

	// Pick a goos to force cross-compilation.
	goos := "linux"
	if runtime.GOOS == "linux" {
		goos = "darwin"
	}

	env := append(os.Environ(), "GOARCH=amd64", "GOOS="+goos, "CGO_ENABLED=1")
	cfg := &packages.Config{
		Mode: packages.NeedImports | packages.NeedDeps | packages.NeedFiles | packages.NeedName,
		Env:  env,
	}

	pkgs, err := packages.Load(cfg, pkg)
	if err != nil {
		log.Fatalf("for GOOS=%v: %v", goos, err)
	}

	type edge string // "from -> to"
	edges := map[edge]bool{}
	saw := map[string]bool{}

	packages.Visit(pkgs, nil, func(p *packages.Package) {
		t.Logf("pkg: %s", p.PkgPath)
		for imp := range p.Imports {
			e := edge(p.PkgPath + " => " + imp)
			edges[e] = true
		}
		if p.PkgPath == pkg {
			return
		}
		saw[p.PkgPath] = true
	})

	if len(saw) == 0 {
		t.Error("didn't see visit any other packages from a cross-compiled cgo root")
	}
	if len(edges) == 0 {
		t.Error("didn't find any edges from a cross-compiled cgo root")
	}

	for _, s := range slices.Sorted(maps.Keys(saw)) {
		t.Logf("saw: %s", s)
	}
	for _, s := range slices.Sorted(maps.Keys(edges)) {
		t.Logf("edge: %s", s)
	}
}

func pkgPaths(pkg ...string) (ipaths []string, err error) {
	pkgs, err := packages.Load(nil, pkg...)
	if err != nil {
		return nil, err
	}
	for _, p := range pkgs {
		ipaths = append(ipaths, p.PkgPath)
	}
	return ipaths, nil
}
