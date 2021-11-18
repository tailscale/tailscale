package main

import (
	"flag"
	"fmt"
	"log"
	"sort"

	"golang.org/x/tools/go/packages"
)

var cfg = &packages.Config{
	Mode: (0 |
		packages.NeedName |
		packages.NeedFiles |
		packages.NeedCompiledGoFiles |
		packages.NeedImports |
		packages.NeedDeps |
		packages.NeedModule |
		packages.NeedTypes |
		packages.NeedSyntax |
		0),
}

func main() {
	flag.Parse()

	var w walker
	w.walk("tailscale.com/cmd/tailscaled")
}

type walker struct {
	done map[string]bool
}

func (w *walker) walk(mainPkg string) {
	pkgs, err := packages.Load(cfg, mainPkg)
	if err != nil {
		log.Fatalf("packages.Load: %v", err)
	}
	for _, pkg := range pkgs {
		w.walkPackage(pkg)
	}
}

func (w *walker) walkPackage(pkg *packages.Package) {
	if w.done[pkg.PkgPath] {
		return
	}
	if w.done == nil {
		w.done = map[string]bool{}
	}
	w.done[pkg.PkgPath] = true

	fmt.Printf("\n### PACKAGE %v\n", pkg.PkgPath)

	if len(pkg.Errors) > 0 {
		log.Fatalf("errors reading %q: %q", pkg.PkgPath, pkg.Errors)
	}

	var imports []*packages.Package
	for _, p := range pkg.Imports {
		imports = append(imports, p)
	}
	sort.Slice(imports, func(i, j int) bool {
		return imports[i].PkgPath < imports[j].PkgPath
	})
	for _, f := range pkg.GoFiles {
		fmt.Printf("file.go %q\n", f)
	}
	for _, f := range pkg.OtherFiles {
		fmt.Printf("file.other %q\n", f)
	}
	for _, p := range imports {
		fmt.Printf("import %q => %q\n", pkg.PkgPath, p.PkgPath)
	}
	fmt.Printf("Fset: %p\n", pkg.Fset)
	fmt.Printf("Syntax: %v\n", len(pkg.Syntax))
	fmt.Printf("Modules: %+v\n", pkg.Module)

	for _, p := range imports {
		w.walkPackage(p)
	}
}
