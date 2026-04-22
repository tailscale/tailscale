// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// listpkgs prints the import paths that match the Go package patterns
// given on the command line and conditionally filters them in various ways.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/build/constraint"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"
)

var (
	ignore3p          = flag.Bool("ignore-3p", false, "ignore third-party packages forked/vendored into Tailscale")
	goos              = flag.String("goos", "", "GOOS to use for loading packages (default: current OS)")
	goarch            = flag.String("goarch", "", "GOARCH to use for loading packages (default: current architecture)")
	withTagsAllStr    = flag.String("with-tags-all", "", "if non-empty, a comma-separated list of builds tags to require (a package will only be listed if it contains all of these build tags)")
	withoutTagsAnyStr = flag.String("without-tags-any", "", "if non-empty, a comma-separated list of build constraints to exclude (a package will be omitted if it contains any of these build tags)")
	shard             = flag.String("shard", "", "if non-empty, a string of the form 'N/M' to only print packages in shard N of M (e.g. '1/3', '2/3', '3/3/' for different thirds of the list)")
	affectedByTag     = flag.String("affected-by-tag", "", "if non-empty, only list packages whose test binary would be affected by the presence or absence of this build tag")
	hasRootTests      = flag.Bool("has-root-tests", false, "list packages (as ./relative/path) containing _test.go files that call tstest.RequireRoot")
	hasGoGenerate     = flag.Bool("has-go-generate", false, "only list packages that contain at least one //go:generate directive")
)

func main() {
	flag.Parse()

	if *hasRootTests {
		printRootTestPkgs()
		return
	}

	patterns := flag.Args()
	if len(patterns) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	cfg := &packages.Config{
		Mode: packages.LoadFiles,
		Env:  os.Environ(),
	}
	if *affectedByTag != "" {
		cfg.Mode |= packages.NeedImports
		cfg.Tests = true
	}
	if *goos != "" {
		cfg.Env = append(cfg.Env, "GOOS="+*goos)
	}
	if *goarch != "" {
		cfg.Env = append(cfg.Env, "GOARCH="+*goarch)
	}

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		log.Fatalf("loading packages: %v", err)
	}

	var withoutAny []string
	if *withoutTagsAnyStr != "" {
		withoutAny = strings.Split(*withoutTagsAnyStr, ",")
	}
	var withAll []string
	if *withTagsAllStr != "" {
		withAll = strings.Split(*withTagsAllStr, ",")
	}

	var affected map[string]bool // PkgPath → true
	if *affectedByTag != "" {
		affected = computeAffected(pkgs, *affectedByTag)
	}

	seen := map[string]bool{}
	matches := 0
Pkg:
	for _, pkg := range pkgs {
		if pkg.PkgPath == "" { // malformed (shouldn’t happen)
			continue
		}
		if affected != nil {
			// Skip synthetic packages created by Tests: true:
			// - for-test variants like "foo [foo.test]" (ID != PkgPath)
			// - test binary packages like "foo.test" (PkgPath ends in ".test")
			if pkg.ID != pkg.PkgPath || strings.HasSuffix(pkg.PkgPath, ".test") {
				continue
			}
			if !affected[pkg.PkgPath] {
				continue
			}
		}
		if seen[pkg.PkgPath] {
			continue // suppress duplicates when patterns overlap
		}
		seen[pkg.PkgPath] = true

		pkgPath := pkg.PkgPath

		if *ignore3p && isThirdParty(pkgPath) {
			continue
		}
		if withAll != nil {
			for _, t := range withAll {
				if !hasBuildTag(pkg, t) {
					continue Pkg
				}
			}
		}
		for _, t := range withoutAny {
			if hasBuildTag(pkg, t) {
				continue Pkg
			}
		}
		if *hasGoGenerate && !pkgHasGoGenerate(pkg) {
			continue Pkg
		}
		matches++

		if *shard != "" {
			var n, m int
			if _, err := fmt.Sscanf(*shard, "%d/%d", &n, &m); err != nil || n < 1 || m < 1 {
				log.Fatalf("invalid shard format %q; expected ‘N/M’", *shard)
			}
			if m > 0 && (matches-1)%m != n-1 {
				continue // not in this shard
			}
		}
		fmt.Println(pkgPath)
	}

	// If any package had errors (e.g. missing deps) report them via packages.PrintErrors.
	// This mirrors `go list` behaviour when -e is *not* supplied.
	if packages.PrintErrors(pkgs) > 0 {
		os.Exit(1)
	}
}

// computeAffected returns the set of package paths whose test binaries would
// differ with vs without the given build tag. It finds packages that directly
// mention the tag, then propagates transitively via reverse dependencies.
func computeAffected(pkgs []*packages.Package, tag string) map[string]bool {
	// Build a map from package ID to package for quick lookup.
	byID := make(map[string]*packages.Package, len(pkgs))
	for _, pkg := range pkgs {
		byID[pkg.ID] = pkg
	}

	// First pass: find directly affected package IDs.
	directlyAffected := make(map[string]bool)
	for _, pkg := range pkgs {
		if hasBuildTag(pkg, tag) {
			directlyAffected[pkg.ID] = true
		}
	}

	// Build reverse dependency graph: importedID → []importingID.
	reverseDeps := make(map[string][]string)
	for _, pkg := range pkgs {
		for _, imp := range pkg.Imports {
			reverseDeps[imp.ID] = append(reverseDeps[imp.ID], pkg.ID)
		}
	}

	// BFS from directly affected packages through reverse deps.
	affectedIDs := make(map[string]bool)
	queue := make([]string, 0, len(directlyAffected))
	for id := range directlyAffected {
		affectedIDs[id] = true
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, rdep := range reverseDeps[id] {
			if !affectedIDs[rdep] {
				affectedIDs[rdep] = true
				queue = append(queue, rdep)
			}
		}
	}

	// Map affected IDs back to PkgPaths. For-test variants like
	// "foo [foo.test]" share the same PkgPath as "foo", so the
	// result naturally deduplicates.
	affected := make(map[string]bool)
	for id := range affectedIDs {
		if pkg, ok := byID[id]; ok {
			affected[pkg.PkgPath] = true
		}
	}
	return affected
}

func isThirdParty(pkg string) bool {
	return strings.HasPrefix(pkg, "tailscale.com/tempfork/")
}

// hasBuildTag reports whether any source file in pkg mentions `tag`
// in a //go:build constraint.
func hasBuildTag(pkg *packages.Package, tag string) bool {
	all := slices.Concat(pkg.CompiledGoFiles, pkg.OtherFiles, pkg.IgnoredFiles)
	suffix := "_" + tag + ".go"
	for _, name := range all {
		if strings.HasSuffix(name, suffix) {
			return true
		}
		ok, err := fileMentionsTag(name, tag)
		if err != nil {
			log.Printf("reading %s: %v", name, err)
			continue
		}
		if ok {
			return true
		}
	}
	return false
}

// tagSet is a set of build tags.
// The values are always true. We avoid non-std set types
// to make this faster to "go run" on empty caches.
type tagSet map[string]bool

var (
	mu       sync.Mutex
	fileTags = map[string]tagSet{} // abs path -> set of build tags mentioned in file
)

func getFileTags(filename string) (tagSet, error) {
	mu.Lock()
	tags, ok := fileTags[filename]
	mu.Unlock()
	if ok {
		return tags, nil
	}

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ts := make(tagSet)
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.TrimSpace(line) == "" {
			continue // still in leading blank lines
		}
		if !strings.HasPrefix(line, "//") {
			// hit real code – done with header comments
			// TODO(bradfitz): care about /* */ comments?
			break
		}
		if !strings.HasPrefix(line, "//go:build") {
			continue // some other comment
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			return nil, fmt.Errorf("parsing %q: %w", line, err)
		}
		// Call Eval to populate ts with the tags mentioned in the expression.
		// We don't care about the result, just the side effect of populating ts.
		expr.Eval(func(tag string) bool {
			ts[tag] = true
			return true // arbitrary
		})
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", filename, err)
	}

	mu.Lock()
	defer mu.Unlock()
	fileTags[filename] = ts
	return ts, nil
}

func fileMentionsTag(filename, tag string) (bool, error) {
	tags, err := getFileTags(filename)
	if err != nil {
		return false, err
	}
	return tags[tag], nil
}

// pkgHasGoGenerate reports whether any source file in pkg contains a
// //go:generate directive.
func pkgHasGoGenerate(pkg *packages.Package) bool {
	// Include IgnoredFiles so directives behind build constraints are still
	// found; the caller can narrow by tag via -with-tags-all/-without-tags-any
	// if they care.
	all := slices.Concat(pkg.CompiledGoFiles, pkg.OtherFiles, pkg.IgnoredFiles)
	for _, name := range all {
		ok, err := fileHasGoGenerate(name)
		if err != nil {
			log.Printf("reading %s: %v", name, err)
			continue
		}
		if ok {
			return true
		}
	}
	return false
}

var (
	goGenerateMu sync.Mutex
	goGenerate   = map[string]bool{} // abs path -> whether file has //go:generate
)

func fileHasGoGenerate(filename string) (bool, error) {
	goGenerateMu.Lock()
	v, ok := goGenerate[filename]
	goGenerateMu.Unlock()
	if ok {
		return v, nil
	}

	f, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer f.Close()

	has := false
	s := bufio.NewScanner(f)
	for s.Scan() {
		// go:generate directives must start at column 1 (no leading
		// whitespace) to be recognized by the go tool.
		if strings.HasPrefix(s.Text(), "//go:generate") {
			has = true
			break
		}
	}
	if err := s.Err(); err != nil {
		return false, fmt.Errorf("reading %s: %w", filename, err)
	}

	goGenerateMu.Lock()
	goGenerate[filename] = has
	goGenerateMu.Unlock()
	return has, nil
}

// printRootTestPkgs walks the current directory tree looking for _test.go
// files that contain "tstest.RequireRoot" and prints the unique package
// directories as ./relative/path.
func printRootTestPkgs() {
	root, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	seen := map[string]bool{}
	var dirs []string
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			// Skip hidden dirs and common non-Go dirs.
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		dir := filepath.Dir(rel)
		if seen[dir] {
			return nil // already found a match in this dir
		}
		if fileContains(path, "tstest.RequireRoot") {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
		return nil
	})
	sort.Strings(dirs)
	for _, d := range dirs {
		fmt.Println("./" + filepath.ToSlash(d))
	}
}

// fileContains reports whether the file at path contains the given substring.
func fileContains(path, substr string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if strings.Contains(s.Text(), substr) {
			return true
		}
	}
	return false
}
