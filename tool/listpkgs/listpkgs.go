// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// listpkgs prints the import paths that match the Go package patterns
// given on the command line and conditionally filters them in various ways.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/build/constraint"
	"log"
	"os"
	"slices"
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
)

func main() {
	flag.Parse()

	patterns := flag.Args()
	if len(patterns) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	cfg := &packages.Config{
		Mode: packages.LoadFiles,
		Env:  os.Environ(),
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

	seen := map[string]bool{}
	matches := 0
Pkg:
	for _, pkg := range pkgs {
		if pkg.PkgPath == "" { // malformed (shouldn’t happen)
			continue
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
		matches++

		if *shard != "" {
			var n, m int
			if _, err := fmt.Sscanf(*shard, "%d/%d", &n, &m); err != nil || n < 1 || m < 1 {
				log.Fatalf("invalid shard format %q; expected 'N/M'", *shard)
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
	return tags, nil
}

func fileMentionsTag(filename, tag string) (bool, error) {
	tags, err := getFileTags(filename)
	if err != nil {
		return false, err
	}
	return tags[tag], nil
}
