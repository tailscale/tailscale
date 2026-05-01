// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The genreadme tool generates/updates README.md files in the tailscale repo.
//
// # Running
//
// From the repo root, run: `./tool/go run ./misc/genreadme` and it will update all
// the README.md files that are stale in the tree.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/creachadair/taskgroup"
	"tailscale.com/tempfork/pkgdoc"
)

// modulePath is the current module's import path, read from go.mod at startup.
var modulePath string

var skip = map[string]bool{
	"out": true,
}

// bkSkip lists directories where the generated file should not mention
// Buildkite because a deploy workflow is not set up for them.
var bkSkip = map[string]bool{}

// defaultRoots are the directory trees walked when genreadme is run with
// no arguments. Add a directory here to opt its package (and any
// sub-packages) into README.md generation from godoc.
var defaultRoots = []string{
	"tsnet",
}

func main() {
	flag.Parse()
	modulePath = readModulePath("go.mod")
	var roots []string
	switch flag.NArg() {
	case 0:
		roots = defaultRoots
	case 1:
		root := flag.Arg(0)
		root = strings.TrimPrefix(root, "./")
		root = strings.TrimSuffix(root, "/")
		roots = []string{root}
	default:
		log.Fatalf("Usage: genreadme [dir]")
	}

	var updateErrs []error
	g, run := taskgroup.New(func(err error) {
		updateErrs = append(updateErrs, err)
	}).Limit(runtime.NumCPU() * 2) // usually I/O bound

	for _, root := range roots {
		g.Go(func() error {
			return fs.WalkDir(os.DirFS("."), root, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !d.IsDir() {
					return nil
				}
				if skip[path] {
					return fs.SkipDir
				}
				base := filepath.Base(path)
				if base == "testdata" || (path != "." && base[0] == '.') {
					return fs.SkipDir
				}
				run(func() error {
					return update(path)
				})
				return nil
			})
		})
	}
	g.Wait()
	if err := errors.Join(updateErrs...); err != nil {
		log.Fatal(err)
	}
}

func update(dir string) error {
	readmePath := filepath.Join(dir, "README.md")
	cur, err := os.ReadFile(readmePath)
	exists := false
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		exists = true
		if !isGenerated(cur) {
			// Do nothing; a human wrote this file.
			return nil
		}
	}

	newContents, err := getNewContent(dir)
	if err != nil {
		return err
	}
	if newContents == nil {
		if exists {
			log.Printf("Deleting %s ...", readmePath)
			os.Remove(readmePath)
		}
		return nil
	}

	if bytes.Equal(cur, newContents) {
		return nil
	}
	log.Printf("Writing %s ...", readmePath)
	return os.WriteFile(readmePath, newContents, 0644)
}

func getNewContent(dir string) (newContent []byte, err error) {
	dents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	generators := []struct {
		name      string
		quickTest func(dir string, dents []fs.DirEntry) bool
		generate  func(dir string) ([]byte, error)
	}{
		{"go", hasGoFiles, genGoDoc},
	}
	for _, gen := range generators {
		if !gen.quickTest(dir, dents) {
			continue
		}
		newContent, err := gen.generate(dir)
		if newContent == nil && err == nil {
			// Generator declined to generate, try next
			continue
		}
		return newContent, err
	}
	return nil, nil
}

func genGoDoc(dir string) ([]byte, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for %q: %w", dir, err)
	}
	var importPath string
	if modulePath != "" {
		importPath = path.Join(modulePath, filepath.ToSlash(dir))
	}
	godoc, err := pkgdoc.PackageDoc(abs, importPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get package doc for %q: %w", dir, err)
	}
	if len(bytes.TrimSpace(godoc)) == 0 {
		// No godoc; skipping.
		return nil, nil
	}
	isLibrary := bytes.HasPrefix(godoc, []byte("package "))
	if isLibrary {
		// Strip the "package X // import Y\n\n" clause emitted for library packages.
		if i := bytes.Index(godoc, []byte("\n\n")); i != -1 {
			godoc = godoc[i+2:]
		}
	}
	if len(bytes.TrimSpace(godoc)) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	io.WriteString(&buf, genHeader)
	fmt.Fprintf(&buf, "\n# %s\n\n", filepath.Base(dir))
	if isLibrary && importPath != "" {
		fmt.Fprintf(&buf, "[![Go Reference](https://pkg.go.dev/badge/%s.svg)](https://pkg.go.dev/%s)\n\n", importPath, importPath)
	}
	buf.Write(godoc)

	if !bytes.Contains(godoc, []byte("## Deploying")) {
		deployPath := filepath.Join(dir, "deploy.sh")
		if _, err := os.Stat(deployPath); err == nil {
			fmt.Fprint(&buf, "\n## Deploying\n\n")
			if hasBuildkite(dir) {
				fmt.Fprintf(&buf,
					"To deploy, run the https://buildkite.com/tailscale/deploy-%s workflow in Buildkite.\n",
					filepath.Base(dir),
				)
			}
			fmt.Fprintf(&buf, "To deploy manually, run `./%s` from the repo root.\n\n", deployPath)
		}
	}
	return buf.Bytes(), nil
}

const genHeader = "<!-- README.md auto-generated by misc/genreadme; DO NOT EDIT. (or remove this line) -->\n"

func isGenerated(b []byte) bool { return bytes.HasPrefix(b, []byte(genHeader)) }

// readModulePath returns the module path declared in the given go.mod file,
// or "" if it can't be read or parsed.
func readModulePath(file string) string {
	b, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(b)) {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return ""
}

func hasBuildkite(dir string) bool {
	if bkSkip[dir] {
		return false
	}
	_, flyErr := os.Stat(filepath.Join(dir, "fly.toml"))
	return flyErr != nil
}

func hasGoFiles(dir string, dents []fs.DirEntry) bool {
	var fset *token.FileSet

	for _, de := range dents {
		name := de.Name()
		if !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			continue
		}
		if fset == nil {
			fset = token.NewFileSet()
		}

		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		pkgFile, err := parser.ParseFile(fset, "", f, parser.PackageClauseOnly)
		f.Close()
		if err != nil {
			// skip files with parse errors
			continue
		}

		return pkgFile.Name.Name != ""
	}
	return false
}
