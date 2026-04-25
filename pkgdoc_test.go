// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailscaleroot

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func hasIgnoreBuildTag(f *ast.File) bool {
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if c.Text == "//go:build ignore" {
				return true
			}
		}
	}
	return false
}

func TestPackageDocs(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "linux":
		// Enough coverage for CI+devs.
	default:
		t.Skipf("skipping on %s", runtime.GOOS)
	}

	var goFiles []string
	err := filepath.Walk(".", func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Mode().IsDir() && path != "." && strings.HasPrefix(filepath.Base(path), ".") {
			return filepath.SkipDir // No documentation lives in dot directories (.git, .claude, etc)
		}
		if fi.Mode().IsRegular() && strings.HasSuffix(path, ".go") {
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			goFiles = append(goFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	byDir := map[string][]string{} // dir => files
	for _, fileName := range goFiles {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, fileName, nil, parser.PackageClauseOnly|parser.ParseComments)
		if err != nil {
			t.Fatalf("failed to ParseFile %q: %v", fileName, err)
		}
		if hasIgnoreBuildTag(f) {
			continue
		}
		dir := filepath.Dir(fileName)
		if _, ok := byDir[dir]; !ok {
			byDir[dir] = nil
		}
		if f.Doc != nil {
			byDir[dir] = append(byDir[dir], fileName)
			txt := f.Doc.Text()
			if strings.Contains(txt, "SPDX-License-Identifier") {
				t.Errorf("the copyright header for %s became its package doc due to missing blank line", fileName)
			}
		}
	}
	for dir, ff := range byDir {
		if len(ff) > 1 {
			t.Errorf("multiple files with package doc in %s: %q", dir, ff)
		}
		if len(ff) == 0 {
			if strings.HasPrefix(dir, "gokrazy/") {
				// Ignore gokrazy appliances. Their *.go file is only for deps.
				continue
			}
			t.Errorf("no package doc in %s", dir)
		}
	}
	t.Logf("parsed %d files", len(goFiles))
}
