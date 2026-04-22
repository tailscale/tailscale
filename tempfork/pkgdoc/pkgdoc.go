// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkgdoc is a library-ified fork of Go's cmd/doc program
// that only does what we need for misc/genreadme.
package pkgdoc

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/doc"
	"go/doc/comment"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log"
	"slices"
)

const (
	punchedCardWidth = 80
	indent           = "    "
)

type Package struct {
	writer   io.Writer    // Destination for output.
	name     string       // Package name, json for encoding/json.
	userPath string       // String the user used to find this package.
	pkg      *ast.Package // Parsed package.
	file     *ast.File    // Merged from all files in the package
	doc      *doc.Package
	build    *build.Package
	fs       *token.FileSet // Needed for printing.
	buf      pkgBuffer
}

func (pkg *Package) ToText(w io.Writer, text, prefix, codePrefix string) {
	d := pkg.doc.Parser().Parse(text)
	pr := pkg.doc.Printer()
	pr.TextPrefix = prefix
	pr.TextCodePrefix = codePrefix
	w.Write(pr.Text(d))
}

// ToMarkdown parses the godoc comment text and writes a Markdown rendering to w
// suitable for a repository README.md: top-level sections become ## headings
// without per-heading anchor IDs, and [Symbol] doc links resolve to pkg.go.dev,
// including for symbols in the current package (which the default printer would
// otherwise emit as bare #Name fragments with no backing anchor).
func (pkg *Package) ToMarkdown(w io.Writer, text string) {
	d := pkg.doc.Parser().Parse(text)
	pr := pkg.doc.Printer()
	pr.HeadingLevel = 2
	pr.HeadingID = func(*comment.Heading) string { return "" }
	pr.DocLinkBaseURL = "https://pkg.go.dev"
	pr.DocLinkURL = func(link *comment.DocLink) string {
		importPath := link.ImportPath
		if importPath == "" {
			importPath = pkg.doc.ImportPath
		}
		name := link.Name
		if link.Recv != "" {
			name = link.Recv + "." + name
		}
		return "https://pkg.go.dev/" + importPath + "#" + name
	}
	w.Write(pr.Markdown(d))
}

// pkgBuffer is a wrapper for bytes.Buffer that prints a package clause the
// first time Write is called.
type pkgBuffer struct {
	pkg     *Package
	printed bool // Prevent repeated package clauses.
	bytes.Buffer
}

func (pb *pkgBuffer) Write(p []byte) (int, error) {
	pb.packageClause()
	return pb.Buffer.Write(p)
}

func (pb *pkgBuffer) packageClause() {
	if !pb.printed {
		pb.printed = true
		// Only show package clause for commands if requested explicitly.
		if pb.pkg.pkg.Name != "main" {
			pb.pkg.packageClause()
		}
	}
}

type PackageError string // type returned by pkg.Fatalf.

func (p PackageError) Error() string {
	return string(p)
}

// parsePackage turns the build package we found into a parsed package
// we can then use to generate documentation.
func parsePackage(writer io.Writer, pkg *build.Package, userPath string) *Package {
	// include tells parser.ParseDir which files to include.
	// That means the file must be in the build package's GoFiles or CgoFiles
	// list only (no tag-ignored files, tests, swig or other non-Go files).
	include := func(info fs.FileInfo) bool {
		return slices.Contains(pkg.GoFiles, info.Name()) || slices.Contains(pkg.CgoFiles, info.Name())
	}
	fset := token.NewFileSet()
	// Parse declarations (not just imports) so that doc.Package knows the
	// package's symbols; the Markdown printer needs this to resolve
	// [Symbol] doc links in package comments.
	pkgs, err := parser.ParseDir(fset, pkg.Dir, include, parser.ParseComments)
	if err != nil {
		log.Fatal(err)
	}
	// Make sure they are all in one package.
	if len(pkgs) == 0 {
		log.Fatalf("no source-code package in directory %s", pkg.Dir)
	}
	if len(pkgs) > 1 {
		log.Fatalf("multiple packages in directory %s", pkg.Dir)
	}
	astPkg := pkgs[pkg.Name]

	// TODO: go/doc does not include typed constants in the constants
	// list, which is what we want. For instance, time.Sunday is of type
	// time.Weekday, so it is defined in the type but not in the
	// Consts list for the package. This prevents
	//	go doc time.Sunday
	// from finding the symbol. Work around this for now, but we
	// should fix it in go/doc.
	// A similar story applies to factory functions.
	mode := doc.AllDecls
	docPkg := doc.New(astPkg, pkg.ImportPath, mode)

	p := &Package{
		writer:   writer,
		name:     pkg.Name,
		userPath: userPath,
		pkg:      astPkg,
		file:     ast.MergePackageFiles(astPkg, 0),
		doc:      docPkg,
		build:    pkg,
		fs:       fset,
	}
	p.buf.pkg = p
	return p
}

func (pkg *Package) Printf(format string, args ...any) {
	fmt.Fprintf(&pkg.buf, format, args...)
}

func (pkg *Package) flush() {
	_, err := pkg.writer.Write(pkg.buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	pkg.buf.Reset() // Not needed, but it's a flush.
}

var newlineBytes = []byte("\n\n") // We never ask for more than 2.

// newlines guarantees there are n newlines at the end of the buffer.
func (pkg *Package) newlines(n int) {
	for !bytes.HasSuffix(pkg.buf.Bytes(), newlineBytes[:n]) {
		pkg.buf.WriteRune('\n')
	}
}

// packageDoc prints the docs for the package as Markdown.
func (pkg *Package) packageDoc() {
	pkg.Printf("") // Trigger the package clause; we know the package exists.
	pkg.ToMarkdown(&pkg.buf, pkg.doc.Doc)
	pkg.newlines(1)

	pkg.bugs()
}

// packageClause prints the package clause.
func (pkg *Package) packageClause() {
	importPath := pkg.build.ImportComment
	if importPath == "" {
		importPath = pkg.build.ImportPath
	}

	pkg.Printf("package %s // import %q\n\n", pkg.name, importPath)
}

// bugs prints the BUGS information for the package.
// TODO: Provide access to TODOs and NOTEs as well (very noisy so off by default)?
func (pkg *Package) bugs() {
	if pkg.doc.Notes["BUG"] == nil {
		return
	}
	pkg.Printf("\n")
	for _, note := range pkg.doc.Notes["BUG"] {
		pkg.Printf("%s: %v\n", "BUG", note.Body)
	}
}

// PackageDoc generates Markdown documentation for the package in the given
// directory. importPath is the full Go import path of that package (e.g.
// "tailscale.com/tsnet"); it's used to render [Symbol] doc links to the
// right pkg.go.dev URL. If importPath is empty, build.ImportDir's guess
// is used (typically "." for module-based repos).
func PackageDoc(dir, importPath string) ([]byte, error) {
	var buf bytes.Buffer
	var writer io.Writer = &buf

	buildPackage, err := build.ImportDir(dir, build.ImportComment)
	if err != nil {
		var noGoError *build.NoGoError
		if errors.As(err, &noGoError) {
			return nil, nil
		}
		return nil, err
	}
	if importPath != "" {
		buildPackage.ImportPath = importPath
	}
	userPath := dir

	pkg := parsePackage(writer, buildPackage, userPath)
	pkg.packageDoc()
	pkg.flush()

	return buf.Bytes(), nil
}
