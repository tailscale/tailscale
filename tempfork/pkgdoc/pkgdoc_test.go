package pkgdoc

import (
	"path/filepath"
	"testing"
)

func TestPkgdoc(t *testing.T) {
	abs, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	got, err := PackageDoc(abs)
	if err != nil {
		t.Fatal(err)
	}
	const want = "package pkgdoc // import \".\"\n\nPackage pkgdoc is a library-ified fork of Go's cmd/doc program that only does\nwhat we need for misc/genreadme.\n"
	if string(got) != want {
		t.Fatalf("PackageDoc(%q) = %q; want %q", abs, got, want)
	}
}