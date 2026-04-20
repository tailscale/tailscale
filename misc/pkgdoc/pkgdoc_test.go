package pkgdoc

import (
	"bytes"
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
	if len(got) == 0 {
		t.Fatalf("PackageDoc(%q) returned empty output", abs)
	}
	want := []byte("Package pkgdoc is a library-ified fork of Go's cmd/doc program")
	if !bytes.Contains(got, want) {
		t.Fatalf("PackageDoc(%q) = %q; want output containing %q", abs, got, want)
	}
}
