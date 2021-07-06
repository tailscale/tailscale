package uring

import (
	"io/ioutil"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestFileRead(t *testing.T) {
	if !Available() {
		t.Skip("io_uring not available")
	}
	c := qt.New(t)

	const path = "testdata/voltaire.txt"
	want, err := os.ReadFile(path)
	c.Assert(err, qt.IsNil)

	f, err := os.Open(path)
	c.Assert(err, qt.IsNil)
	t.Cleanup(func() { f.Close() })

	uf, err := newFile(f)
	if err != nil {
		t.Skipf("io_uring not available: %v", err)
	}
	t.Cleanup(func() { uf.Close() })
	buf := make([]byte, len(want)+128)
	n, err := uf.Read(buf)
	c.Assert(err, qt.IsNil)
	c.Assert(buf[:n], qt.DeepEquals, want)
}

func TestFileWrite(t *testing.T) {
	if !Available() {
		t.Skip("io_uring not available")
	}
	c := qt.New(t)
	tmpFile, err := ioutil.TempFile(".", "uring-test")
	c.Assert(err, qt.IsNil)
	t.Cleanup(func() {
		os.Remove(tmpFile.Name())
	})
	f, err := newFile(tmpFile)
	c.Assert(err, qt.IsNil)
	content := []byte("a test string to check writing works 😀 with non-unicode input")
	n, err := f.Write(content)
	if n != len(content) {
		t.Errorf("mismatch between written len and content len: want %d, got %d", len(content), n)
	}
	c.Assert(err, qt.IsNil)
	c.Assert(f.Close(), qt.IsNil)
}
