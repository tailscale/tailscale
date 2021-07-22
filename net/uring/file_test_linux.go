package uring

import (
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
