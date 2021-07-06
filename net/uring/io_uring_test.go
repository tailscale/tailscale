// +build linux

package uring

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestFile(t *testing.T) {
	tmpFile, err := ioutil.TempFile(".", "uring-test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	f, err := NewFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to create io_uring file: %v", err)
	}
	content := []byte("a test string to check writing works 😀 with non-unicode input")
	n, err := f.Write(content)
	if n != len(content) {
		t.Errorf("mismatch between written len and content len: want %d, got %d", len(content), n)
	}
	if err != nil {
		t.Errorf("file write failed: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Errorf("file close failed: %v", err)
	}
}
