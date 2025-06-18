// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/tstime"
)

// nopWriteCloser is a no-op io.WriteCloser wrapping a bytes.Buffer.
type nopWriteCloser struct{ *bytes.Buffer }

func (nwc nopWriteCloser) Close() error { return nil }

// mockFileOps implements the taildrop.FileOps interface for testing SAF mode.
type mockFileOps struct {
	root string
}

func (m *mockFileOps) OpenWriter(name string, offset int64,
	perm os.FileMode) (io.WriteCloser, string, error) {

	path := name
	if !filepath.IsAbs(name) {
		path = filepath.Join(m.root, name)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, "", err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, perm)
	if err != nil {
		return nil, "", err
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return nil, "", err
		}
	}
	return f, path, nil
}

func (m *mockFileOps) Rename(oldPath, finalName string) (string, error) {
	if err := os.MkdirAll(m.root, 0o755); err != nil {
		return "", fmt.Errorf("mkdir root: %w", err)
	}

	name := finalName
	for i := 0; ; i++ {
		dst := filepath.Join(m.root, name)
		if _, err := os.Stat(dst); err == nil {
			name = nextFilename(finalName)
			continue
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("stat %q: %w", dst, err)
		}
		if err := os.Rename(oldPath, dst); err != nil {
			return "", fmt.Errorf("rename %q → %q: %w", oldPath, dst, err)
		}
		return dst, nil
	}
}

func (m *mockFileOps) Base(p string) string {
	return filepath.Base(strings.TrimPrefix(p, "uri://"))
}

func (m *mockFileOps) Remove(name string) error {
	return os.Remove(filepath.Join(m.root, name))
}
func (m *mockFileOps) ListDir(dir string) ([]os.DirEntry, error) {
	return os.ReadDir(dir)
}

func TestPutFile(t *testing.T) {
	const content = "hello, world"

	dir := t.TempDir()
	mops := &mockFileOps{root: dir}
	mgr := managerOptions{
		Logf:           t.Logf,
		Clock:          tstime.DefaultClock{},
		State:          nil,
		Dir:            dir,
		FileOps:        mops,
		DirectFileMode: true,
		SendFileNotify: func() {},
	}.New()

	id := clientID("0")
	n, err := mgr.PutFile(id, "file.txt", strings.NewReader(content), 0, int64(len(content)))
	if err != nil {
		t.Fatalf("PutFile error: %v", err)
	}
	if n != int64(len(content)) {
		t.Errorf("wrote %d bytes; want %d", n, len(content))
	}

	path := filepath.Join(dir, "file.txt")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %q: %v", path, err)
	}
	if string(got) != content {
		t.Errorf("file contents = %q; want %q", string(got), content)
	}
}
