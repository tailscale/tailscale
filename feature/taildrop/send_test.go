// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/tstime"
)

// nopWriteCloser is a no-op io.WriteCloser wrapping a bytes.Buffer.
type nopWriteCloser struct{ *bytes.Buffer }

func (nwc nopWriteCloser) Close() error { return nil }

func TestPutFile(t *testing.T) {
	const content = "hello, world"

	dir := t.TempDir()
	mops, _ := newDefaultFileOps(dir)
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
