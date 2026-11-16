// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/util/must"
)

type notifyingReader struct {
	r       io.Reader
	started chan struct{}
}

func (r notifyingReader) Read(p []byte) (int, error) {
	select {
	case r.started <- struct{}{}:
	default:
	}
	return r.r.Read(p)
}

func TestPutFile(t *testing.T) {
	const content = "hello, world"

	tests := []struct {
		name           string
		directFileMode bool
	}{
		{"DirectFileMode", true},
		{"NonDirectFileMode", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			mgr := managerOptions{
				Logf:           t.Logf,
				Clock:          tstime.DefaultClock{},
				State:          nil,
				fileOps:        must.Get(newFileOps(dir)),
				DirectFileMode: tt.directFileMode,
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

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.Contains(entry.Name(), ".partial") {
					t.Errorf("unexpected partial file left behind: %s", entry.Name())
				}
			}
		})
	}
}

func TestIncomingFilesPeerID(t *testing.T) {
	dir := t.TempDir()
	mgr := managerOptions{
		Logf:           t.Logf,
		Clock:          tstime.DefaultClock{},
		fileOps:        must.Get(newFileOps(dir)),
		SendFileNotify: func() {},
	}.New()

	id := clientID("n12345CNTRL")
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	started := make(chan struct{}, 1)
	done := make(chan error, 1)

	go func() {
		_, err := mgr.PutFile(
			id,
			"photo.jpg",
			notifyingReader{r: pr, started: started},
			0,
			5,
		)
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("PutFile() did not start reading")
	}

	files := mgr.IncomingFiles()
	if len(files) != 1 {
		t.Fatalf("IncomingFiles() returned %d files; want 1", len(files))
	}

	want := tailcfg.StableNodeID(id)
	if files[0].PeerID != want {
		t.Errorf("PeerID = %q; want %q", files[0].PeerID, want)
	}

	if _, err := pw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := <-done; err != nil {
		t.Fatalf("PutFile() error: %v", err)
	}
}
