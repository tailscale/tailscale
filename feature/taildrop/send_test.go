// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"tailscale.com/tstime"
	"tailscale.com/util/must"
)

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
			n, err := mgr.PutFile(id, "file.txt", strings.NewReader(content), 0, int64(len(content)), "")
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

// hashTestFileOps observes reads and injects failures without changing the
// on-disk contents, so tests can distinguish streaming from post-write hashing.
type hashTestFileOps struct {
	FileOps
	openReader func(string) (io.ReadCloser, error)
	wrapWriter func(io.WriteCloser) io.WriteCloser
}

func (f hashTestFileOps) OpenReader(name string) (io.ReadCloser, error) {
	return f.openReader(name)
}

func (f hashTestFileOps) OpenWriter(name string, offset int64, perm os.FileMode) (io.WriteCloser, string, error) {
	w, path, err := f.FileOps.OpenWriter(name, offset, perm)
	if err == nil && f.wrapWriter != nil {
		w = f.wrapWriter(w)
	}
	return w, path, err
}

type hashTestWriter struct {
	io.WriteCloser
	writeErr, closeErr error
}

func (w hashTestWriter) Write(p []byte) (int, error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return w.WriteCloser.Write(p)
}

func (w hashTestWriter) Close() error {
	err := w.WriteCloser.Close()
	if w.closeErr != nil {
		return w.closeErr
	}
	return err
}

// TestPutFileStreamingHash verifies that consented uploads hash incoming bytes
// plus any resumed prefix before publishing; corrupt content and read, write,
// or close failures must not publish a file.
func TestPutFileStreamingHash(t *testing.T) {
	fault := errors.New("injected failure")
	for _, tt := range []struct {
		name, content, prefix       string
		offset                      int64
		shortPrefix                 bool
		interrupted                 bool
		readErr, writeErr, closeErr error
		wantErr                     error
	}{
		{name: "fresh", content: "hello"},
		{name: "empty"},
		{name: "resume", content: "hello", prefix: "hel", offset: 3},
		{name: "interrupted_resume", content: "hello", prefix: "hel", offset: 3, interrupted: true},
		{name: "resume_earlier", content: "hello", prefix: "hell", offset: 2},
		{name: "resume_complete", content: "hello", prefix: "hello", offset: 5},
		{name: "restart", content: "hello", prefix: "wrong"},
		{name: "corrupt_prefix", content: "hello", prefix: "bad", offset: 3, wantErr: ErrConsentHashMismatch},
		{name: "short_prefix", content: "hello", prefix: "hel", offset: 3, shortPrefix: true, wantErr: io.EOF},
		{name: "prefix_read_error", content: "hello", prefix: "hel", offset: 3, readErr: fault, wantErr: fault},
		{name: "write_error", content: "hello", writeErr: fault, wantErr: fault},
		{name: "close_error", content: "hello", closeErr: fault, wantErr: fault},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			fo := must.Get(newFileOps(dir))
			id := clientID("hash-test")
			const name = "file.txt"
			partialName := name + id.partialSuffix()
			if tt.prefix != "" && !tt.interrupted {
				if err := os.WriteFile(filepath.Join(dir, partialName), []byte(tt.prefix), 0600); err != nil {
					t.Fatal(err)
				}
			}
			reads := 0
			ops := hashTestFileOps{FileOps: fo, openReader: func(n string) (io.ReadCloser, error) {
				reads++
				if tt.readErr != nil {
					return nil, tt.readErr
				}
				if tt.shortPrefix {
					return io.NopCloser(strings.NewReader("h")), nil
				}
				// The new suffix must not have been written yet.
				if fi := must.Get(fo.Stat(n)); fi.Size() != tt.offset {
					t.Errorf("read after suffix was written: size=%d, offset=%d", fi.Size(), tt.offset)
				}
				return fo.OpenReader(n)
			}, wrapWriter: func(w io.WriteCloser) io.WriteCloser {
				return hashTestWriter{w, tt.writeErr, tt.closeErr}
			}}
			m := managerOptions{Logf: t.Logf, Clock: tstime.DefaultClock{}, fileOps: ops, SendFileNotify: func() {}}.New()
			t.Cleanup(m.Shutdown)
			hash := fmt.Sprintf("%x", sha256.Sum256([]byte(tt.content)))
			if tt.interrupted {
				r := io.MultiReader(strings.NewReader(tt.prefix), iotest.ErrReader(fault))
				n, err := m.PutFile(id, name, r, 0, int64(len(tt.content)), hash)
				if !errors.Is(err, fault) || n != int64(len(tt.prefix)) {
					t.Fatalf("interrupted PutFile = %d, %v; want %d, %v", n, err, len(tt.prefix), fault)
				}
				if _, err := fo.Stat(name); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("interrupted transfer published a file: %v", err)
				}
			}
			suffix := tt.content[tt.offset:]
			n, err := m.PutFile(id, name, strings.NewReader(suffix), tt.offset, int64(len(suffix)), hash)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("PutFile: %v; want %v", err, tt.wantErr)
			}
			wantReads := 0
			if tt.offset > 0 {
				wantReads = 1
			}
			if reads != wantReads {
				t.Errorf("OpenReader calls = %d; want %d", reads, wantReads)
			}
			if tt.wantErr != nil {
				if _, err := fo.Stat(name); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("failed transfer published a file: %v", err)
				}
				return
			}
			if n != int64(len(tt.content)) {
				t.Errorf("length = %d; want %d", n, len(tt.content))
			}
			if got := must.Get(os.ReadFile(filepath.Join(dir, name))); string(got) != tt.content {
				t.Errorf("content = %q; want %q", got, tt.content)
			}
		})
	}
}

// TestPutFileWithoutConsentDoesNotReadPrefix verifies that ordinary resumed
// uploads preserve existing bytes without paying the extra prefix-read cost of
// consent hash verification.
func TestPutFileWithoutConsentDoesNotReadPrefix(t *testing.T) {
	dir := t.TempDir()
	fo := must.Get(newFileOps(dir))
	id := clientID("ordinary")
	const name = "file.txt"
	if err := os.WriteFile(filepath.Join(dir, name+id.partialSuffix()), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	ops := hashTestFileOps{FileOps: fo, openReader: func(string) (io.ReadCloser, error) {
		t.Error("ordinary resumed PUT opened its prefix for hashing")
		return nil, errors.New("unexpected prefix read")
	}}
	m := managerOptions{Logf: t.Logf, fileOps: ops}.New()
	t.Cleanup(m.Shutdown)
	n, err := m.PutFile(id, name, strings.NewReader(" world"), 5, 6, "")
	if err != nil || n != 11 {
		t.Fatalf("PutFile = %d, %v", n, err)
	}
	if got := string(must.Get(os.ReadFile(filepath.Join(dir, name)))); got != "hello world" {
		t.Fatalf("content = %q", got)
	}
}
