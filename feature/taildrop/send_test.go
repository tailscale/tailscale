// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
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

func TestPutFileRestart(t *testing.T) {
	for _, direct := range []bool{false, true} {
		for _, tt := range []struct {
			name   string
			offset int64
			body   string
			want   string
		}{
			{"shorter", 0, "NEW", "NEW"},
			{"empty", 0, "", ""},
			{"longer", 0, "LONGER-REPLACEMENT", "LONGER-REPLACEMENT"},
			{"resume", 3, "-NEW", "OLD-NEW"},
		} {
			t.Run(fmt.Sprintf("direct=%v/%s", direct, tt.name), func(t *testing.T) {
				dir := t.TempDir()
				m := managerOptions{fileOps: must.Get(newFileOps(dir)), DirectFileMode: direct}.New()
				defer m.Shutdown()
				const id = clientID("sender")
				const name = "file.txt"
				r := io.MultiReader(strings.NewReader("OLD-CONTENT"), iotest.ErrReader(io.ErrUnexpectedEOF))
				if _, err := m.PutFile(id, name, r, 0, 100); !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("interrupted PutFile: %v", err)
				}
				n, err := m.PutFile(id, name, strings.NewReader(tt.body), tt.offset, int64(len(tt.body)))
				if err != nil {
					t.Fatal(err)
				}
				if n != int64(len(tt.want)) {
					t.Errorf("length = %d; want %d", n, len(tt.want))
				}
				got := must.Get(os.ReadFile(filepath.Join(dir, name)))
				if string(got) != tt.want {
					t.Errorf("contents = %q; want %q", got, tt.want)
				}
			})
		}
	}
}

func TestPutFileRejectDuplicateBeforeOpening(t *testing.T) {
	for _, offset := range []int64{0, 1} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			dir := t.TempDir()
			m := managerOptions{fileOps: must.Get(newFileOps(dir))}.New()
			defer m.Shutdown()
			const id = clientID("sender")
			const name = "file.txt"
			// Attempt another upload after the first has written its prefix,
			// but before it completes. No scheduler timing is involved.
			r := io.MultiReader(strings.NewReader("OLD"), taildropReaderFunc(func([]byte) (int, error) {
				if _, err := m.PutFile(id, name, strings.NewReader("NEW"), offset, 3); err != ErrFileExists {
					t.Errorf("duplicate PutFile: %v; want ErrFileExists", err)
				}
				got := must.Get(os.ReadFile(filepath.Join(dir, name+id.partialSuffix())))
				if string(got) != "OLD" {
					t.Errorf("active partial contents = %q; want OLD", got)
				}
				return 0, io.EOF
			}), strings.NewReader("-CONTENT"))
			if _, err := m.PutFile(id, name, r, 0, 11); err != nil {
				t.Fatal(err)
			}
			got := must.Get(os.ReadFile(filepath.Join(dir, name)))
			if string(got) != "OLD-CONTENT" {
				t.Errorf("contents = %q; want OLD-CONTENT", got)
			}
		})
	}
}

type taildropReaderFunc func([]byte) (int, error)

func (f taildropReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestPutFileOpenErrorReleasesTransfer(t *testing.T) {
	dir := t.TempDir()
	m := managerOptions{fileOps: must.Get(newFileOps(dir))}.New()
	defer m.Shutdown()
	for _, offset := range []int64{-1, 1} {
		if _, err := m.PutFile("sender", "file.txt", strings.NewReader("NEW"), offset, 3); err == nil || err == ErrFileExists {
			t.Fatalf("offset %d: got %v; want an OpenWriter error", offset, err)
		}
	}
	if _, err := m.PutFile("sender", "file.txt", strings.NewReader("NEW"), 0, 3); err != nil {
		t.Fatal(err)
	}
	if got := string(must.Get(os.ReadFile(filepath.Join(dir, "file.txt")))); got != "NEW" {
		t.Errorf("contents = %q; want NEW", got)
	}
}
