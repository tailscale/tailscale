// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
