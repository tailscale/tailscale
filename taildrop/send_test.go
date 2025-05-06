// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tstime"
)

// nopWriteCloser is a no-op io.WriteCloser wrapping a bytes.Buffer.
type nopWriteCloser struct{ *bytes.Buffer }

func (nwc nopWriteCloser) Close() error { return nil }

// mockFileOps implements just enough of the FileOps interface for SAF tests.
type mockFileOps struct {
	writes   *bytes.Buffer
	renameOK bool
}

func (m *mockFileOps) OpenFileWriter(name string) (io.WriteCloser, string, error) {
	m.writes = new(bytes.Buffer)
	return nopWriteCloser{m.writes}, "uri://" + name + ".partial", nil
}

func (m *mockFileOps) RenamePartialFile(partialPath, dir, finalName string) (string, error) {
	if !m.renameOK {
		m.renameOK = true
		return "uri://" + finalName, nil
	}
	return "", io.ErrUnexpectedEOF
}

func TestPutFile(t *testing.T) {
	const content = "hello, world"

	tests := []struct {
		name     string
		mode     ipn.PutMode
		setup    func(t *testing.T) (*Manager, string, *mockFileOps)
		wantFile string
	}{
		{
			name: "PutModeDirect",
			mode: ipn.PutModeDirect,
			setup: func(t *testing.T) (*Manager, string, *mockFileOps) {
				dir := t.TempDir()
				opts := ManagerOptions{
					Logf:           t.Logf,
					Clock:          tstime.DefaultClock{},
					State:          nil,
					Dir:            dir,
					PutMode:        ipn.PutModeDirect,
					DirectFileMode: true,
					SendFileNotify: func() {},
				}
				mgr := opts.New(nil)
				return mgr, dir, nil
			},
			wantFile: "file.txt",
		},
		{
			name: "PutModeAndroidSAF",
			mode: ipn.PutModeAndroidSAF,
			setup: func(t *testing.T) (*Manager, string, *mockFileOps) {
				// SAF still needs a non-empty Dir to pass the guard.
				dir := t.TempDir()
				opts := ManagerOptions{
					Logf:           t.Logf,
					Clock:          tstime.DefaultClock{},
					State:          nil,
					Dir:            dir,
					PutMode:        ipn.PutModeAndroidSAF,
					DirectFileMode: true,
					SendFileNotify: func() {},
				}
				mops := &mockFileOps{}
				mgr := opts.New(mops)
				return mgr, dir, mops
			},
			wantFile: "file.txt",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mgr, dir, mops := tc.setup(t)
			id := ClientID(fmt.Sprint(0))
			reader := bytes.NewReader([]byte(content))

			n, err := mgr.PutFile(id, "file.txt", reader, 0, int64(len(content)))
			if err != nil {
				t.Fatalf("PutFile(%s) error: %v", tc.name, err)
			}
			if n != int64(len(content)) {
				t.Errorf("wrote %d bytes; want %d", n, len(content))
			}

			switch tc.mode {
			case ipn.PutModeDirect:
				path := filepath.Join(dir, tc.wantFile)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("ReadFile error: %v", err)
				}
				if got := string(data); got != content {
					t.Errorf("file contents = %q; want %q", got, content)
				}

			case ipn.PutModeAndroidSAF:
				if mops.writes == nil {
					t.Fatal("SAF writer was never created")
				}
				if got := mops.writes.String(); got != content {
					t.Errorf("SAF writes = %q; want %q", got, content)
				}
			}
		})
	}
}
