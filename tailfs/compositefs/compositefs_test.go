// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositefs

import (
	"context"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/webdav"
	"tailscale.com/tailfs/shared"
)

func TestStat(t *testing.T) {
	cfs, dir1, _, close := createFileSystem(t)
	defer close()

	tests := []struct {
		label    string
		name     string
		expected fs.FileInfo
		err      error
	}{
		{
			label: "root folder",
			name:  "/",
			expected: &shared.StaticFileInfo{
				Named:    "/",
				Sized:    0,
				Moded:    0555,
				ModTimed: time.Time{},
				Dir:      true,
			},
		},
		{
			label: "remote1",
			name:  "/remote1",
			expected: &shared.StaticFileInfo{
				Named:    "/remote1",
				Sized:    0,
				Moded:    0555,
				ModTimed: time.Time{},
				Dir:      true,
			},
		},
		{
			label: "remote2",
			name:  "/remote2",
			expected: &shared.StaticFileInfo{
				Named:    "/remote2",
				Sized:    0,
				Moded:    0555,
				ModTimed: time.Time{},
				Dir:      true,
			},
		},
		{
			label: "non-existent remote",
			name:  "/remote3",
			err:   os.ErrNotExist,
		},
		{
			label: "file on remote1",
			name:  "/remote1/file1.txt",
			expected: &shared.StaticFileInfo{
				Named:    "/remote1/file1.txt",
				Sized:    stat(t, filepath.Join(dir1, "file1.txt")).Size(),
				Moded:    0644,
				ModTimed: stat(t, filepath.Join(dir1, "file1.txt")).ModTime(),
				Dir:      false,
			},
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			fi, err := cfs.Stat(ctx, test.name)
			if test.err != nil {
				if err == nil || test.err.Error() != err.Error() {
					t.Errorf("expected error: %v   got: %v", test.err, err)
				}
			} else {
				if err != nil {
					t.Errorf("unable to stat file: %v", err)
				} else {
					infosEqual(t, test.expected, fi)
				}
			}
		})
	}
}

func TestMkdir(t *testing.T) {
	fs, _, _, close := createFileSystem(t)
	defer close()

	tests := []struct {
		label string
		name  string
		perm  os.FileMode
		err   error
	}{
		{
			label: "attempt to create root folder",
			name:  "/",
			err:   os.ErrPermission,
		},
		{
			label: "attempt to create remote",
			name:  "/remote1",
			err:   os.ErrPermission,
		},
		{
			label: "attempt to create non-existent remote",
			name:  "/remote3",
			err:   os.ErrPermission,
		},
		{
			label: "success",
			name:  "/remote1/newfile.txt",
			perm:  0772,
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			err := fs.Mkdir(ctx, test.name, test.perm)
			if test.err != nil {
				if err == nil || test.err.Error() != err.Error() {
					t.Errorf("expected error: %v   got: %v", test.err, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else {
					fi, err := fs.Stat(ctx, test.name)
					if err != nil {
						t.Errorf("unable to stat file: %v", err)
					} else {
						if fi.Name() != test.name {
							t.Errorf("expected name: %v   got: %v", test.name, fi.Name())
						}
						if !fi.IsDir() {
							t.Error("expected directory")
						}
					}
				}
			}
		})
	}
}

func TestRemoveAll(t *testing.T) {
	fs, _, _, close := createFileSystem(t)
	defer close()

	tests := []struct {
		label string
		name  string
		err   error
	}{
		{
			label: "attempt to remove root folder",
			name:  "/",
			err:   os.ErrPermission,
		},
		{
			label: "attempt to remove remote",
			name:  "/remote1",
			err:   os.ErrPermission,
		},
		{
			label: "attempt to remove non-existent remote",
			name:  "/remote3",
			err:   os.ErrPermission,
		},
		{
			label: "remove non-existent file",
			name:  "/remote1/nonexistent.txt",
		},
		{
			label: "remove existing file",
			name:  "/remote1/dir1",
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			err := fs.RemoveAll(ctx, test.name)
			if test.err != nil {
				if err == nil || test.err.Error() != err.Error() {
					t.Errorf("expected error: %v   got: %v", test.err, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else {
					_, err := fs.Stat(ctx, test.name)
					if !os.IsNotExist(err) {
						t.Errorf("expected dir to be gone: %v", err)
					}
				}
			}
		})
	}
}

func TestRename(t *testing.T) {
	fs, _, _, close := createFileSystem(t)
	defer close()

	tests := []struct {
		label           string
		oldName         string
		newName         string
		err             error
		expectedNewInfo *shared.StaticFileInfo
	}{
		{
			label:   "attempt to move root folder",
			oldName: "/",
			newName: "/remote2/copy.txt",
			err:     os.ErrPermission,
		},
		{
			label:   "attempt to move to root folder",
			oldName: "/remote1/file1.txt",
			newName: "/",
			err:     os.ErrPermission,
		},
		{
			label:   "attempt to move to remote",
			oldName: "/remote1/file1.txt",
			newName: "/remote2",
			err:     os.ErrPermission,
		},
		{
			label:   "attempt to move to non-existent remote",
			oldName: "/remote1/file1.txt",
			newName: "/remote3",
			err:     os.ErrPermission,
		},
		{
			label:   "attempt to move file from non-existent remote",
			oldName: "/remote3/file1.txt",
			newName: "/remote1/file1.txt",
			err:     os.ErrPermission,
		},
		{
			label:   "attempt to move non-existent file",
			oldName: "/remote2/filenonexistent.txt",
			newName: "/remote1/file1.txt",
			err:     os.ErrNotExist,
		},
		{
			label:   "move file within remote",
			oldName: "/remote2/file2.txt",
			newName: "/remote2/file3.txt",
			expectedNewInfo: &shared.StaticFileInfo{
				Named: "/remote2/file3.txt",
				Sized: 5,
				Moded: 0644,
				Dir:   false,
			},
		},
		{
			label:   "move file across remotes",
			oldName: "/remote1/file1.txt",
			newName: "/remote2/file1.txt",
			expectedNewInfo: &shared.StaticFileInfo{
				Named: "/remote2/file1.txt",
				Sized: 5,
				Moded: 0644,
				Dir:   false,
			},
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			err := fs.Rename(ctx, test.oldName, test.newName)
			if test.err != nil {
				if err == nil || test.err.Error() != err.Error() {
					t.Errorf("expected error: %v   got: %v", test.err, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else {
					fi, err := fs.Stat(ctx, test.newName)
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					} else {
						// Override modTime to avoid having to compare it
						test.expectedNewInfo.ModTimed = fi.ModTime()
						infosEqual(t, test.expectedNewInfo, fi)
					}
				}
			}
		})
	}
}

func createFileSystem(t *testing.T) (webdav.FileSystem, string, string, func()) {
	l1, dir1 := startRemote(t)

	l2, dir2 := startRemote(t)

	// make some files
	err := os.WriteFile(filepath.Join(dir1, "file1.txt"), []byte("12345"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(dir2, "file2.txt"), []byte("54321"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// make some directories
	err = os.Mkdir(filepath.Join(dir1, "dir1"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Mkdir(filepath.Join(dir2, "dir2"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	fs := New(
		t.Logf,
		&child{
			name: "remote1",
			fs:   webdav.Dir(dir1),
		},
		&child{
			name: "remote2",
			fs:   webdav.Dir(dir2),
		})

	return fs, dir1, dir2, func() {
		defer l1.Close()
		defer os.RemoveAll(dir1)
		defer l2.Close()
		defer os.RemoveAll(dir2)
	}
}

func stat(t *testing.T, path string) fs.FileInfo {
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

func startRemote(t *testing.T) (net.Listener, string) {
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatal(err)
	}

	h := &webdav.Handler{
		FileSystem: webdav.Dir(dir),
		LockSystem: webdav.NewMemLS(),
	}

	s := &http.Server{Handler: h}
	go s.Serve(l)

	return l, dir
}

func infosEqual(t *testing.T, expected, actual fs.FileInfo) {
	if expected.Name() != actual.Name() {
		t.Errorf("expected name: %v   got: %v", expected.Name(), actual.Name())
	}
	if expected.Size() != actual.Size() {
		t.Errorf("expected Size: %v   got: %v", expected.Size(), actual.Size())
	}
	if expected.Mode() != actual.Mode() {
		t.Errorf("expected Mode: %v   got: %v", expected.Mode(), actual.Mode())
	}
	if !expected.ModTime().Truncate(time.Second).UTC().Equal(actual.ModTime().Truncate(time.Second).UTC()) {
		t.Errorf("expected ModTime: %v   got: %v", expected.ModTime(), actual.ModTime())
	}
	if expected.IsDir() != actual.IsDir() {
		t.Errorf("expected IsDir: %v   got: %v", expected.IsDir(), actual.IsDir())
	}
}
