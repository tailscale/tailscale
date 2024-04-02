// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dirfs

import (
	"context"
	"errors"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/tailscale/xnet/webdav"
	"tailscale.com/drive/driveimpl/shared"
	"tailscale.com/tstest"
)

func TestStat(t *testing.T) {
	cfs, _, _, clock := createFileSystem(t)

	tests := []struct {
		label    string
		name     string
		expected fs.FileInfo
		err      error
	}{
		{
			label: "root folder",
			name:  "",
			expected: &shared.StaticFileInfo{
				Named:      "",
				Sized:      0,
				Moded:      0555,
				ModdedTime: clock.Now(),
				Dir:        true,
			},
		},
		{
			label: "static root folder",
			name:  "/domain",
			expected: &shared.StaticFileInfo{
				Named:      "domain",
				Sized:      0,
				Moded:      0555,
				ModdedTime: clock.Now(),
				Dir:        true,
			},
		},
		{
			label: "remote1",
			name:  "/domain/remote1",
			expected: &shared.StaticFileInfo{
				Named:      "remote1",
				Sized:      0,
				Moded:      0555,
				ModdedTime: clock.Now(),
				Dir:        true,
			},
		},
		{
			label: "remote2",
			name:  "/domain/remote2",
			expected: &shared.StaticFileInfo{
				Named:      "remote2",
				Sized:      0,
				Moded:      0555,
				ModdedTime: clock.Now(),
				Dir:        true,
			},
		},
		{
			label: "non-existent remote",
			name:  "remote3",
			err:   os.ErrNotExist,
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			fi, err := cfs.Stat(ctx, test.name)
			if test.err != nil {
				if !errors.Is(err, test.err) {
					t.Errorf("got %v, want %v", err, test.err)
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

func TestListDir(t *testing.T) {
	cfs, _, _, clock := createFileSystem(t)

	tests := []struct {
		label    string
		name     string
		expected []fs.FileInfo
		err      error
	}{
		{
			label: "root folder",
			name:  "",
			expected: []fs.FileInfo{
				&shared.StaticFileInfo{
					Named:      "domain",
					Sized:      0,
					Moded:      0555,
					ModdedTime: clock.Now(),
					Dir:        true,
				},
			},
		},
		{
			label: "static root folder",
			name:  "/domain",
			expected: []fs.FileInfo{
				&shared.StaticFileInfo{
					Named:      "remote1",
					Sized:      0,
					Moded:      0555,
					ModdedTime: clock.Now(),
					Dir:        true,
				},
				&shared.StaticFileInfo{
					Named:      "remote2",
					Sized:      0,
					Moded:      0555,
					ModdedTime: clock.Now(),
					Dir:        true,
				},
				&shared.StaticFileInfo{
					Named:      "remote4",
					Sized:      0,
					Moded:      0555,
					ModdedTime: clock.Now(),
					Dir:        true,
				},
			},
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			var infos []fs.FileInfo
			file, err := cfs.OpenFile(ctx, test.name, os.O_RDONLY, 0)
			if err == nil {
				defer file.Close()
				infos, err = file.Readdir(0)
			}
			if test.err != nil {
				if !errors.Is(err, test.err) {
					t.Errorf("got %v, want %v", err, test.err)
				}
			} else {
				if err != nil {
					t.Errorf("unable to stat file: %v", err)
				} else {
					if len(infos) != len(test.expected) {
						t.Errorf("wrong number of file infos, want %d, got %d", len(test.expected), len(infos))
					} else {
						for i, expected := range test.expected {
							infosEqual(t, expected, infos[i])
						}
					}
				}
			}
		})
	}
}

func TestMkdir(t *testing.T) {
	fs, _, _, _ := createFileSystem(t)

	tests := []struct {
		label string
		name  string
		perm  os.FileMode
		err   error
	}{
		{
			label: "attempt to create root folder",
			name:  "/",
		},
		{
			label: "attempt to create static root folder",
			name:  "/domain",
		},
		{
			label: "attempt to create remote",
			name:  "/domain/remote1",
		},
		{
			label: "attempt to create non-existent remote",
			name:  "/domain/remote3",
			err:   os.ErrPermission,
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			err := fs.Mkdir(ctx, test.name, test.perm)
			if test.err != nil {
				if !errors.Is(err, test.err) {
					t.Errorf("got %v, want %v", err, test.err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRemoveAll(t *testing.T) {
	fs, _, _, _ := createFileSystem(t)

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
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			err := fs.RemoveAll(ctx, test.name)
			if !errors.Is(err, test.err) {
				t.Errorf("got %v, want %v", err, test.err)
			}
		})
	}
}

func TestRename(t *testing.T) {
	fs, _, _, _ := createFileSystem(t)

	tests := []struct {
		label   string
		oldName string
		newName string
		err     error
	}{
		{
			label:   "attempt to move root folder",
			oldName: "/",
			newName: "/domain/remote2/copy.txt",
			err:     os.ErrPermission,
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			err := fs.Rename(ctx, test.oldName, test.newName)
			if !errors.Is(err, test.err) {
				t.Errorf("got %v, want: %v", err, test.err)
			}
		})
	}
}

func createFileSystem(t *testing.T) (webdav.FileSystem, string, string, *tstest.Clock) {
	s1, dir1 := startRemote(t)
	s2, dir2 := startRemote(t)

	// Make some files, use perms 0666 as lowest common denominator that works
	// on both UNIX and Windows.
	err := os.WriteFile(filepath.Join(dir1, "file1.txt"), []byte("12345"), 0666)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(dir2, "file2.txt"), []byte("54321"), 0666)
	if err != nil {
		t.Fatal(err)
	}

	// make some directories
	err = os.Mkdir(filepath.Join(dir1, "dir1"), 0666)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Mkdir(filepath.Join(dir2, "dir2"), 0666)
	if err != nil {
		t.Fatal(err)
	}

	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Now()})
	fs := &FS{
		Clock:      clock,
		StaticRoot: "domain",
		Children: []*Child{
			{Name: "remote1"},
			{Name: "remote2"},
			{Name: "remote4"},
		},
	}

	t.Cleanup(func() {
		defer s1.Close()
		defer os.RemoveAll(dir1)
		defer s2.Close()
		defer os.RemoveAll(dir2)
	})

	return fs, dir1, dir2, clock
}

func startRemote(t *testing.T) (*httptest.Server, string) {
	dir := t.TempDir()

	h := &webdav.Handler{
		FileSystem: webdav.Dir(dir),
		LockSystem: webdav.NewMemLS(),
	}

	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s, dir
}

func infosEqual(t *testing.T, expected, actual fs.FileInfo) {
	t.Helper()
	sfi, ok := actual.(*shared.StaticFileInfo)
	if ok {
		// zero out BirthedTime because we don't want to compare that
		sfi.BirthedTime = time.Time{}
	}
	if diff := cmp.Diff(actual, expected); diff != "" {
		t.Errorf("Wrong file info (-got, +want):\n%s", diff)
	}
}
