// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositefs

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tailscale/xnet/webdav"
	"tailscale.com/tailfs/shared"
	"tailscale.com/tstest"
)

func TestStat(t *testing.T) {
	cfs, dir1, _, clock, close := createFileSystem(t, nil)
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
				Named:      "/",
				Sized:      0,
				ModdedTime: clock.Now(),
				Dir:        true,
			},
		},
		{
			label: "remote1",
			name:  "/remote1",
			expected: &shared.StaticFileInfo{
				Named:      "/remote1",
				Sized:      0,
				ModdedTime: clock.Now(),
				Dir:        true,
			},
		},
		{
			label: "remote2",
			name:  "/remote2",
			expected: &shared.StaticFileInfo{
				Named:      "/remote2",
				Sized:      0,
				ModdedTime: clock.Now(),
				Dir:        true,
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
				Named:      "/remote1/file1.txt",
				Sized:      stat(t, filepath.Join(dir1, "file1.txt")).Size(),
				ModdedTime: stat(t, filepath.Join(dir1, "file1.txt")).ModTime(),
				Dir:        false,
			},
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			fi, err := cfs.Stat(ctx, test.name)
			if test.err != nil {
				if err == nil || !errors.Is(err, test.err) {
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

func TestStatWithStatChildren(t *testing.T) {
	cfs, dir1, dir2, _, close := createFileSystem(t, &Options{StatChildren: true})
	defer close()

	tests := []struct {
		label    string
		name     string
		expected fs.FileInfo
	}{
		{
			label: "root folder",
			name:  "/",
			expected: &shared.StaticFileInfo{
				Named:      "/",
				Sized:      0,
				ModdedTime: stat(t, dir2).ModTime(), // ModTime should be greatest modtime of children
				Dir:        true,
			},
		},
		{
			label: "remote1",
			name:  "/remote1",
			expected: &shared.StaticFileInfo{
				Named:      "/remote1",
				Sized:      stat(t, dir1).Size(),
				ModdedTime: stat(t, dir1).ModTime(),
				Dir:        true,
			},
		},
		{
			label: "remote2",
			name:  "/remote2",
			expected: &shared.StaticFileInfo{
				Named:      "/remote2",
				Sized:      stat(t, dir2).Size(),
				ModdedTime: stat(t, dir2).ModTime(),
				Dir:        true,
			},
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			fi, err := cfs.Stat(ctx, test.name)
			if err != nil {
				t.Errorf("unable to stat file: %v", err)
			} else {
				infosEqual(t, test.expected, fi)
			}
		})
	}
}

func TestMkdir(t *testing.T) {
	fs, _, _, _, close := createFileSystem(t, nil)
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
		},
		{
			label: "attempt to create remote",
			name:  "/remote1",
		},
		{
			label: "attempt to create non-existent remote",
			name:  "/remote3",
			err:   os.ErrPermission,
		},
		{
			label: "attempt to create file on non-existent remote",
			name:  "/remote3/somefile.txt",
			err:   os.ErrNotExist,
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
				if err == nil || !errors.Is(err, test.err) {
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
	fs, _, _, _, close := createFileSystem(t, nil)
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
			label: "attempt to remove file on non-existent remote",
			name:  "/remote3/somefile.txt",
			err:   os.ErrNotExist,
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
				if err == nil || !errors.Is(err, test.err) {
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
	fs, _, _, _, close := createFileSystem(t, nil)
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
			err:     os.ErrNotExist,
		},
		{
			label:   "attempt to move file to a non-existent remote",
			oldName: "/remote2/file2.txt",
			newName: "/remote3/file2.txt",
			err:     os.ErrNotExist,
		},
		{
			label:   "attempt to move file across remotes",
			oldName: "/remote1/file1.txt",
			newName: "/remote2/file1.txt",
			err:     os.ErrPermission,
		},
		{
			label:   "attempt to move remote itself",
			oldName: "/remote1",
			newName: "/remote2",
			err:     os.ErrPermission,
		},
		{
			label:   "attempt to move to a remote",
			oldName: "/remote1/file2.txt",
			newName: "/remote2",
			err:     os.ErrPermission,
		},
		{
			label:   "move file within remote",
			oldName: "/remote2/file2.txt",
			newName: "/remote2/file3.txt",
			expectedNewInfo: &shared.StaticFileInfo{
				Named: "/remote2/file3.txt",
				Sized: 5,
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
						test.expectedNewInfo.ModdedTime = fi.ModTime()
						infosEqual(t, test.expectedNewInfo, fi)
					}
				}
			}
		})
	}
}

func createFileSystem(t *testing.T, opts *Options) (webdav.FileSystem, string, string, *tstest.Clock, func()) {
	l1, dir1 := startRemote(t)
	l2, dir2 := startRemote(t)

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

	if opts == nil {
		opts = &Options{}
	}
	if opts.Logf == nil {
		opts.Logf = t.Logf
	}
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Now()})
	opts.Clock = clock

	fs := New(*opts)
	fs.AddChild(&Child{Name: "remote4", FS: &closeableFS{webdav.Dir(dir2)}})
	fs.SetChildren(&Child{Name: "remote2", FS: webdav.Dir(dir2)},
		&Child{Name: "remote3", FS: &closeableFS{webdav.Dir(dir2)}},
	)
	fs.AddChild(&Child{Name: "remote1", FS: webdav.Dir(dir1)})
	fs.RemoveChild("remote3")

	child, ok := fs.GetChild("remote1")
	if !ok || child == nil {
		t.Fatal("unable to GetChild(remote1)")
	}
	child, ok = fs.GetChild("remote2")
	if !ok || child == nil {
		t.Fatal("unable to GetChild(remote2)")
	}
	child, ok = fs.GetChild("remote3")
	if ok || child != nil {
		t.Fatal("should have been able to GetChild(remote3)")
	}
	child, ok = fs.GetChild("remote4")
	if ok || child != nil {
		t.Fatal("should have been able to GetChild(remote4)")
	}

	return fs, dir1, dir2, clock, func() {
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
	dir := t.TempDir()

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
	t.Helper()
	if expected.Name() != actual.Name() {
		t.Errorf("expected name: %v   got: %v", expected.Name(), actual.Name())
	}
	if expected.Size() != actual.Size() {
		t.Errorf("expected Size: %v   got: %v", expected.Size(), actual.Size())
	}
	if !expected.ModTime().Truncate(time.Second).UTC().Equal(actual.ModTime().Truncate(time.Second).UTC()) {
		t.Errorf("expected ModTime: %v   got: %v", expected.ModTime(), actual.ModTime())
	}
	if expected.IsDir() != actual.IsDir() {
		t.Errorf("expected IsDir: %v   got: %v", expected.IsDir(), actual.IsDir())
	}
}

// closeableFS is a webdav.FileSystem that implements io.Closer()
type closeableFS struct {
	webdav.FileSystem
}

func (cfs *closeableFS) Close() error {
	return nil
}
