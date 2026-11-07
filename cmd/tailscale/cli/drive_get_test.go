// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive && !ts_mac_gui

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/xnet/webdav"
)

func TestDriveGet(t *testing.T) {
	for _, name := range []string{"file.txt", "subdir/file.txt", "space name.txt", "日本語.txt", "%2e%2e%#?.bin"} {
		t.Run(name, func(t *testing.T) {
			if runtime.GOOS == "windows" && strings.ContainsAny(name, `<>:"\|?*`) {
				t.Skip("filename is not representable on the local Windows filesystem")
			}
			source := t.TempDir()
			filename := filepath.Join(source, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
				t.Fatal(err)
			}
			content := []byte("hello\x00\xff\nexact bytes")
			if err := os.WriteFile(filename, content, 0600); err != nil {
				t.Fatal(err)
			}
			dav := &webdav.Handler{Prefix: "/example.com/pippo/shared", FileSystem: webdav.Dir(source), LockSystem: webdav.NewMemLS()}
			server := httptest.NewServer(dav)
			defer server.Close()
			remote, err := parseDriveRemotePath("pippo:shared/" + name)
			if err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{"default", "directory", "filename"} {
				t.Run(mode, func(t *testing.T) {
					dir := t.TempDir()
					dest, want := dir, filepath.Join(dir, filepath.Base(name))
					if mode == "default" {
						t.Chdir(dir)
						dest = "."
						want = filepath.Base(name)
					}
					if mode == "filename" {
						dest = filepath.Join(dir, "renamed")
						want = dest
					}
					got, n, err := getDriveFile(context.Background(), driveTestStatus(), remote, dest, server.URL)
					if err != nil || got != want || n != int64(len(content)) {
						t.Fatalf("get = %q, %d, %v; want %q", got, n, err, want)
					}
					if runtime.GOOS != "windows" {
						fi, err := os.Stat(want)
						if err != nil {
							t.Fatal(err)
						}
						if fi.Mode().Perm() & ^os.FileMode(0600) != 0 {
							t.Fatalf("download permissions broadened: %v", fi.Mode())
						}
					} else {
						zone, err := os.ReadFile(want + ":Zone.Identifier")
						if err != nil || !strings.Contains(string(zone), "ZoneId=3") {
							t.Fatalf("download quarantine = %q, %v", zone, err)
						}
					}
					data, err := os.ReadFile(want)
					if err != nil || !bytes.Equal(data, content) {
						t.Fatalf("contents = %q, %v", data, err)
					}
					_, _, err = getDriveFile(context.Background(), driveTestStatus(), remote, dest, server.URL)
					if !errors.Is(err, os.ErrExist) {
						t.Fatalf("overwrite error = %v", err)
					}
					data, _ = os.ReadFile(want)
					if !bytes.Equal(data, content) {
						t.Fatal("existing file changed")
					}
					assertNoDriveTemps(t, dir)
				})
			}
		})
	}
}

func assertNoDriveTemps(t *testing.T, dir string) {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, ".tailscale-drive-*"))
	if err != nil || len(names) != 0 {
		t.Fatalf("temporary files = %v, %v", names, err)
	}
}

func TestDriveGetInvalidArgs(t *testing.T) {
	for _, args := range [][]string{{"get"}, {"get", "pippo:shared"}, {"get", "pippo:shared/"}, {"get", "pippo:shared/../x"}, {"get", "pippo:shared/a", "x", "y"}} {
		cmd := driveCmd()
		if err := cmd.Parse(args); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Run(context.Background()); err == nil {
			t.Fatalf("%v succeeded", args)
		}
	}
}

func TestDriveGetFailures(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "file"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	dav := &webdav.Handler{Prefix: "/example.com/pippo/shared", FileSystem: webdav.Dir(source), LockSystem: webdav.NewMemLS()}
	for _, mode := range []string{"404", "403", "get-404", "get-403", "directory", "local-error", "permission", "truncated", "race", "symlink", "cleanup-error", "changed-to-directory"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			destination := filepath.Join(dir, "download")
			remote := driveRemotePath{"pippo", "shared", "file"}
			want := ""
			switch mode {
			case "404", "get-404":
				want = "not found"
			case "403", "get-403":
				want = "access denied"
			case "directory":
				remote.path = "folder"
				if err := os.Mkdir(filepath.Join(source, "folder"), 0700); err != nil {
					t.Fatal(err)
				}
				want = "recursive downloads"
			case "local-error":
				destination = filepath.Join(dir, "missing", "download")
				want = "destination directory"
			case "cleanup-error":
				if runtime.GOOS == "windows" || os.Geteuid() == 0 {
					t.Skip("requires Unix directory permissions")
				}
				want = "removing temporary download"
				defer os.Chmod(dir, 0700)
			case "changed-to-directory":
				want = "method not allowed"
			case "permission":
				if runtime.GOOS == "windows" {
					t.Skip("Unix mode bits do not control Windows directory ACLs")
				}
				if os.Geteuid() == 0 {
					t.Skip("root bypasses directory permissions")
				}
				if err := os.Chmod(dir, 0500); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(dir, 0700)
				want = "permission denied"
			case "truncated":
				want = "download failed while copying to"
			case "race":
				want = "already exists"
			case "symlink":
				if err := os.Symlink(filepath.Join(dir, "missing"), destination); err != nil {
					t.Skipf("cannot create test symlink: %v", err)
				}
				want = "already exists"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "404" || mode == "403" || r.Method == "GET" && (mode == "get-404" || mode == "get-403") {
					code := 404
					if mode == "403" || mode == "get-403" {
						code = 403
					}
					http.Error(w, "<private XML>", code)
					return
				}
				if r.Method == "GET" && mode == "cleanup-error" {
					if err := os.Chmod(dir, 0500); err != nil {
						t.Error(err)
					}
				}
				if r.Method == "GET" && mode == "changed-to-directory" {
					http.Error(w, "directory changed since Stat", http.StatusMethodNotAllowed)
					return
				}
				if r.Method == "GET" && mode == "truncated" {
					w.Header().Set("Content-Length", "100")
					fmt.Fprint(w, "short")
					return
				}
				if r.Method == "GET" && mode == "race" {
					if err := os.WriteFile(destination, []byte("winner"), 0600); err != nil {
						t.Error(err)
					}
				}
				dav.ServeHTTP(w, r)
			}))
			defer server.Close()
			_, _, err := getDriveFile(context.Background(), driveTestStatus(), remote, destination, server.URL)
			if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "private XML") {
				t.Fatalf("error = %v; want %q", err, want)
			}
			if mode == "cleanup-error" {
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				names, err := filepath.Glob(filepath.Join(dir, ".tailscale-drive-*"))
				if err != nil || len(names) != 1 {
					t.Fatalf("leftovers = %v, %v", names, err)
				}
				if err := os.Remove(names[0]); err != nil {
					t.Fatal(err)
				}
			}
			assertNoDriveTemps(t, dir)
			if mode == "race" {
				b, _ := os.ReadFile(destination)
				if string(b) != "winner" {
					t.Fatalf("race overwrote winner: %q", b)
				}
			} else if mode != "symlink" {
				if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("partial destination exists: %v", err)
				}
			}
		})
	}
}

func TestDriveGetStreamingAndCancellation(t *testing.T) {
	for _, cancelTransfer := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelTransfer), func(t *testing.T) {
			source := t.TempDir()
			if err := os.WriteFile(filepath.Join(source, "file"), []byte("metadata"), 0600); err != nil {
				t.Fatal(err)
			}
			dav := &webdav.Handler{Prefix: "/example.com/pippo/shared", FileSystem: webdav.Dir(source), LockSystem: webdav.NewMemLS()}
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					dav.ServeHTTP(w, r)
					return
				}
				// Keep the response open until the test observes bytes on disk. A fully
				// buffered implementation cannot complete this handshake.
				chunk := bytes.Repeat([]byte("x"), 64<<10)
				for range 128 {
					if _, err := w.Write(chunk); err != nil {
						return
					}
				}
				w.(http.Flusher).Flush()
				select {
				case <-release:
					io.WriteString(w, "end")
				case <-r.Context().Done():
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dir := t.TempDir()
			dest := filepath.Join(dir, "download")
			done := make(chan error, 1)
			go func() {
				_, _, err := getDriveFile(ctx, driveTestStatus(), driveRemotePath{"pippo", "shared", "file"}, dest, server.URL)
				done <- err
			}()
			deadline := time.Now().Add(10 * time.Second)
			streamed := false
			for time.Now().Before(deadline) {
				names, _ := filepath.Glob(filepath.Join(dir, ".tailscale-drive-*"))
				if len(names) == 1 {
					if st, err := os.Stat(names[0]); err == nil && st.Size() > 0 {
						streamed = true
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !streamed {
				cancel()
				t.Fatal("no streamed bytes reached disk before response completed")
			}
			if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("destination published before completion")
			}
			if cancelTransfer {
				cancel()
			} else {
				close(release)
			}
			select {
			case err := <-done:
				if cancelTransfer {
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancel error = %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("download did not stop")
			}
			assertNoDriveTemps(t, dir)
			if cancelTransfer {
				if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("canceled destination exists")
				}
			} else {
				st, err := os.Stat(dest)
				if err != nil || st.Size() != 8<<20+3 {
					t.Fatalf("download size: %v, %v", st, err)
				}
			}
		})
	}
}

func TestDriveGetDirectorySyntax(t *testing.T) {
	for _, arg := range []string{"pippo:shared/file/.", "pippo:shared/file/./.", "pippo:shared/folder/"} {
		remote, err := parseDriveRemotePath(arg)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkDriveGetPath(remote); err == nil || !strings.Contains(err.Error(), "recursive downloads") {
			t.Fatalf("checkDriveGetPath(%q) = %v; want directory error", arg, err)
		}
	}
}

func TestDriveGetDestinationSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	remote := driveRemotePath{"pippo", "shared", "file.txt"}
	for _, name := range []string{"file", "dangling", "directory"} {
		link := filepath.Join(dir, name)
		to := target
		if name == "dangling" {
			to = filepath.Join(dir, "missing")
		}
		if name == "directory" {
			to = dir
		}
		if err := os.Symlink(to, link); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		got, err := driveGetDestination(remote, link)
		if name == "directory" {
			if err != nil || got != filepath.Join(link, "file.txt") {
				t.Fatalf("directory symlink = %q, %v", got, err)
			}
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatalf("%s symlink error = %v", name, err)
		}
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("target changed: %q, %v", data, err)
	}
}
