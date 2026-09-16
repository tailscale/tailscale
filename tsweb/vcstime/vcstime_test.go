// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vcstime

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

//go:embed testdata
var testFS embed.FS

func TestNewStampsModTime(t *testing.T) {
	mod := time.Unix(1700000000, 0).UTC()
	fsys := New(testFS, mod)

	if err := fstest.TestFS(fsys, "testdata/hello.txt", "testdata/sub/inner.txt"); err != nil {
		t.Fatalf("fstest.TestFS: %v", err)
	}

	f, err := fsys.Open("testdata/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if got := info.ModTime(); got != mod {
		t.Errorf("file ModTime = %v, want %v", got, mod)
	}
	if got, want := info.Name(), "hello.txt"; got != want {
		t.Errorf("Name = %q, want %q", got, want)
	}
	if info.IsDir() || info.Mode() != 0444 {
		t.Errorf("unexpected mode/isDir: %v %v", info.Mode(), info.IsDir())
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if want := "hello, embedded world\n"; string(got) != want {
		t.Errorf("content = %q, want %q", got, want)
	}

	// Directories and directory entries get stamped too.
	des, err := fs.ReadDir(fsys, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(des) != 2 {
		t.Fatalf("got %d entries, want 2: %v", len(des), des)
	}
	for _, de := range des {
		i, err := de.Info()
		if err != nil {
			t.Fatal(err)
		}
		if got := i.ModTime(); got != mod {
			t.Errorf("entry %q ModTime = %v, want %v", de.Name(), got, mod)
		}
	}
}

func TestHTTPCachingSemantics(t *testing.T) {
	mod := time.Unix(1700000000, 0).UTC()
	srv := httptest.NewServer(http.FileServerFS(New(testFS, mod)))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/testdata/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status = %v, want 200", res.StatusCode)
	}
	lm := res.Header.Get("Last-Modified")
	if want := mod.Format(http.TimeFormat); lm != want {
		t.Fatalf("Last-Modified = %q, want %q", lm, want)
	}

	// A conditional request should now be answered with 304.
	req, err := http.NewRequest("GET", srv.URL+"/testdata/hello.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("If-Modified-Since", mod.Format(http.TimeFormat))
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional request status = %v, want 304", res.StatusCode)
	}
}

func TestPassthroughRealTimestamps(t *testing.T) {
	real := time.Unix(1234567890, 0).UTC()
	stamp := time.Unix(1700000000, 0).UTC()
	mapFS := fstest.MapFS{
		"a.txt": &fstest.MapFile{Data: []byte("hi"), ModTime: real},
	}
	fsys := New(mapFS, stamp)
	fi, err := fs.Stat(fsys, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.ModTime(); got != real {
		t.Errorf("ModTime = %v, want untouched %v", got, real)
	}
}

func TestZeroModReturnsFSys(t *testing.T) {
	if got := New(testFS, time.Time{}); got != fs.FS(testFS) {
		t.Errorf("New with zero mod should return fsys unchanged, got %v", got)
	}
	fi, err := fs.Stat(testFS, "testdata/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.ModTime(); !got.IsZero() {
		t.Errorf("ModTime = %v, want zero", got)
	}
}

func TestVCSTime(t *testing.T) {
	good := time.Unix(1700000000, 0).UTC()
	t.Run("present", func(t *testing.T) {
		bi := &debug.BuildInfo{Settings: []debug.BuildSetting{
			{Key: "vcs.time", Value: good.Format(time.RFC3339)},
		}}
		if got := vcsTime(bi); got != good {
			t.Errorf("vcsTime = %v, want %v", got, good)
		}
	})
	t.Run("unparseable", func(t *testing.T) {
		bi := &debug.BuildInfo{Settings: []debug.BuildSetting{
			{Key: "vcs.time", Value: "not-a-time"},
		}}
		if got := vcsTime(bi); !got.IsZero() {
			t.Errorf("vcsTime = %v, want zero", got)
		}
	})
	t.Run("absent", func(t *testing.T) {
		bi := &debug.BuildInfo{Settings: []debug.BuildSetting{
			{Key: "GOOS", Value: "linux"},
		}}
		if got := vcsTime(bi); !got.IsZero() {
			t.Errorf("vcsTime = %v, want zero", got)
		}
	})
}

func TestFSMatchesModTime(t *testing.T) {
	// FS stamps with ModTime, which may be zero in unstamped test
	// binaries (go test does not stamp vcs info by default).
	mod := ModTime()
	fsys := FS(testFS)
	if mod.IsZero() {
		if fsys != fs.FS(testFS) {
			t.Errorf("FS should return fsys unchanged when ModTime is zero")
		}
		return
	}
	fi, err := fs.Stat(fsys, "testdata/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.ModTime(); got != mod {
		t.Errorf("ModTime = %v, want %v", got, mod)
	}
}

func TestModTimeMatchesBuildInfo(t *testing.T) {
	var want time.Time
	bi, ok := debug.ReadBuildInfo()
	if ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.time" {
				want, _ = time.Parse(time.RFC3339, s.Value)
				break
			}
		}
	}
	if got := ModTime(); got != want {
		t.Errorf("ModTime = %v, want %v", got, want)
	}
}

func TestWrappedSubFS(t *testing.T) {
	mod := time.Unix(1700000000, 0).UTC()
	sub, err := fs.Sub(New(testFS, mod), "testdata")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := fs.Stat(sub, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.ModTime(); got != mod {
		t.Errorf("sub FS ModTime = %v, want %v", got, mod)
	}
	if got, err := fs.ReadFile(sub, "hello.txt"); err != nil || !strings.HasPrefix(string(got), "hello") {
		t.Errorf("sub FS ReadFile = %q, %v", got, err)
	}
}

// plainFS hides the fs.ReadDirFS and fs.ReadFileFS implementations of
// the wrapped file system, so that only the plain fs.FS fallback paths
// of modFS are exercised.
type plainFS struct{ fs.FS }

func TestFallbackWithoutReadDirFSOrReadFileFS(t *testing.T) {
	mod := time.Unix(1700000000, 0).UTC()
	mapFS := fstest.MapFS{
		"a.txt":   &fstest.MapFile{Data: []byte("a content")},
		"d/b.txt": &fstest.MapFile{Data: []byte("b content")},
	}
	fsys := New(plainFS{mapFS}, mod)

	// ReadDir falls back to opening the directory and reading its
	// entries, which are still stamped.
	des, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(des) != 2 {
		t.Fatalf("got %d entries, want 2: %v", len(des), des)
	}
	for _, de := range des {
		i, err := de.Info()
		if err != nil {
			t.Fatal(err)
		}
		if got := i.ModTime(); got != mod {
			t.Errorf("entry %q ModTime = %v, want %v", de.Name(), got, mod)
		}
	}

	// ReadFile falls back to Open plus a plain read.
	got, err := fs.ReadFile(fsys, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "a content" {
		t.Errorf("ReadFile = %q, want %q", got, "a content")
	}

	// The opened directory is still an fs.ReadDirFile.
	f, err := fsys.Open("d")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	des, err = f.(fs.ReadDirFile).ReadDir(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(des) != 1 || des[0].Name() != "b.txt" {
		t.Fatalf("ReadDir = %v, want [b.txt]", des)
	}
	if i, _ := des[0].Info(); i.ModTime() != mod {
		t.Errorf("entry b.txt ModTime = %v, want %v", i.ModTime(), mod)
	}
}
