// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package web

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/klauspost/compress/zstd"
)

func compressZstd(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf, zstd.WithWindowSize(8<<20))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestOpenPrecompressedFile_ZstdPassthrough(t *testing.T) {
	original := []byte("hello world")
	compressed := compressZstd(t, original)

	tfs := fstest.MapFS{
		"test.js.zst": &fstest.MapFile{Data: compressed},
	}

	r := httptest.NewRequest("GET", "/test.js", nil)
	r.Header.Set("Accept-Encoding", "zstd, gzip")
	w := httptest.NewRecorder()

	f, err := openPrecompressedFile(w, r, "test.js", tfs)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if got := w.Header().Get("Content-Encoding"); got != "zstd" {
		t.Errorf("Content-Encoding = %q, want %q", got, "zstd")
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	// Should return the raw compressed bytes when client accepts zstd.
	if !bytes.Equal(got, compressed) {
		t.Errorf("got decompressed data, want raw compressed passthrough")
	}
}

func TestOpenPrecompressedFile_ZstdDecompress(t *testing.T) {
	original := []byte("hello world")
	compressed := compressZstd(t, original)

	tfs := fstest.MapFS{
		"test.js.zst": &fstest.MapFile{Data: compressed},
	}

	// Client does not accept zstd.
	r := httptest.NewRequest("GET", "/test.js", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()

	f, err := openPrecompressedFile(w, r, "test.js", tfs)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty (transparent decompression)", got)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("got %q, want %q", got, original)
	}
}

func TestOpenPrecompressedFile_GzipFallback(t *testing.T) {
	gzData := []byte("fake-gzip-data")
	tfs := fstest.MapFS{
		"test.js.gz": &fstest.MapFile{Data: gzData},
	}

	r := httptest.NewRequest("GET", "/test.js", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()

	f, err := openPrecompressedFile(w, r, "test.js", tfs)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if got := w.Header().Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want %q", got, "gzip")
	}
}

func TestOpenPrecompressedFile_GzipNotAccepted(t *testing.T) {
	tfs := fstest.MapFS{
		"test.js":    &fstest.MapFile{Data: []byte("raw js")},
		"test.js.gz": &fstest.MapFile{Data: []byte("fake-gzip-data")},
	}

	// Client accepts neither zstd nor gzip.
	r := httptest.NewRequest("GET", "/test.js", nil)
	w := httptest.NewRecorder()

	f, err := openPrecompressedFile(w, r, "test.js", tfs)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty (no compression accepted)", got)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "raw js" {
		t.Errorf("got %q, want %q", got, "raw js")
	}
}

func TestOpenPrecompressedFile_PlainFallback(t *testing.T) {
	tfs := fstest.MapFS{
		"test.js": &fstest.MapFile{Data: []byte("raw js")},
	}

	r := httptest.NewRequest("GET", "/test.js", nil)
	r.Header.Set("Accept-Encoding", "zstd, gzip")
	w := httptest.NewRecorder()

	f, err := openPrecompressedFile(w, r, "test.js", tfs)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "raw js" {
		t.Errorf("got %q, want %q", got, "raw js")
	}
}

func TestZstFile_Seek(t *testing.T) {
	original := []byte("hello world, this is a test of zstd seeking")
	compressed := compressZstd(t, original)

	tfs := fstest.MapFS{
		"test.zst": &fstest.MapFile{Data: compressed},
	}

	f, err := tfs.Open("test.zst")
	if err != nil {
		t.Fatal(err)
	}
	zf, err := newZSTFile(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zf.Close()

	// SeekEnd with offset 0 should return the total decompressed size.
	n, err := zf.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatalf("Seek(0, SeekEnd) error: %v", err)
	}
	if n != int64(len(original)) {
		t.Errorf("Seek(0, SeekEnd) = %d, want %d", n, len(original))
	}

	// SeekStart with offset 0 should reset to the beginning.
	n, err = zf.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("Seek(0, SeekStart) error: %v", err)
	}
	if n != 0 {
		t.Errorf("Seek(0, SeekStart) = %d, want 0", n)
	}

	// Read all content after reset.
	got, err := io.ReadAll(zf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("after Seek(0, SeekStart) + ReadAll: got %q, want %q", got, original)
	}
}

func TestZstFile_SeekCurrent(t *testing.T) {
	original := []byte("hello world")
	compressed := compressZstd(t, original)

	tfs := fstest.MapFS{
		"test.zst": &fstest.MapFile{Data: compressed},
	}

	f, err := tfs.Open("test.zst")
	if err != nil {
		t.Fatal(err)
	}
	zf, err := newZSTFile(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zf.Close()

	// Skip forward 6 bytes.
	n, err := zf.Seek(6, io.SeekCurrent)
	if err != nil {
		t.Fatalf("Seek(6, SeekCurrent) error: %v", err)
	}
	if n != 6 {
		t.Errorf("Seek(6, SeekCurrent) = %d, want 6", n)
	}

	// Read remaining.
	got, err := io.ReadAll(zf)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "world" {
		t.Errorf("after Seek(6, SeekCurrent) + ReadAll: got %q, want %q", got, "world")
	}
}

func TestZstFile_SeekNegativeCurrentErrors(t *testing.T) {
	original := []byte("hello world")
	compressed := compressZstd(t, original)

	tfs := fstest.MapFS{
		"test.zst": &fstest.MapFile{Data: compressed},
	}

	f, err := tfs.Open("test.zst")
	if err != nil {
		t.Fatal(err)
	}
	zf, err := newZSTFile(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zf.Close()

	_, err = zf.Seek(-1, io.SeekCurrent)
	if err == nil {
		t.Error("Seek(-1, SeekCurrent) should return error")
	}
}

func TestZstFile_SeekEndNonZeroErrors(t *testing.T) {
	original := []byte("hello")
	compressed := compressZstd(t, original)

	tfs := fstest.MapFS{
		"test.zst": &fstest.MapFile{Data: compressed},
	}

	f, err := tfs.Open("test.zst")
	if err != nil {
		t.Fatal(err)
	}
	zf, err := newZSTFile(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zf.Close()

	_, err = zf.Seek(-1, io.SeekEnd)
	if err == nil {
		t.Error("Seek(-1, SeekEnd) should return error")
	}
}

func TestZstFile_ServeContent(t *testing.T) {
	// Integration test: verify that zstFile works correctly with
	// http.ServeContent, which uses Seek to determine content length.
	original := []byte("hello world, served via http.ServeContent")
	compressed := compressZstd(t, original)

	tfs := fstest.MapFS{
		"test.js.zst": &fstest.MapFile{Data: compressed},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := tfs.Open("test.js.zst")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		zf, err := newZSTFile(f)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer zf.Close()
		http.ServeContent(w, r, "test.js", time.Time{}, zf)
	})

	r := httptest.NewRequest("GET", "/test.js", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), original) {
		t.Errorf("body = %q, want %q", w.Body.String(), original)
	}
}

func TestNewZSTFile_CloseOnSuccess(t *testing.T) {
	// Verify that newZSTFile produces a valid zstFile that, when closed,
	// closes the underlying file.
	original := []byte("hello")
	compressed := compressZstd(t, original)

	closed := false
	f := &fakeFile{
		data:    compressed,
		closeFn: func() error { closed = true; return nil },
	}
	zf, err := newZSTFile(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("got %q, want %q", got, original)
	}
	zf.Close()
	if !closed {
		t.Error("underlying file was not closed")
	}
}

// fakeFile implements fs.File with controllable behavior for testing.
type fakeFile struct {
	data    []byte
	offset  int
	closeFn func() error
}

func (f *fakeFile) Read(p []byte) (int, error) {
	if f.offset >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.offset:])
	f.offset += n
	return n, nil
}

func (f *fakeFile) Close() error {
	if f.closeFn != nil {
		return f.closeFn()
	}
	return nil
}

func (f *fakeFile) Stat() (fs.FileInfo, error) {
	return nil, fs.ErrInvalid
}
