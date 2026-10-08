// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package compserve

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"mime"
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

func TestNegotiate(t *testing.T) {
	tests := []struct {
		ae   string // Accept-Encoding header value
		want string // Token of expected encoding, "" for identity
	}{
		{ae: "", want: ""},
		{ae: "zstd", want: "zstd"},
		{ae: "zstd, gzip", want: "zstd"},
		{ae: "gzip, zstd", want: "zstd"}, // preference order wins ties
		{ae: "gzip", want: "gzip"},
		{ae: "br", want: ""},
		{ae: "identity", want: ""},            // identity is never an offered encoding
		{ae: "identity;q=1, *;q=0", want: ""}, // explicitly accepting only identity
		{ae: "foo, gzip", want: "gzip"},
		{ae: "foo, gzip ", want: "gzip"},
		{ae: "ZSTD", want: "zstd"}, // case-insensitive token match
		{ae: "zstd;q=0", want: ""},
		{ae: "zstd;q=0, gzip", want: "gzip"},
		{ae: "zstd;q=0.5, gzip;q=0.4", want: "zstd"},
		{ae: "gzip;q=0.9, zstd;q=0.4", want: "gzip"},
		{ae: "zstd;q=1.2, foo", want: "zstd"}, // lenient: valid float
		{ae: "zstd;q=abc", want: ""},          // malformed q rejects
		{ae: "zstd;Q=0", want: ""},            // parameter names are case-insensitive
		{ae: "*", want: "zstd"},
		{ae: "*;q=0.1", want: "zstd"},
		{ae: "*;q=0", want: ""},
		{ae: "zstd;q=1, *;q=0", want: "zstd"},
		{ae: "gzip;q=1, *;q=0", want: "gzip"}, // explicit entries beat the wildcard
		{ae: "br;q=1, *;q=0", want: ""},       // nothing offered is accepted
	}
	for _, tt := range tests {
		got := negotiate(tt.ae, DefaultEncodings)
		var gotToken string
		if got != nil {
			gotToken = got.Token
		}
		if gotToken != tt.want {
			t.Errorf("negotiate(%q) = %q, want %q", tt.ae, gotToken, tt.want)
		}
	}
}

func mapFS(files map[string][]byte) fstest.MapFS {
	tfs := fstest.MapFS{}
	for name, data := range files {
		tfs[name] = &fstest.MapFile{Data: data}
	}
	return tfs
}

func serveFileRequest(t *testing.T, fsys fs.FS, path, ae string, opts Options) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	r := httptest.NewRequest("GET", "/"+path, nil)
	if ae != "" {
		r.Header.Set("Accept-Encoding", ae)
	}
	w := httptest.NewRecorder()
	err := ServeFile(w, r, fsys, path, opts)
	return w, errors.Is(err, fs.ErrNotExist)
}

func TestServeFile_ZstdPassthrough(t *testing.T) {
	original := []byte("hello world")
	compressed := compressZstd(t, original)
	tfs := mapFS(map[string][]byte{"test.js.zst": compressed})

	w, notExist := serveFileRequest(t, tfs, "test.js", "zstd", Options{})
	if notExist {
		t.Fatal("unexpected fs.ErrNotExist")
	}
	if got := w.Header().Get("Content-Encoding"); got != "zstd" {
		t.Errorf("Content-Encoding = %q, want %q", got, "zstd")
	}
	// http.ServeContent derives Content-Type from the (original) name via
	// mime.TypeByExtension; the exact value is platform-dependent (Windows
	// consults the registry).
	if got, want := w.Header().Get("Content-Type"), mime.TypeByExtension(".js"); want != "" && got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	} else if want == "" && got == "" {
		t.Error("Content-Type not set")
	}
	if !bytes.Equal(w.Body.Bytes(), compressed) {
		t.Errorf("body = decompressed data, want raw compressed passthrough")
	}
}

func TestServeFile_TranscodeWithoutRawFile(t *testing.T) {
	// A file system may ship only precompressed variants (as build-webclient
	// does); clients that do not accept the encoding must still be served.
	original := []byte("hello world")
	compressed := compressZstd(t, original)
	tfs := mapFS(map[string][]byte{"test.js.zst": compressed})

	// Client accepts only gzip: the zstd variant is served decompressed, as
	// identity.
	w, notExist := serveFileRequest(t, tfs, "test.js", "gzip", Options{})
	if notExist {
		t.Fatal("unexpected fs.ErrNotExist")
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty (transparent decompression)", got)
	}
	if !bytes.Equal(w.Body.Bytes(), original) {
		t.Errorf("body = %q, want %q", w.Body.Bytes(), original)
	}

	// So must clients that accept no encoding at all.
	w, notExist = serveFileRequest(t, tfs, "test.js", "", Options{})
	if notExist {
		t.Fatal("unexpected fs.ErrNotExist")
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	if !bytes.Equal(w.Body.Bytes(), original) {
		t.Errorf("body = %q, want %q", w.Body.Bytes(), original)
	}
}

func TestServeFile_RawPreferredOverTranscode(t *testing.T) {
	// When the raw file exists, a client that accepts no encoding is served
	// it directly; transcoding a variant to identical bytes would only
	// waste CPU.
	original := []byte("raw js")
	compressed := compressZstd(t, []byte("compressed js"))
	tfs := mapFS(map[string][]byte{
		"test.js":     original,
		"test.js.zst": compressed,
	})

	w, notExist := serveFileRequest(t, tfs, "test.js", "", Options{})
	if notExist {
		t.Fatal("unexpected fs.ErrNotExist")
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	if !bytes.Equal(w.Body.Bytes(), original) {
		t.Errorf("body = %q, want %q", w.Body.Bytes(), original)
	}
}

func TestServeFile_PrefersNegotiatedVariant(t *testing.T) {
	// A client accepting zstd gets the zstd variant even when it also
	// accepts encodings that are not served (e.g. gzip).
	tfs := mapFS(map[string][]byte{
		"test.js.zst": compressZstd(t, []byte("zstd content")),
	})

	w, notExist := serveFileRequest(t, tfs, "test.js", "zstd, gzip", Options{})
	if notExist {
		t.Fatal("unexpected fs.ErrNotExist")
	}
	if got := w.Header().Get("Content-Encoding"); got != "zstd" {
		t.Errorf("Content-Encoding = %q, want %q", got, "zstd")
	}
}

func TestServeFile_ZstdRejectedServesIdentity(t *testing.T) {
	// A client that explicitly rejects zstd is served identity content,
	// transcoded from the only available representation.
	original := []byte("identity content")
	tfs := mapFS(map[string][]byte{
		"test.js.zst": compressZstd(t, original),
	})

	w, notExist := serveFileRequest(t, tfs, "test.js", "gzip;q=1, zstd;q=0", Options{})
	if notExist {
		t.Fatal("unexpected fs.ErrNotExist")
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	if !bytes.Equal(w.Body.Bytes(), original) {
		t.Errorf("body = %q, want %q", w.Body.Bytes(), original)
	}
}

func TestServeFile_GzipPassthrough(t *testing.T) {
	// Transitional: pre-zstd file systems ship .gz variants; gzip-accepting
	// clients get them passthrough.
	original := []byte("hello world")
	tfs := mapFS(map[string][]byte{"test.js.gz": original})

	w, notExist := serveFileRequest(t, tfs, "test.js", "gzip", Options{})
	if notExist {
		t.Fatal("unexpected fs.ErrNotExist")
	}
	if got := w.Header().Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want %q", got, "gzip")
	}
	if !bytes.Equal(w.Body.Bytes(), original) {
		t.Errorf("body = %q, want %q", w.Body.Bytes(), original)
	}
}

func TestServeFile_TranscodeGzip(t *testing.T) {
	// Transitional: a gz-only file system (the pre-zstd
	// web-client-prebuilt shape) serves identity content to clients that
	// do not accept gzip.
	original := []byte("hello world")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(original); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	tfs := mapFS(map[string][]byte{"test.js.gz": buf.Bytes()})

	w, notExist := serveFileRequest(t, tfs, "test.js", "", Options{})
	if notExist {
		t.Fatal("unexpected fs.ErrNotExist")
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	if !bytes.Equal(w.Body.Bytes(), original) {
		t.Errorf("body = %q, want %q", w.Body.Bytes(), original)
	}
}

func TestServeFile_RawFallback(t *testing.T) {
	tfs := mapFS(map[string][]byte{"test.js": []byte("raw js")})

	w, notExist := serveFileRequest(t, tfs, "test.js", "zstd, gzip", Options{})
	if notExist {
		t.Fatal("unexpected fs.ErrNotExist")
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	if !bytes.Equal(w.Body.Bytes(), []byte("raw js")) {
		t.Errorf("body = %q, want %q", w.Body.Bytes(), "raw js")
	}
}

func TestServeFile_Missing(t *testing.T) {
	tfs := mapFS(map[string][]byte{})

	w, notExist := serveFileRequest(t, tfs, "missing.js", "zstd", Options{})
	if !notExist {
		t.Error("expected fs.ErrNotExist for missing file")
	}
	if w.Body.Len() != 0 {
		t.Errorf("body = %q, want no response written", w.Body.String())
	}
}

func TestServeFile_InvalidPath(t *testing.T) {
	// Wrap a map FS in fs.Sub with a non-root directory: the subFS
	// rejects invalid names with fs.ErrInvalid, like embedded-asset
	// file systems do (prebuilt.FS is fs.Sub(embed.FS, "build")).
	sub, err := fs.Sub(mapFS(map[string][]byte{"build/index.html": []byte("html")}), "build")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", "../escape"} {
		w, notExist := serveFileRequest(t, sub, path, "zstd", Options{})
		if !notExist {
			t.Errorf("path %q: expected fs.ErrNotExist", path)
		}
		if w.Body.Len() != 0 {
			t.Errorf("path %q: body = %q, want no response written", path, w.Body.String())
		}
	}
}

// modTimeFS is an fs.FS whose files report a fixed modification time, like
// vcstime-wrapped file systems do for embedded files.
type modTimeFS struct {
	fsys fs.FS
	mod  time.Time
}

func (m modTimeFS) Open(name string) (fs.File, error) {
	f, err := m.fsys.Open(name)
	if err != nil {
		return nil, err
	}
	return modTimeFile{f, m.mod}, nil
}

type modTimeFile struct {
	f   fs.File
	mod time.Time
}

func (m modTimeFile) Read(p []byte) (int, error) { return m.f.Read(p) }
func (m modTimeFile) Seek(off int64, w int) (int64, error) {
	return m.f.(io.Seeker).Seek(off, w)
}
func (m modTimeFile) Close() error { return m.f.Close() }

func (m modTimeFile) Stat() (fs.FileInfo, error) {
	fi, err := m.f.Stat()
	if err != nil {
		return nil, err
	}
	return modTimeInfo{fi: fi, mod: m.mod}, nil
}

type modTimeInfo struct {
	fi  fs.FileInfo
	mod time.Time
}

func (m modTimeInfo) Name() string       { return m.fi.Name() }
func (m modTimeInfo) Size() int64        { return m.fi.Size() }
func (m modTimeInfo) Mode() fs.FileMode  { return m.fi.Mode() }
func (m modTimeInfo) IsDir() bool        { return m.fi.IsDir() }
func (m modTimeInfo) Sys() any           { return m.fi.Sys() }
func (m modTimeInfo) ModTime() time.Time { return m.mod }

func TestServeFile_ModTimeFromFileStat(t *testing.T) {
	// The served mod time comes from the file's Stat, so wrapping an
	// embedded FS in vcstime.FS yields working conditional requests.
	mod := time.Unix(1700000000, 0)
	tfs := modTimeFS{fsys: mapFS(map[string][]byte{"test.js": []byte("raw js")}), mod: mod}

	w, notExist := serveFileRequest(t, tfs, "test.js", "zstd", Options{})
	if notExist {
		t.Fatal("unexpected fs.ErrNotExist")
	}
	if got, want := w.Header().Get("Last-Modified"), mod.UTC().Format(http.TimeFormat); got != want {
		t.Errorf("Last-Modified = %q, want %q", got, want)
	}

	// And conditional requests get 304s.
	r := httptest.NewRequest("GET", "/test.js", nil)
	r.Header.Set("If-Modified-Since", mod.UTC().Format(http.TimeFormat))
	w2 := httptest.NewRecorder()
	if err := ServeFile(w2, r, tfs, "test.js", Options{}); err != nil {
		t.Fatal(err)
	}
	if w2.Code != http.StatusNotModified {
		t.Errorf("code = %d, want 304", w2.Code)
	}
}

func TestServeFile_VaryAlwaysSet(t *testing.T) {
	// Vary must be set even when the negotiated representation is identity,
	// and on responses to clients sending no Accept-Encoding at all.
	for _, ae := range []string{"", "zstd", "identity"} {
		tfs := mapFS(map[string][]byte{"test.js": []byte("raw js")})
		w, notExist := serveFileRequest(t, tfs, "test.js", ae, Options{})
		if notExist {
			t.Fatal("unexpected fs.ErrNotExist")
		}
		if got := w.Header().Get("Vary"); got != "Accept-Encoding" {
			t.Errorf("Accept-Encoding %q: Vary = %q, want Accept-Encoding", ae, got)
		}
	}
}

func TestTranscodedFile_Seek(t *testing.T) {
	original := []byte("hello world, this is a test of transcoded seeking")
	compressed := compressZstd(t, original)
	tfs := mapFS(map[string][]byte{"test.zst": compressed})

	tf := &transcodedFile{fsys: tfs, path: "test.zst", dec: Zstd.Decompress}
	if err := tf.restart(); err != nil {
		t.Fatal(err)
	}
	defer tf.Close()

	// SeekEnd with offset 0 should return the total decompressed size.
	n, err := tf.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatalf("Seek(0, SeekEnd) error: %v", err)
	}
	if n != int64(len(original)) {
		t.Errorf("Seek(0, SeekEnd) = %d, want %d", n, len(original))
	}

	// SeekStart with offset 0 should reset to the beginning.
	n, err = tf.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("Seek(0, SeekStart) error: %v", err)
	}
	if n != 0 {
		t.Errorf("Seek(0, SeekStart) = %d, want 0", n)
	}

	// Read all content after reset.
	got, err := io.ReadAll(tf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("after Seek(0, SeekStart) + ReadAll: got %q, want %q", got, original)
	}
}

func TestTranscodedFile_SeekCurrentFromNonZeroPosition(t *testing.T) {
	// Regression test: SeekCurrent must return the absolute stream
	// position, not the number of bytes skipped. From a non-zero position
	// these differ.
	original := []byte("hello world")
	compressed := compressZstd(t, original)
	tfs := mapFS(map[string][]byte{"test.zst": compressed})

	tf := &transcodedFile{fsys: tfs, path: "test.zst", dec: Zstd.Decompress}
	if err := tf.restart(); err != nil {
		t.Fatal(err)
	}
	defer tf.Close()

	// Read 5 bytes to advance the position, then seek relative.
	buf := make([]byte, 5)
	if _, err := io.ReadFull(tf, buf); err != nil {
		t.Fatal(err)
	}
	n, err := tf.Seek(3, io.SeekCurrent)
	if err != nil {
		t.Fatalf("Seek(3, SeekCurrent) error: %v", err)
	}
	if n != 8 {
		t.Errorf("Seek(3, SeekCurrent) = %d, want 8", n)
	}

	// Read remaining.
	got, err := io.ReadAll(tf)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "rld" {
		t.Errorf("after read+Seek(3, SeekCurrent)+ReadAll: got %q, want %q", got, "rld")
	}
}

func TestTranscodedFile_SeekNegativeCurrentErrors(t *testing.T) {
	tfs := mapFS(map[string][]byte{"test.zst": compressZstd(t, []byte("hello"))})
	tf := &transcodedFile{fsys: tfs, path: "test.zst", dec: Zstd.Decompress}
	if err := tf.restart(); err != nil {
		t.Fatal(err)
	}
	defer tf.Close()

	if _, err := tf.Seek(-1, io.SeekCurrent); err == nil {
		t.Error("Seek(-1, SeekCurrent) should return error")
	}
}

func TestTranscodedFile_SeekEndNonZeroErrors(t *testing.T) {
	tfs := mapFS(map[string][]byte{"test.zst": compressZstd(t, []byte("hello"))})
	tf := &transcodedFile{fsys: tfs, path: "test.zst", dec: Zstd.Decompress}
	if err := tf.restart(); err != nil {
		t.Fatal(err)
	}
	defer tf.Close()

	if _, err := tf.Seek(-1, io.SeekEnd); err == nil {
		t.Error("Seek(-1, SeekEnd) should return error")
	}
}

func TestTranscodedFile_ServeContent(t *testing.T) {
	// Integration test: verify that transcodedFile works correctly with
	// http.ServeContent, which uses Seek to determine content length and
	// then serves the content through the same reader.
	original := []byte("hello world, served via http.ServeContent")
	compressed := compressZstd(t, original)
	tfs := mapFS(map[string][]byte{"test.js.zst": compressed})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tf := &transcodedFile{fsys: tfs, path: "test.js.zst", dec: Zstd.Decompress}
		if err := tf.restart(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer tf.Close()
		http.ServeContent(w, r, "test.js", time.Time{}, tf)
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

func TestTranscodedFile_ReusedDecoders(t *testing.T) {
	// Regression test: pooled zstd decoders must be reusable after a
	// previous request fully drained (hit EOF on) and returned them.
	original := []byte("hello world")
	compressed := compressZstd(t, original)
	tfs := mapFS(map[string][]byte{"test.zst": compressed})

	for i := 0; i < 3; i++ {
		tf := &transcodedFile{fsys: tfs, path: "test.zst", dec: Zstd.Decompress}
		if err := tf.restart(); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(tf)
		if err != nil {
			t.Fatal(err)
		}
		tf.Close()
		if !bytes.Equal(got, original) {
			t.Errorf("round %d: got %q, want %q", i, got, original)
		}
	}
}
