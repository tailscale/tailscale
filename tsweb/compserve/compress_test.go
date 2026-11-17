// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package compserve

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"tailscale.com/util/zstdframe"
)

var timeZero time.Time

// serveCompressed runs inner through CompressWriter with the given
// Accept-Encoding header and returns the recorder.
func serveCompressed(t *testing.T, ae string, inner http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "/", nil)
	if ae != "" {
		r.Header.Set("Accept-Encoding", ae)
	}
	w := httptest.NewRecorder()
	cw := CompressWriter(w, r)
	defer cw.Close()
	inner.ServeHTTP(cw, r)
	return w
}

const testBody = `{"hello": "world, this is a moderately sized json response body intended to exceed the minimum compression size threshold"}`

func TestCompressWriter_Compresses(t *testing.T) {
	w := serveCompressed(t, "zstd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(strings.Repeat(testBody, 20)))
	})
	if got := w.Header().Get("Content-Encoding"); got != "zstd" {
		t.Errorf("Content-Encoding = %q, want %q", got, "zstd")
	}
	if got := w.Code; got != 200 {
		t.Errorf("code = %d, want 200", got)
	}
	decoded, err := zstdframe.AppendDecode(nil, w.Body.Bytes())
	if err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if want := strings.Repeat(testBody, 20); string(decoded) != want {
		t.Errorf("decoded body = %q, want %q", decoded, want)
	}
	// The compressed size is not known up front, so no Content-Length is
	// set; the response is chunked.
	if got := w.Header().Get("Content-Length"); got != "" {
		t.Errorf("Content-Length = %q, want empty", got)
	}
}

func TestCompressWriter_VaryAndWeakETag(t *testing.T) {
	w := serveCompressed(t, "zstd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"strong-etag"`)
		w.Header().Set("Vary", "Origin")
		w.Write([]byte(strings.Repeat(testBody, 20)))
	})
	if got := w.Header().Get("ETag"); got != `W/"strong-etag"` {
		t.Errorf("ETag = %q, want weakened", got)
	}
	if vary := strings.Join(w.Header().Values("Vary"), ", "); vary != "Origin, Accept-Encoding" {
		t.Errorf("Vary = %q, want %q", vary, "Origin, Accept-Encoding")
	}
}

func TestCompressWriter_PreservesWeakETag(t *testing.T) {
	w := serveCompressed(t, "zstd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `W/"already-weak"`)
		w.Write([]byte(strings.Repeat(testBody, 20)))
	})
	if got := w.Header().Get("ETag"); got != `W/"already-weak"` {
		t.Errorf("ETag = %q, want unchanged", got)
	}
	if got := w.Header().Get("Content-Encoding"); got != "zstd" {
		t.Errorf("Content-Encoding = %q, want zstd", got)
	}
}

func TestCompressWriter_NotAccepted(t *testing.T) {
	want := strings.Repeat(testBody, 20)
	w := serveCompressed(t, "br", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(want))
	})
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	if w.Body.String() != want {
		t.Error("body was modified")
	}
}

func TestCompressWriter_SkipsWhenAlreadyEncoded(t *testing.T) {
	want := strings.Repeat(testBody, 20)
	w := serveCompressed(t, "zstd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "zstd") // e.g. precompressed passthrough
		w.Write([]byte(want))
	})
	if w.Body.String() != want {
		t.Error("body was modified")
	}
	if n := len(w.Header().Values("Content-Encoding")); n != 1 {
		t.Errorf("Content-Encoding set %d times, want 1", n)
	}
}

func TestCompressWriter_GzipNotLiveCompressed(t *testing.T) {
	// Gzip has no Compress hook: live compression is zstd-only, so a
	// gzip-accepting client gets identity rather than gzip.
	want := strings.Repeat(testBody, 20)
	w := serveCompressed(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(want))
	})
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	if w.Body.String() != want {
		t.Error("body was modified")
	}
}

func TestCompressWriter_SkipsRange(t *testing.T) {
	want := strings.Repeat(testBody, 20)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "zstd")
	r.Header.Set("Range", "bytes=0-99")
	w := httptest.NewRecorder()
	cw := CompressWriter(w, r)
	defer cw.Close()
	cw.WriteHeader(http.StatusPartialContent)
	cw.Write([]byte(want))
	if w.Body.String() != want {
		t.Error("body was modified")
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
}

func TestCompressWriter_SkipsIncompressibleType(t *testing.T) {
	// Media codec content types are excluded by category, regardless of
	// what the bytes look like.
	want := strings.Repeat(testBody, 20)
	w := serveCompressed(t, "zstd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		w.Write([]byte(want))
	})
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	if w.Body.String() != want {
		t.Error("body was modified")
	}

	// Raw audio is compressed despite the audio/ exclusion.
	w = serveCompressed(t, "zstd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "audio/wav")
		w.Write([]byte(want))
	})
	if got := w.Header().Get("Content-Encoding"); got != "zstd" {
		t.Errorf("Content-Encoding = %q, want zstd", got)
	}
}

func TestCompressWriter_SniffsUnsetContentType(t *testing.T) {
	// No Content-Type: http.DetectContentType sniffs text/plain, which is
	// compressible. The sniffed type must be persisted on the response:
	// net/http would otherwise sniff the compressed bytes and label the
	// response application/octet-stream.
	w := serveCompressed(t, "zstd", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat(testBody, 20)))
	})
	if got := w.Header().Get("Content-Encoding"); got != "zstd" {
		t.Errorf("Content-Encoding = %q, want zstd", got)
	}
	if got := w.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain; charset=utf-8", got)
	}
}

func TestCompressWriter_SkipsNon200(t *testing.T) {
	want := strings.Repeat(testBody, 20)
	w := serveCompressed(t, "zstd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(want))
	})
	if w.Code != http.StatusNotFound {
		t.Errorf("code = %d, want 404", w.Code)
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	if w.Body.String() != want {
		t.Error("body was modified")
	}
}

func TestCompressWriter_FlushStreamsCompressed(t *testing.T) {
	// Streaming handlers that flush mid-body remain compressed; each flush
	// emits the pending compressed bytes to the client.
	want := strings.Repeat(testBody, 20)
	w := serveCompressed(t, "zstd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(want[:100]))
		w.(http.Flusher).Flush()
		w.Write([]byte(want[100:]))
	})
	if got := w.Header().Get("Content-Encoding"); got != "zstd" {
		t.Errorf("Content-Encoding = %q, want zstd", got)
	}
	decoded, err := zstdframe.AppendDecode(nil, w.Body.Bytes())
	if err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if string(decoded) != want {
		t.Error("decoded body mismatch")
	}
}

func TestCompressWriter_NoBody(t *testing.T) {
	// A handler that only sets headers (e.g. a redirect) still produces a
	// well-formed response.
	w := serveCompressed(t, "zstd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(http.StatusFound)
	})
	if w.Code != http.StatusFound {
		t.Errorf("code = %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/elsewhere" {
		t.Errorf("Location = %q", got)
	}
}

func TestCompressContentTypes(t *testing.T) {
	tests := map[string]bool{
		// Default: compressible.
		"text/html; charset=utf-8":        true,
		"application/json":                true,
		"application/json; charset=utf-8": true,
		"application/javascript":          true,
		"application/manifest+json":       true,
		"application/vnd.api+json":        true,
		"application/problem+json":        true,
		"application/xhtml+xml":           true,
		"image/svg+xml":                   true,
		"image/svg+xml; charset=utf-8":    true,
		"application/rss+xml":             true,
		"application/wasm":                true,
		"TEXT/PLAIN":                      true,
		"application/octet-stream":        true, // no-gain guard bails if needed
		"image/png":                       true, // no-gain guard bails if needed
		"image/jpeg; charset=binary":      true, // no-gain guard bails if needed
		"font/woff2":                      true, // no-gain guard bails if needed
		"":                                true,

		// Media codecs are already compressed; excluded by category...
		"audio/mpeg": false,
		"audio/ogg":  false,
		"audio/flac": false,
		"video/mp4":  false,
		"video/webm": false,
		"video/H264": false,
		// ...unless raw, uncompressed media.
		"audio/wav":      true,
		"audio/x-wav":    true,
		"audio/vnd.wave": true,
		"audio/pcm":      true,
		"audio/L16":      true,
		"audio/l24":      true,
		"video/x-y4m":    true,
		"video/x-raw":    true,
		"video/raw":      true,

		// Known compression formats are skipped.
		"application/zip":                         false,
		"application/gzip":                        false,
		"application/x-gzip":                      false,
		"application/x-bzip2":                     false,
		"application/x-xz":                        false,
		"application/zstd":                        false,
		"application/x-7z-compressed":             false,
		"application/x-rar-compressed":            false,
		"application/vnd.rar":                     false,
		"application/x-compress":                  false,
		"application/x-snappy-framed":             false,
		"application/x-lz4":                       false,
		"application/java-archive":                false, // jar: zip
		"application/vnd.android.package-archive": false, // apk: zip
		"application/x-apple-diskimage":           false, // dmg
	}
	for ct, want := range tests {
		if got := compressibleContentType(ct); got != want {
			t.Errorf("compressibleContentType(%q) = %v, want %v", ct, got, want)
		}
	}
}

func TestCompressWriter_ServeContentIntegration(t *testing.T) {
	// An inner http.ServeContent handler (raw, non-precompressed file)
	// should be compressed, with its Content-Length replaced and ETag
	// weakened.
	original := []byte(strings.Repeat(testBody, 20))
	tfs := fstest.MapFS{"data.json": &fstest.MapFile{Data: original}}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := tfs.Open("data.json")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		// fs.File does not claim to implement Seeker, but MapFS files do.
		http.ServeContent(w, r, "data.json", timeZero, f.(io.ReadSeeker))
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "zstd")
	w := httptest.NewRecorder()
	cw := CompressWriter(w, r)
	handler.ServeHTTP(cw, r)
	// Close before asserting: it is what emits the buffered response.
	cw.Close()

	if got := w.Header().Get("Content-Encoding"); got != "zstd" {
		t.Errorf("Content-Encoding = %q, want zstd", got)
	}
	// http.ServeContent sets Content-Length for the raw file; streaming
	// compression must have removed it rather than lie about the size.
	if got := w.Header().Get("Content-Length"); got != "" {
		t.Errorf("Content-Length = %q, want empty", got)
	}
	decoded, err := zstdframe.AppendDecode(nil, w.Body.Bytes())
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Error("decoded body mismatch")
	}
}

func TestCompressWriter_DoubleClose(t *testing.T) {
	// A second Close must not return the pooled encoder to the pool twice;
	// two concurrent requests would then share one encoder.
	body := strings.Repeat(testBody, 20)
	w := serveCompressed(t, "zstd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	})
	// serveCompressed already Closed once; a second Close is a no-op.
	decoded, err := zstdframe.AppendDecode(nil, w.Body.Bytes())
	if err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if string(decoded) != body {
		t.Error("decoded body mismatch")
	}

	// The pool is not poisoned: the next request compresses correctly.
	w2 := serveCompressed(t, "zstd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	})
	decoded2, err := zstdframe.AppendDecode(nil, w2.Body.Bytes())
	if err != nil {
		t.Fatalf("decoding second response: %v", err)
	}
	if string(decoded2) != body {
		t.Error("second decoded body mismatch")
	}
}

// hijackableRecorder wraps a ResponseRecorder, recording whether the
// handler used the raw connection.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

func TestCompressWriter_HijackBeforeWrite(t *testing.T) {
	// A handler that hijacks before producing a response gets the raw
	// connection: no compression is attached, no headers are sent, and the
	// wrapper adds no io overhead on the hijacked path.
	hr := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "zstd")
	cw := CompressWriter(hr, r)

	conn, rw, err := cw.Hijack()
	if err != nil || conn != nil || rw != nil {
		t.Fatalf("Hijack() = %v, %v, %v", conn, rw, err)
	}
	// The wrapper's passthrough path must not forward a header-only
	// response for a hijacked request.
	if hr.Code != 200 {
		t.Errorf("WriteHeader forwarded to underlying writer (code %d)", hr.Code)
	}
	if got := hr.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	if !hr.hijacked {
		t.Error("underlying writer was not hijacked")
	}
	// Post-hijack writes are rejected, not forwarded.
	if n, err := cw.Write([]byte("x")); err == nil || n != 0 {
		t.Errorf("post-hijack Write = (%d, %v), want (0, error)", n, err)
	}
	cw.Close()
}

func TestCompressWriter_HijackAfterCompression(t *testing.T) {
	// Hijacking mid-compressed-stream finishes the frame (pooled encoder
	// returned) and hands over the connection.
	original := strings.Repeat(testBody, 20)
	hr := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "zstd")
	cw := CompressWriter(hr, r)
	if _, err := cw.Write([]byte(original)); err != nil {
		t.Fatal(err)
	}
	if got := hr.Header().Get("Content-Encoding"); got != "zstd" {
		t.Fatalf("Content-Encoding = %q, want zstd", got)
	}
	if _, _, err := cw.Hijack(); err != nil {
		t.Fatal(err)
	}
	if got := wBody(hr); !bytes.Equal(got, nil) && len(got) == 0 {
		t.Error("compressed body was dropped")
	}
	decoded, err := zstdframe.AppendDecode(nil, wBody(hr))
	if err != nil {
		t.Fatalf("decoding streamed body (frame not finished?): %v", err)
	}
	if string(decoded) != original {
		t.Error("decoded body mismatch")
	}
	// Close after hijack must not double-close the pooled encoder.
	cw.Close()
}

// unwrapOnlyWriter is middleware supporting neither Hijack nor Flush,
// only Unwrap, like other middleware that may sit below compressWriter.
type unwrapOnlyWriter struct {
	http.ResponseWriter
}

func (u unwrapOnlyWriter) Unwrap() http.ResponseWriter { return u.ResponseWriter }

func TestCompressWriter_HijackThroughUnwrap(t *testing.T) {
	// compressWriter -> unwrapOnlyWriter -> hijackableRecorder: the
	// hijacker is two layers down. Hijack must walk the Unwrap chain
	// (via http.ResponseController) and reach it.
	hr := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "zstd")
	cw := CompressWriter(unwrapOnlyWriter{hr}, r)
	if _, _, err := cw.Hijack(); err != nil {
		t.Fatalf("Hijack through middleware: %v", err)
	}
	if !hr.hijacked {
		t.Error("deepest writer was not hijacked")
	}
	cw.Close()
}

func TestCompressWriter_HijackNotSupported(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	cw := CompressWriter(w, r)
	if _, _, err := cw.Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Errorf("Hijack on non-hijackable writer = %v, want http.ErrNotSupported", err)
	}
	cw.Close()
}

func wBody(h *hijackableRecorder) []byte {
	return h.Body.Bytes()
}

func TestCompressWriter_SkipsUpgradesAndUnusualMethods(t *testing.T) {
	// Protocol upgrades and non-standard methods get identity responses:
	// their bodies are not normal response payloads (tunnels, WebDAV
	// extensions, etc.).
	want := strings.Repeat(testBody, 20)
	for _, tt := range []struct {
		name    string
		method  string
		upgrade bool
	}{
		{name: "upgrade", method: "GET", upgrade: true},
		{name: "propfind", method: "PROPFIND"},
	} {
		r := httptest.NewRequest(tt.method, "/", nil)
		r.Header.Set("Accept-Encoding", "zstd")
		if tt.upgrade {
			r.Header.Set("Upgrade", "websocket")
		}
		w := httptest.NewRecorder()
		cw := CompressWriter(w, r)
		cw.WriteHeader(200)
		cw.Write([]byte(want))
		cw.Close()
		if got := w.Header().Get("Content-Encoding"); got != "" {
			t.Errorf("%s: Content-Encoding = %q, want empty", tt.name, got)
		}
		if w.Body.String() != want {
			t.Errorf("%s: body was modified", tt.name)
		}
	}
}

func TestCompressWriter_HeadRequestPassthrough(t *testing.T) {
	// HEAD responses have no body; they pass through untouched.
	r := httptest.NewRequest("HEAD", "/", nil)
	r.Header.Set("Accept-Encoding", "zstd")
	w := httptest.NewRecorder()
	cw := CompressWriter(w, r)
	defer cw.Close()
	cw.WriteHeader(200)
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
}
