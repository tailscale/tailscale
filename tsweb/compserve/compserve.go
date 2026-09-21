// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package compserve serves static files with content negotiation for
// precompressed variants, and provides live compression for dynamic
// responses.
//
// An [Encoding] describes a content coding's wire token and where its
// precompressed variants live.
package compserve

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Encoding describes a single content coding (e.g. zstd) that this package
// can negotiate and serve.
type Encoding struct {
	// Token is the Content-Encoding token for this coding, e.g. "zstd".
	// Comparison against Accept-Encoding is case-insensitive.
	Token string

	// Ext is the file name extension (including the leading dot) of
	// precompressed variants as produced by util/precompress, e.g. ".zst".
	Ext string

	// Decompress, if non-nil, wraps f and yields its decompressed content,
	// taking ownership of f: the returned ReadCloser's Close closes f, and
	// if Decompress returns an error it must have closed f already.
	//
	// When Decompress is set, a precompressed variant can also be served to
	// clients that do not accept Token by decompressing it on the fly, so a
	// file system shipping only precompressed variants can still serve
	// every client. If nil, the variant is only served passthrough to
	// clients that accept Token.
	Decompress func(f fs.File) (io.ReadCloser, error)

	// Compress, if non-nil, wraps w in a streaming compressor used by
	// [CompressWriter] for live (non-precompressed) response compression:
	// everything written to the returned WriteCloser is compressed and
	// forwarded to w, and its Close finishes the stream and releases any
	// pooled resources. Implementations should use a fast compression
	// mode: live compression runs per request and must not add meaningful
	// latency. If nil, the encoding is not offered for live compression.
	Compress func(w io.Writer) (io.WriteCloser, error)
}

// DefaultEncodings is the set of encodings used when Options does not
// specify any: zstd, then gzip for compatibility with file systems built
// before zstd-only asset generation. Ties prefer the earlier encoding.
var DefaultEncodings = []Encoding{Zstd, Gzip}

// Options configures ServeFile.
type Options struct {
	// Encodings lists the precompressed variants available in the file
	// system, in preference order. The zero value selects
	// [DefaultEncodings].
	Encodings []Encoding
}

// ServeFile serves the file at path from fsys to w, negotiating a
// precompressed variant when the client accepts one and the variant exists.
// Clients that do not accept any offered encoding are served the raw file;
// if the raw file is absent (e.g. a file system shipping only
// precompressed variants), a variant with a Decompress hook is served
// decompressed instead.
//
// ServeFile sets Vary: Accept-Encoding on every response and serves the
// content via http.ServeContent with the file's modification time (for
// embedded file systems, wrap fsys in [tailscale.com/tsweb/vcstime.FS] to
// supply one). Callers may set additional headers (e.g. Cache-Control)
// before calling. If ServeFile returns an error it has not written a
// response body, so callers may adjust headers and retry with a different
// path. If no representation of the file exists, the returned error wraps
// fs.ErrNotExist.
func ServeFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, path string, opts Options) error {
	encodings := opts.Encodings
	if encodings == nil {
		encodings = DefaultEncodings
	}
	if !fs.ValidPath(path) {
		// An invalid name can never exist. Report not-found rather than
		// the fs.ErrInvalid that validating file systems such as fs.Sub
		// return, so callers can fall back to another path.
		return &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	// The served representation (an encoded variant or identity) is
	// selected from Accept-Encoding, so caches must treat the response as
	// varying even when the negotiated representation is identity.
	addVary(w.Header(), "Accept-Encoding")

	// Prefer serving an accepted variant passthrough: no server CPU cost.
	if enc := negotiate(r.Header.Get("Accept-Encoding"), encodings); enc != nil {
		if f, err := fsys.Open(path + enc.Ext); err == nil {
			rs, ok := f.(io.ReadSeeker)
			if !ok {
				// Fall through to the raw file; it may still be servable.
				f.Close()
			} else {
				w.Header().Set("Content-Encoding", enc.Token)
				return serveContent(w, r, path, fileModTime(f), rs)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	// Serve the raw file if it exists: it is identical to what transcoding
	// a variant would produce, without the CPU cost.
	f, err := fsys.Open(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err == nil {
		rs, ok := f.(io.ReadSeeker)
		if !ok {
			f.Close()
			return fmt.Errorf("%s is not seekable", path)
		}
		return serveContent(w, r, path, fileModTime(f), rs)
	}

	// The raw file does not exist: transcode a precompressed variant to
	// identity for clients that do not accept it.
	for _, e := range encodings {
		if e.Decompress == nil {
			continue
		}
		f, err := fsys.Open(path + e.Ext)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return err
		}
		modTime := fileModTime(f)
		tf := &transcodedFile{fsys: fsys, path: path + e.Ext, dec: e.Decompress}
		if err := tf.start(f); err != nil {
			return err
		}
		return serveContent(w, r, path, modTime, tf)
	}
	return &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}

// fileModTime reports f's modification time, or the zero time (which
// disables conditional requests in http.ServeContent) if f does not stat.
func fileModTime(f fs.File) time.Time {
	fi, err := f.Stat()
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// serveContent serves rs via http.ServeContent, closing it if it is an
// io.Closer.
func serveContent(w http.ResponseWriter, r *http.Request, name string, modTime time.Time, rs io.ReadSeeker) error {
	http.ServeContent(w, r, name, modTime, rs)
	if c, ok := rs.(io.Closer); ok {
		// The response body has been written; a close error is not
		// actionable.
		c.Close()
	}
	return nil
}

// negotiate returns the encoding from offered that the given
// Accept-Encoding header value accepts with the highest quality value, or
// nil if it accepts none of them. Ties prefer the earlier entry in offered.
func negotiate(ae string, offered []Encoding) *Encoding {
	if ae == "" {
		return nil
	}
	exact, wildcard, hasWildcard := parseAcceptEncoding(ae)
	var best *Encoding
	bestQ := 0.0
	for i := range offered {
		enc := &offered[i]
		q, ok := exact[strings.ToLower(enc.Token)]
		if !ok && hasWildcard {
			q, ok = wildcard, true
		}
		// A quality of zero explicitly rejects the coding, and equal
		// qualities prefer the earlier entry in offered.
		if ok && q > bestQ {
			best, bestQ = enc, q
		}
	}
	return best
}

// parseAcceptEncoding parses an Accept-Encoding header value into the
// quality values of the explicitly named (lowercased) coding tokens and of
// the "*" wildcard, if present. Quality values default to 1 per RFC 9110,
// and a malformed quality value rejects the coding.
func parseAcceptEncoding(h string) (exact map[string]float64, wildcard float64, hasWildcard bool) {
	exact = make(map[string]float64)
	for _, part := range strings.Split(h, ",") {
		token, params, _ := strings.Cut(part, ";")
		token = strings.ToLower(strings.TrimSpace(token))
		if token == "" {
			continue
		}
		q := 1.0
		for _, p := range strings.FieldsFunc(params, func(r rune) bool { return r == ';' }) {
			name, value, _ := strings.Cut(strings.TrimSpace(p), "=")
			if !strings.EqualFold(name, "q") {
				continue
			}
			if v, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
				q = v
			} else {
				q = 0
			}
			break
		}
		if token == "*" {
			wildcard, hasWildcard = q, true
			continue
		}
		exact[token] = q
	}
	return exact, wildcard, hasWildcard
}

// transcodedFile serves the decompressed content of a precompressed file to
// clients that do not accept its encoding. It implements io.ReadSeeker so
// that it can be used with http.ServeContent; seeking re-opens the
// underlying file and decompresses from the start, so it is only suitable
// for small files where the double decompression cost is acceptable.
type transcodedFile struct {
	fsys fs.FS
	path string                                 // path of the compressed file in fsys
	dec  func(f fs.File) (io.ReadCloser, error) // decompressor for that file
	rc   io.ReadCloser                          // current decompressed stream
	pos  int64                                  // current position in the decompressed stream
}

// start replaces the decompressed stream with one reading f (whose
// ownership is taken) from its start.
func (t *transcodedFile) start(f fs.File) error {
	rc, err := t.dec(f)
	if err != nil {
		return err
	}
	t.closeStream()
	t.rc, t.pos = rc, 0
	return nil
}

// restart replaces the decompressed stream with a fresh one reading the
// underlying file from its start.
func (t *transcodedFile) restart() error {
	f, err := t.fsys.Open(t.path)
	if err != nil {
		return err
	}
	return t.start(f)
}

func (t *transcodedFile) closeStream() {
	if t.rc != nil {
		t.rc.Close()
		t.rc = nil
	}
}

func (t *transcodedFile) Read(p []byte) (int, error) {
	if t.rc == nil {
		return 0, fs.ErrClosed
	}
	n, err := t.rc.Read(p)
	t.pos += int64(n)
	return n, err
}

func (t *transcodedFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		if err := t.restart(); err != nil {
			return 0, err
		}
		_, err := io.CopyN(io.Discard, t, offset)
		return t.pos, err
	case io.SeekCurrent:
		if offset < 0 {
			return 0, fmt.Errorf("negative offset for SeekCurrent: %w", fs.ErrInvalid)
		}
		_, err := io.CopyN(io.Discard, t, offset)
		return t.pos, err
	case io.SeekEnd:
		if offset != 0 {
			return 0, fmt.Errorf("non-zero offset for SeekEnd: %w", fs.ErrInvalid)
		}
		_, err := io.Copy(io.Discard, t)
		return t.pos, err
	}
	return 0, fs.ErrInvalid
}

func (t *transcodedFile) Close() error {
	t.closeStream()
	return nil
}
