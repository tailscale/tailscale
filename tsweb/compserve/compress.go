// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package compserve

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"

	"tailscale.com/util/httpm"
)

// CompressWriter wraps w so that its response body is transparently
// compressed, incrementally as the handler writes it, with the first
// encoding from encodings (default: [DefaultEncodings]) that offers live
// compression and that r accepts.
//
// The caller must call Close exactly once after the wrapped handler
// returns, to finish any compressed stream:
//
//	cw := compserve.CompressWriter(w, r)
//	defer cw.Close()
//	handler.ServeHTTP(cw, r)
func CompressWriter(w http.ResponseWriter, r *http.Request, encodings ...Encoding) *compressWriter {
	if len(encodings) == 0 {
		encodings = DefaultEncodings
	}
	var encs []Encoding
	for _, e := range encodings {
		if e.Compress != nil {
			encs = append(encs, e)
		}
	}
	// Compression applies to plain responses of standard body-carrying
	// requests: not HEAD (no body), not CONNECT (tunnel), not protocol
	// upgrades, not range requests (range semantics apply to the
	// uncompressed representation).
	safe := (r.Method == httpm.GET || r.Method == httpm.POST) &&
		r.Header.Get("Upgrade") == "" &&
		r.Header.Get("Range") == ""
	return &compressWriter{
		ResponseWriter: w,
		encs:           encs,
		ae:             r.Header.Get("Accept-Encoding"),
		safe:           safe,
	}
}

// compressWriter is a ResponseWriter wrapper that compresses the response
// body of dynamic handlers. See [CompressWriter].
//
// The body is compressed as it is written, with no buffering. The compress
// decision is made once from the response headers, sniffing the first
// write if the handler sets no Content-Type.
//
// Compressed responses are chunked: the compressed size is not known up
// front, so a handler-set Content-Length is removed. zstd framing may add
// a few bytes to incompressible data.
//
// Responses pass through uncompressed when they already have a
// Content-Encoding, on non-GET/POST requests (HEAD, CONNECT, upgrades,
// range requests), non-200 statuses, or incompressible content types (see
// compressibleContentType).
//
// Every response gets Vary: Accept-Encoding. Strong ETags are weakened:
// validators are representation-specific.
type compressWriter struct {
	http.ResponseWriter
	encs []Encoding

	ae   string // Accept-Encoding header of the request
	safe bool   // request is safe to compress the response of

	code     int  // stashed status code; 0 until the first WriteHeader or Write
	decided  bool // whether the compress-or-passthrough decision was made
	compress bool // decision outcome: stream through the compressor
	hijacked bool // connection hijacked; the wrapper is out of the path
	cw       io.WriteCloser
}

// Unwrap exposes the wrapped ResponseWriter to http.ResponseController for
// deadline support; Flush and Hijack stay handled by the wrapper.
func (c *compressWriter) Unwrap() http.ResponseWriter {
	return c.ResponseWriter
}

// Hijack switches the connection out from under the wrapper: after a
// successful hijack the connection is raw, no compression applies, and
// wrapper writes fail. Handlers reach it via http.NewResponseController or
// a direct type assertion, so hijacked paths carry no io overhead from
// this wrapper. ResponseController.Hijack unwraps through further
// middleware below this wrapper.
func (c *compressWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if !c.decided {
		// No response was produced; the handler will speak for itself on
		// the hijacked connection. Do not attach a compressor or send
		// response headers.
		c.decided = true
	} else if c.compress {
		// Compressed bytes were already streamed; finish the frame and
		// return the encoder to its pool before the connection leaves our
		// control.
		err := c.cw.Close()
		c.compress, c.cw = false, nil
		if err != nil {
			return nil, nil, err
		}
	}
	c.hijacked = true
	return http.NewResponseController(c.ResponseWriter).Hijack()
}

// WriteHeader stashes the status code, deciding early if the response is
// already disqualified from compression. See [CompressWriter].
func (c *compressWriter) WriteHeader(code int) {
	if c.hijacked {
		return // the handler owns the connection
	}
	if c.code != 0 {
		return // ignore superfluous calls, like net/http does
	}
	c.code = code
	if !c.mayCompress() {
		c.decide(nil)
	}
}

// mayCompress reports whether the stashed response could still be
// compressed based on the request and the handler's headers alone.
func (c *compressWriter) mayCompress() bool {
	if len(c.encs) == 0 || c.code != http.StatusOK || !c.safe {
		return false
	}
	// Never double-encode (e.g. precompressed variants served by
	// [ServeFile] through this wrapper).
	return c.Header().Get("Content-Encoding") == ""
}

// Write passes the body through the streaming compressor or the wrapped
// writer, deciding on the first write. See [CompressWriter].
func (c *compressWriter) Write(p []byte) (int, error) {
	if c.hijacked {
		return 0, http.ErrHijacked
	}
	if !c.decided {
		c.decide(p)
	}
	if c.compress {
		return c.cw.Write(p)
	}
	return c.ResponseWriter.Write(p)
}

// Flush flushes buffered compressed data and the underlying writer. See
// [CompressWriter].
func (c *compressWriter) Flush() {
	if !c.decided {
		c.decide(nil)
	}
	if c.compress {
		type flusher interface{ Flush() }
		if f, ok := c.cw.(flusher); ok {
			f.Flush()
		}
	}
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Close finishes any compressed stream and must be called exactly once
// after the wrapped handler returns. See [CompressWriter].
func (c *compressWriter) Close() error {
	if c.hijacked {
		return nil // the connection left our control in Hijack
	}
	if !c.decided {
		c.decide(nil)
	}
	if c.compress {
		return c.cw.Close()
	}
	return nil
}

// decide makes the compress-or-passthrough decision from the request, the
// response headers, and (when no Content-Type is set) the first body
// bytes. It forwards the response headers.
func (c *compressWriter) decide(first []byte) {
	c.decided = true
	if c.code == 0 {
		c.code = http.StatusOK
	}
	ct := c.Header().Get("Content-Type")
	sniffed := false
	if ct == "" && first != nil {
		// Mirror net/http's sniffing of the first bytes.
		ct = http.DetectContentType(first)
		sniffed = true
	}
	if !c.mayCompress() || ct == "" || !compressibleContentType(ct) {
		c.commitPassthrough()
		return
	}
	enc := negotiate(c.ae, c.encs)
	if enc == nil {
		c.commitPassthrough()
		return
	}
	cw, err := enc.Compress(c.ResponseWriter)
	if err != nil {
		c.commitPassthrough()
		return
	}

	h := c.Header()
	if sniffed {
		// net/http would otherwise sniff the compressed bytes and label
		// the response application/octet-stream.
		h.Set("Content-Type", ct)
	}
	// The handler's Content-Length describes the uncompressed
	// representation; the compressed length is unknown, so the response is
	// chunked.
	h.Del("Content-Length")
	h.Set("Content-Encoding", enc.Token)
	// Strong validators must be representation-specific.
	if etag := h.Get("ETag"); etag != "" && !strings.HasPrefix(etag, "W/") {
		h.Set("ETag", "W/"+etag)
	}
	addVary(h, "Accept-Encoding")

	c.cw = cw
	c.compress = true
	c.ResponseWriter.WriteHeader(c.code)
}

// commitPassthrough forwards the stashed status to the wrapped writer;
// subsequent writes stream through directly.
func (c *compressWriter) commitPassthrough() {
	if c.code == 0 {
		c.code = http.StatusOK
	}
	addVary(c.Header(), "Accept-Encoding")
	c.ResponseWriter.WriteHeader(c.code)
}

// compressibleContentType reports whether the given content type is worth
// live compression. Most types are assumed compressible: only content that
// is already compressed by construction is excluded (media codecs, archive
// formats), except raw media types that are not, listed below.
// +json/+xml suffix types are always compressed.
func compressibleContentType(ct string) bool {
	ct = strings.ToLower(ct)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml") {
		return true
	}
	switch {
	case strings.HasPrefix(ct, "audio/"):
		return rawAudioContentType(ct)
	case strings.HasPrefix(ct, "video/"):
		return rawVideoContentType(ct)
	}
	switch ct {
	case "application/zip",
		"application/gzip",
		"application/x-gzip",
		"application/x-bzip2",
		"application/x-xz",
		"application/zstd",
		"application/x-zstd",
		"application/x-7z-compressed",
		"application/x-rar-compressed",
		"application/vnd.rar",
		"application/x-compress",
		"application/x-snappy-framed",
		"application/x-lz4",
		// Archive formats that are zip or other compressed containers.
		"application/java-archive",                // jar: zip
		"application/vnd.android.package-archive", // apk: zip
		"application/x-apple-diskimage":           // dmg: compressed
		return false
	}
	return true
}

// rawAudioContentType reports whether ct is an uncompressed audio format
// worth compressing despite audio/ being excluded by default: audio content
// is almost always compressed by its codec, but raw PCM is not.
func rawAudioContentType(ct string) bool {
	switch ct {
	case "audio/wav", "audio/wave", "audio/x-wav", "audio/vnd.wave", // WAV: PCM
		"audio/pcm",
		"audio/l16", "audio/l24": // raw linear PCM, RFC 2586
		return true
	}
	return false
}

// rawVideoContentType reports whether ct is an uncompressed video format
// worth compressing despite video/ being excluded by default: video content
// is almost always compressed by its codec, but raw frame data is not.
func rawVideoContentType(ct string) bool {
	switch ct {
	case "video/raw", "video/x-raw", "video/x-raw-yuv",
		"video/x-y4m": // YUV4MPEG2
		return true
	}
	return false
}

// addVary adds token to the response's Vary header, preserving any values
// already set by the handler.
func addVary(h http.Header, token string) {
	for _, vary := range h.Values("Vary") {
		for _, t := range strings.Split(vary, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return
			}
		}
	}
	h.Add("Vary", token)
}
