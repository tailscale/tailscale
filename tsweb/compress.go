// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/andybalholm/brotli"
)

type compressingHandler struct {
	h http.Handler
}

func (h compressingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !AcceptsEncoding(r, "br") && !AcceptsEncoding(r, "gzip") {
		h.h.ServeHTTP(w, r)
		return
	}

	cw := &compressingResponseWriter{
		ResponseWriter: w,
		r:              r,
	}
	defer cw.Close()

	h.h.ServeHTTP(cw, r)
}

type compressingResponseWriter struct {
	http.ResponseWriter
	r *http.Request
	w io.Writer
}

// WriteHeader implements http.ResponseWriter.
func (w *compressingResponseWriter) WriteHeader(code int) {
	// If a handler has already set a Content-Encoding, such as for precompressed
	// assets, skip the compressing writer. This must be recorded before
	// WriteHeader call as "The header map is cleared when 2xx-5xx headers are
	// sent".
	if w.w == nil {
		if w.ResponseWriter.Header().Get("Content-Encoding") == "" {
			w.w = brotli.HTTPCompressor(w.ResponseWriter, w.r)
		} else {
			w.w = w.ResponseWriter
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write implements http.ResponseWriter.
func (w *compressingResponseWriter) Write(b []byte) (int, error) {
	if w.w == nil {
		w.WriteHeader(http.StatusOK)
	}
	return w.w.Write(b)
}

// Close implements io.Closer.
func (w *compressingResponseWriter) Close() error {
	if w.w == nil {
		return nil
	}
	if c, ok := w.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// flusher is an interface that is implemented by gzip.Writer and other writers
// that differs from http.Flusher in that it may return an error.
type flusher interface {
	Flush() error
}

// Flush implements http.Flusher.
func (w *compressingResponseWriter) Flush() {
	// the writer may implement either of the flusher interfaces, so try both.
	if f, ok := w.w.(flusher); ok {
		_ = f.Flush()
	}
	if f, ok := w.w.(http.Flusher); ok {
		f.Flush()
	}

	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker.
func (w *compressingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("ResponseWriter is not a Hijacker")
}
