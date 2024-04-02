// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositedav

import (
	"bytes"
	"fmt"
	"math"
	"net/http"
	"regexp"

	"tailscale.com/tailfs/tailfsimpl/shared"
)

var (
	hrefRegex = regexp.MustCompile(`(?s)<D:href>/?([^<]*)/?</D:href>`)
)

func (h *Handler) handlePROPFIND(w http.ResponseWriter, r *http.Request) {
	pathComponents := shared.CleanAndSplit(r.URL.Path)
	mpl := h.maxPathLength(r)
	if !shared.IsRoot(r.URL.Path) && len(pathComponents)+getDepth(r) > mpl {
		// Delegate to a Child.
		depth := getDepth(r)

		cached := h.StatCache.get(r.URL.Path, depth)
		if cached != nil {
			w.Header().Del("Content-Length")
			w.WriteHeader(http.StatusMultiStatus)
			w.Write(cached)
			return
		}

		// Use a buffering ResponseWriter so that we can manipulate the result.
		// The only thing we use from the original ResponseWriter is Header().
		bw := &bufferingResponseWriter{ResponseWriter: w}

		mpl := h.maxPathLength(r)
		h.delegate(pathComponents[mpl-1:], bw, r)

		// Fixup paths to add the requested path as a prefix.
		pathPrefix := shared.Join(pathComponents[0:mpl]...)
		b := hrefRegex.ReplaceAll(bw.buf.Bytes(), []byte(fmt.Sprintf("<D:href>%s/$1</D:href>", pathPrefix)))

		if h.StatCache != nil && bw.status == http.StatusMultiStatus && b != nil {
			h.StatCache.set(r.URL.Path, depth, b)
		}

		w.Header().Del("Content-Length")
		w.WriteHeader(bw.status)
		w.Write(b)

		return
	}

	h.handle(w, r)
}

func getDepth(r *http.Request) int {
	switch r.Header.Get("Depth") {
	case "0":
		return 0
	case "1":
		return 1
	case "infinity":
		return math.MaxInt
	}
	return 0
}

type bufferingResponseWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (bw *bufferingResponseWriter) WriteHeader(statusCode int) {
	bw.status = statusCode
}

func (bw *bufferingResponseWriter) Write(p []byte) (int, error) {
	return bw.buf.Write(p)
}
