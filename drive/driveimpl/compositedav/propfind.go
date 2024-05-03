// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositedav

import (
	"bytes"
	"fmt"
	"math"
	"net/http"
	"regexp"

	"tailscale.com/drive/driveimpl/shared"
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

		status, result := h.StatCache.getOr(r.URL.Path, depth, func() (int, []byte) {
			// Use a buffering ResponseWriter so that we can manipulate the result.
			// The only thing we use from the original ResponseWriter is Header().
			bw := &bufferingResponseWriter{ResponseWriter: w}

			mpl := h.maxPathLength(r)
			h.delegate(mpl, pathComponents[mpl-1:], bw, r)

			// Fixup paths to add the requested path as a prefix.
			pathPrefix := shared.Join(pathComponents[0:mpl]...)
			b := hrefRegex.ReplaceAll(bw.buf.Bytes(), []byte(fmt.Sprintf("<D:href>%s/$1</D:href>", pathPrefix)))

			return bw.status, b
		})

		w.Header().Del("Content-Length")
		w.WriteHeader(status)
		if result != nil {
			w.Write(result)
		}
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
