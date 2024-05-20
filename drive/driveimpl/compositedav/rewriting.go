// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositedav

import (
	"bytes"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"

	"tailscale.com/drive/driveimpl/shared"
)

var (
	responseHrefRegex = regexp.MustCompile(`(?s)(<D:(response|lockroot)>)<D:href>/?([^<]*)/?</D:href>`)
	ifHrefRegex       = regexp.MustCompile(`^<(https?://[^/]+)?([^>]+)>`)
)

func (h *Handler) handlePROPFIND(w http.ResponseWriter, r *http.Request, pathComponents []string, mpl int) {
	if shouldDelegateToChild(r, pathComponents, mpl) {
		// Delegate to a Child.
		depth := getDepth(r)

		status, result := h.StatCache.getOr(r.URL.Path, depth, func() (int, []byte) {
			return h.delegateRewriting(w, r, pathComponents, mpl)
		})

		respondRewritten(w, status, result)
		return
	}

	h.handle(w, r)
}

func (h *Handler) handleLOCK(w http.ResponseWriter, r *http.Request, pathComponents []string, mpl int) {
	if shouldDelegateToChild(r, pathComponents, mpl) {
		// Delegate to a Child.
		status, result := h.delegateRewriting(w, r, pathComponents, mpl)
		respondRewritten(w, status, result)
		return
	}

	http.Error(w, "locking of top level directories is not allowed", http.StatusMethodNotAllowed)
}

// shouldDelegateToChild decides whether a request should be delegated to a
// child filesystem, as opposed to being handled by this filesystem. It checks
// the depth of the requested path, and if it's deeper than the portion of the
// tree that's handled by the parent, returns true.
func shouldDelegateToChild(r *http.Request, pathComponents []string, mpl int) bool {
	return !shared.IsRoot(r.URL.Path) && len(pathComponents)+getDepth(r) > mpl
}

func (h *Handler) delegateRewriting(w http.ResponseWriter, r *http.Request, pathComponents []string, mpl int) (int, []byte) {
	// Use a buffering ResponseWriter so that we can manipulate the result.
	// The only thing we use from the original ResponseWriter is Header().
	bw := &bufferingResponseWriter{ResponseWriter: w}

	h.delegate(mpl, pathComponents[mpl-1:], bw, r)

	// Fixup paths to add the requested path as a prefix, escaped for inclusion in XML.
	pp := shared.EscapeForXML(shared.Join(pathComponents[0:mpl]...))
	b := responseHrefRegex.ReplaceAll(bw.buf.Bytes(), []byte(fmt.Sprintf("$1<D:href>%s/$3</D:href>", pp)))
	return bw.status, b
}

func respondRewritten(w http.ResponseWriter, status int, result []byte) {
	w.Header().Del("Content-Length")
	w.WriteHeader(status)
	if result != nil {
		w.Write(result)
	}
}

func getDepth(r *http.Request) int {
	switch r.Header.Get("Depth") {
	case "0":
		return 0
	case "1":
		return 1
	case "infinity":
		return math.MaxInt16 // a really large number, but not infinity (avoids wrapping when we do arithmetic with this)
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

// rewriteIfHeader rewrites URLs in the If header by removing the host and the
// portion of the path that corresponds to this composite filesystem. This way,
// when we delegate requests to child filesystems, the If header will reference
// a path that makes sense on those filesystems.
//
// See http://www.webdav.org/specs/rfc4918.html#HEADER_If
func rewriteIfHeader(r *http.Request, pathComponents []string, mpl int) {
	ih := r.Header.Get("If")
	if ih == "" {
		return
	}
	matches := ifHrefRegex.FindStringSubmatch(ih)
	if len(matches) == 3 {
		pp := shared.JoinEscaped(pathComponents[0:mpl]...)
		p := strings.Replace(shared.JoinEscaped(pathComponents...), pp, "", 1)
		nih := ifHrefRegex.ReplaceAllString(ih, fmt.Sprintf("<%s>", p))
		r.Header.Set("If", nih)
	}
}
