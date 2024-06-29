// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package compositedav provides an http.Handler that composes multiple WebDAV
// services into a single WebDAV service that presents each of them as its own
// folder.
package compositedav

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/tailscale/xnet/webdav"
	"tailscale.com/drive/driveimpl/dirfs"
	"tailscale.com/drive/driveimpl/shared"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
)

// Child is a child folder of this compositedav.
type Child struct {
	*dirfs.Child

	// BaseURL returns the base URL of the WebDAV service to which we'll proxy
	// requests for this Child. We will append the filename from the original
	// URL to this.
	BaseURL func() (string, error)

	// Transport (if specified) is the http transport to use when communicating
	// with this Child's WebDAV service.
	Transport http.RoundTripper

	rp       *httputil.ReverseProxy
	initOnce sync.Once
}

// CloseIdleConnections forcibly closes any idle connections on this Child's
// reverse proxy.
func (c *Child) CloseIdleConnections() {
	tr, ok := c.Transport.(*http.Transport)
	if ok {
		tr.CloseIdleConnections()
	}
}

func (c *Child) init() {
	c.initOnce.Do(func() {
		c.rp = &httputil.ReverseProxy{
			Transport: c.Transport,
			Rewrite:   func(r *httputil.ProxyRequest) {},
		}
	})
}

// Handler implements http.Handler by using a dirfs.FS for showing a virtual
// read-only folder that represents the Child WebDAV services as sub-folders
// and proxying all requests for resources on the children to those children
// via httputil.ReverseProxy instances.
type Handler struct {
	// Logf specifies a logging function to use.
	Logf logger.Logf

	// Clock, if specified, determines the current time. If not specified, we
	// default to time.Now().
	Clock tstime.Clock

	// StatCache is an optional cache for PROPFIND results.
	StatCache *StatCache

	// childrenMu guards the fields below. Note that we do read the contents of
	// children after releasing the read lock, which we can do because we never
	// modify children but only ever replace it in SetChildren.
	childrenMu sync.RWMutex
	children   []*Child
	staticRoot string
}

var cacheInvalidatingMethods = map[string]bool{
	"PUT":       true,
	"POST":      true,
	"COPY":      true,
	"MKCOL":     true,
	"MOVE":      true,
	"PROPPATCH": true,
	"DELETE":    true,
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pathComponents := shared.CleanAndSplit(r.URL.Path)
	mpl := h.maxPathLength(r)

	switch r.Method {
	case "PROPFIND":
		h.handlePROPFIND(w, r, pathComponents, mpl)
		return
	case "LOCK":
		h.handleLOCK(w, r, pathComponents, mpl)
		return
	}

	_, shouldInvalidate := cacheInvalidatingMethods[r.Method]
	if shouldInvalidate {
		// If the user is performing a modification (e.g. PUT, MKDIR, etc.),
		// we need to invalidate the StatCache to make sure we're not knowingly
		// showing stale stats.
		// TODO(oxtoacart): maybe only invalidate specific paths
		h.StatCache.invalidate()
	}

	if len(pathComponents) >= mpl {
		h.delegate(mpl, pathComponents[mpl-1:], w, r)
		return
	}
	h.handle(w, r)
}

// handle handles the request locally using our dirfs.FS.
func (h *Handler) handle(w http.ResponseWriter, r *http.Request) {
	h.childrenMu.RLock()
	clk, kids, root := h.Clock, h.children, h.staticRoot
	h.childrenMu.RUnlock()

	children := make([]*dirfs.Child, 0, len(kids))
	for _, child := range kids {
		children = append(children, child.Child)
	}
	wh := &webdav.Handler{
		LockSystem: webdav.NewMemLS(),
		FileSystem: &dirfs.FS{
			Clock:      clk,
			Children:   children,
			StaticRoot: root,
		},
	}

	wh.ServeHTTP(w, r)
}

// delegate sends the request to the Child WebDAV server.
func (h *Handler) delegate(mpl int, pathComponents []string, w http.ResponseWriter, r *http.Request) {
	rewriteIfHeader(r, pathComponents, mpl)

	dest := r.Header.Get("Destination")
	if dest != "" {
		// Rewrite destination header
		destURL, err := url.Parse(dest)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		destinationComponents := shared.CleanAndSplit(destURL.Path)
		if len(destinationComponents) < mpl || destinationComponents[mpl-1] != pathComponents[0] {
			http.Error(w, "Destination across shares is not supported", http.StatusBadRequest)
			return
		}
		updatedDest := shared.JoinEscaped(destinationComponents[mpl:]...)
		r.Header.Set("Destination", updatedDest)
	}

	childName := pathComponents[0]
	child := h.GetChild(childName)
	if child == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	baseURL, err := child.BaseURL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		h.logf("warning: parse base URL %s failed: %s", baseURL, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u.Path = path.Join(u.Path, shared.Join(pathComponents[1:]...))
	r.URL = u
	r.Host = u.Host
	child.rp.ServeHTTP(w, r)
}

// SetChildren replaces the entire existing set of children with the given
// ones. If staticRoot is given, the children will appear with a subfolder
// bearing named <staticRoot>.
func (h *Handler) SetChildren(staticRoot string, children ...*Child) {
	for _, child := range children {
		child.init()
	}

	slices.SortFunc(children, func(a, b *Child) int {
		return strings.Compare(a.Name, b.Name)
	})

	h.childrenMu.Lock()
	oldChildren := children
	h.children = children
	h.staticRoot = staticRoot
	h.childrenMu.Unlock()

	for _, child := range oldChildren {
		child.CloseIdleConnections()
	}
}

// GetChild gets the Child identified by name, or nil if no matching child
// found.
func (h *Handler) GetChild(name string) *Child {
	h.childrenMu.RLock()
	defer h.childrenMu.RUnlock()

	_, child := h.findChildLocked(name)
	return child
}

// Close closes this Handler,including closing all idle connections on children
// and stopping the StatCache (if caching is enabled).
func (h *Handler) Close() {
	h.childrenMu.RLock()
	oldChildren := h.children
	h.children = nil
	h.childrenMu.RUnlock()

	for _, child := range oldChildren {
		child.CloseIdleConnections()
	}

	if h.StatCache != nil {
		h.StatCache.stop()
	}
}

func (h *Handler) findChildLocked(name string) (int, *Child) {
	var child *Child
	i, found := slices.BinarySearchFunc(h.children, name, func(child *Child, name string) int {
		return strings.Compare(child.Name, name)
	})
	if found {
		return i, h.children[i]
	}
	return i, child
}

func (h *Handler) logf(format string, args ...any) {
	if h.Logf != nil {
		h.Logf(format, args...)
		return
	}

	log.Printf(format, args...)
}

// maxPathLength calculates the maximum length of a path that can be handled by
// this handler without delegating to a Child. It's always at least 1, and if
// staticRoot is configured, it's 2.
func (h *Handler) maxPathLength(r *http.Request) int {
	h.childrenMu.RLock()
	defer h.childrenMu.RUnlock()

	if h.staticRoot != "" {
		return 2
	}
	return 1
}
