// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package localapi contains the HTTP server handlers for tailscaled's API server.
package localapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"inet.af/netaddr"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func NewHandler(b *ipnlocal.LocalBackend, logf logger.Logf, logID string) *Handler {
	return &Handler{b: b, logf: logf, backendLogID: logID}
}

type Handler struct {
	// RequiredPassword, if non-empty, forces all HTTP
	// requests to have HTTP basic auth with this password.
	// It's used by the sandboxed macOS sameuserproof GUI auth mechanism.
	RequiredPassword string

	// PermitRead is whether read-only HTTP handlers are allowed.
	PermitRead bool

	// PermitWrite is whether mutating HTTP handlers are allowed.
	PermitWrite bool

	b            *ipnlocal.LocalBackend
	logf         logger.Logf
	backendLogID string
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.b == nil {
		http.Error(w, "server has no local backend", http.StatusInternalServerError)
		return
	}
	if h.RequiredPassword != "" {
		_, pass, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		if pass != h.RequiredPassword {
			http.Error(w, "bad password", http.StatusForbidden)
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, "/localapi/v0/files/") {
		h.serveFiles(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/localapi/v0/file-put/") {
		h.serveFilePut(w, r)
		return
	}
	switch r.URL.Path {
	case "/localapi/v0/whois":
		h.serveWhoIs(w, r)
	case "/localapi/v0/goroutines":
		h.serveGoroutines(w, r)
	case "/localapi/v0/status":
		h.serveStatus(w, r)
	case "/localapi/v0/logout":
		h.serveLogout(w, r)
	case "/localapi/v0/prefs":
		h.servePrefs(w, r)
	case "/localapi/v0/check-ip-forwarding":
		h.serveCheckIPForwarding(w, r)
	case "/localapi/v0/bugreport":
		h.serveBugReport(w, r)
	case "/localapi/v0/file-targets":
		h.serveFileTargets(w, r)
	case "/":
		io.WriteString(w, "tailscaled\n")
	default:
		http.Error(w, "404 not found", 404)
	}
}

func (h *Handler) serveBugReport(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "bugreport access denied", http.StatusForbidden)
		return
	}

	logMarker := fmt.Sprintf("BUG-%v-%v-%v", h.backendLogID, time.Now().UTC().Format("20060102150405Z"), randHex(8))
	h.logf("user bugreport: %s", logMarker)
	if note := r.FormValue("note"); len(note) > 0 {
		h.logf("user bugreport note: %s", note)
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, logMarker)
}

func (h *Handler) serveWhoIs(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "whois access denied", http.StatusForbidden)
		return
	}
	b := h.b
	var ipp netaddr.IPPort
	if v := r.FormValue("addr"); v != "" {
		var err error
		ipp, err = netaddr.ParseIPPort(v)
		if err != nil {
			http.Error(w, "invalid 'addr' parameter", 400)
			return
		}
	} else {
		http.Error(w, "missing 'addr' parameter", 400)
		return
	}
	n, u, ok := b.WhoIs(ipp)
	if !ok {
		http.Error(w, "no match for IP:port", 404)
		return
	}
	res := &tailcfg.WhoIsResponse{
		Node:        n,
		UserProfile: &u,
	}
	j, err := json.MarshalIndent(res, "", "\t")
	if err != nil {
		http.Error(w, "JSON encoding error", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func (h *Handler) serveGoroutines(w http.ResponseWriter, r *http.Request) {
	// Require write access out of paranoia that the goroutine dump
	// (at least its arguments) might contain something sensitive.
	if !h.PermitWrite {
		http.Error(w, "goroutine dump access denied", http.StatusForbidden)
		return
	}
	buf := make([]byte, 2<<20)
	buf = buf[:runtime.Stack(buf, true)]
	w.Header().Set("Content-Type", "text/plain")
	w.Write(buf)
}

func (h *Handler) serveCheckIPForwarding(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "IP forwarding check access denied", http.StatusForbidden)
		return
	}
	var warning string
	if err := h.b.CheckIPForwarding(); err != nil {
		warning = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Warning string
	}{
		Warning: warning,
	})
}

func (h *Handler) serveStatus(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "status access denied", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var st *ipnstate.Status
	if defBool(r.FormValue("peers"), true) {
		st = h.b.Status()
	} else {
		st = h.b.StatusWithoutPeers()
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "\t")
	e.Encode(st)
}

func (h *Handler) serveLogout(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "logout access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "want POST", 400)
		return
	}
	err := h.b.LogoutSync(r.Context())
	if err == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Error(w, err.Error(), 500)
}

func (h *Handler) servePrefs(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "prefs access denied", http.StatusForbidden)
		return
	}
	var prefs *ipn.Prefs
	if r.Method == "POST" {
		mp := new(ipn.MaskedPrefs)
		if err := json.NewDecoder(r.Body).Decode(mp); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var err error
		prefs, err = h.b.EditPrefs(mp)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	} else {
		prefs = h.b.Prefs()
	}
	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "\t")
	e.Encode(prefs)
}

func (h *Handler) serveFiles(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "file access denied", http.StatusForbidden)
		return
	}
	suffix := strings.TrimPrefix(r.URL.Path, "/localapi/v0/files/")
	if suffix == "" {
		if r.Method != "GET" {
			http.Error(w, "want GET to list files", 400)
			return
		}
		wfs, err := h.b.WaitingFiles()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(wfs)
		return
	}
	name, err := url.PathUnescape(suffix)
	if err != nil {
		http.Error(w, "bad filename", 400)
		return
	}
	if r.Method == "DELETE" {
		if err := h.b.DeleteFile(name); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rc, size, err := h.b.OpenFile(name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Length", fmt.Sprint(size))
	io.Copy(w, rc)
}

func (h *Handler) serveFileTargets(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "file access denied", http.StatusForbidden)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "want GET to list targets", 400)
		return
	}
	fts, err := h.b.FileTargets()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	makeNonNil(&fts)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fts)
}

func (h *Handler) serveFilePut(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "file access denied", http.StatusForbidden)
		return
	}
	if r.Method != "PUT" {
		http.Error(w, "want PUT to put file", 400)
		return
	}
	fts, err := h.b.FileTargets()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	upath := strings.TrimPrefix(r.URL.EscapedPath(), "/localapi/v0/file-put/")
	slash := strings.Index(upath, "/")
	if slash == -1 {
		http.Error(w, "bogus URL", 400)
		return
	}
	stableID, filenameEscaped := tailcfg.StableNodeID(upath[:slash]), upath[slash+1:]

	var ft *ipnlocal.FileTarget
	for _, x := range fts {
		if x.Node.StableID == stableID {
			ft = x
			break
		}
	}
	if ft == nil {
		http.Error(w, "node not found", 404)
		return
	}
	dstURL, err := url.Parse(ft.PeerAPIURL)
	if err != nil {
		http.Error(w, "bogus peer URL", 500)
		return
	}
	outReq, err := http.NewRequestWithContext(r.Context(), "PUT", "http://peer/v0/put/"+filenameEscaped, r.Body)
	if err != nil {
		http.Error(w, "bogus outreq", 500)
		return
	}
	outReq.ContentLength = r.ContentLength

	rp := httputil.NewSingleHostReverseProxy(dstURL)
	rp.Transport = getDialPeerTransport(h.b)
	rp.ServeHTTP(w, outReq)
}

var dialPeerTransportOnce struct {
	sync.Once
	v *http.Transport
}

func getDialPeerTransport(b *ipnlocal.LocalBackend) *http.Transport {
	dialPeerTransportOnce.Do(func() {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Dial = nil //lint:ignore SA1019 yes I know I'm setting it to nil defensively
		dialer := net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   b.PeerDialControlFunc(),
		}
		t.DialContext = dialer.DialContext
		dialPeerTransportOnce.v = t
	})
	return dialPeerTransportOnce.v
}

func defBool(a string, def bool) bool {
	if a == "" {
		return def
	}
	v, err := strconv.ParseBool(a)
	if err != nil {
		return def
	}
	return v
}

// makeNonNil takes a pointer to a Go data structure
// (currently only a slice or a map) and makes sure it's non-nil for
// JSON serialization. (In particular, JavaScript clients usually want
// the field to be defined after they decode the JSON.)
func makeNonNil(ptr interface{}) {
	if ptr == nil {
		panic("nil interface")
	}
	rv := reflect.ValueOf(ptr)
	if rv.Kind() != reflect.Ptr {
		panic(fmt.Sprintf("kind %v, not Ptr", rv.Kind()))
	}
	if rv.Pointer() == 0 {
		panic("nil pointer")
	}
	rv = rv.Elem()
	if rv.Pointer() != 0 {
		return
	}
	switch rv.Type().Kind() {
	case reflect.Slice:
		rv.Set(reflect.MakeSlice(rv.Type(), 0, 0))
	case reflect.Map:
		rv.Set(reflect.MakeMap(rv.Type()))
	}
}
