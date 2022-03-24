// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package localapi contains the HTTP server handlers for tailscaled's API server.
package localapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"time"

	"inet.af/netaddr"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/version"
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
	// If PermitWrite is true, everything is allowed.
	// It effectively means that the user is root or the admin
	// (operator user).
	PermitWrite bool

	// PermitCert is whether the client is additionally granted
	// cert fetching access.
	PermitCert bool

	b            *ipnlocal.LocalBackend
	logf         logger.Logf
	backendLogID string
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.b == nil {
		http.Error(w, "server has no local backend", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Tailscale-Version", version.Long)
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
	if strings.HasPrefix(r.URL.Path, "/localapi/v0/cert/") {
		h.serveCert(w, r)
		return
	}
	switch r.URL.Path {
	case "/localapi/v0/whois":
		h.serveWhoIs(w, r)
	case "/localapi/v0/goroutines":
		h.serveGoroutines(w, r)
	case "/localapi/v0/profile":
		h.serveProfile(w, r)
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
	case "/localapi/v0/set-dns":
		h.serveSetDNS(w, r)
	case "/localapi/v0/derpmap":
		h.serveDERPMap(w, r)
	case "/localapi/v0/metrics":
		h.serveMetrics(w, r)
	case "/localapi/v0/debug":
		h.serveDebug(w, r)
	case "/localapi/v0/set-expiry-sooner":
		h.serveSetExpirySooner(w, r)
	case "/localapi/v0/dial":
		h.serveDial(w, r)
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
	res := &apitype.WhoIsResponse{
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

func (h *Handler) serveMetrics(w http.ResponseWriter, r *http.Request) {
	// Require write access out of paranoia that the metrics
	// might contain something sensitive.
	if !h.PermitWrite {
		http.Error(w, "metric access denied", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	clientmetric.WritePrometheusExpositionFormat(w)
}

func (h *Handler) serveDebug(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	action := r.FormValue("action")
	var err error
	switch action {
	case "rebind":
		err = h.b.DebugRebind()
	case "restun":
		err = h.b.DebugReSTUN()
	case "":
		err = fmt.Errorf("missing parameter 'action'")
	default:
		err = fmt.Errorf("unknown action %q", action)
	}
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "done\n")
}

// serveProfileFunc is the implementation of Handler.serveProfile, after auth,
// for platforms where we want to link it in.
var serveProfileFunc func(http.ResponseWriter, *http.Request)

func (h *Handler) serveProfile(w http.ResponseWriter, r *http.Request) {
	// Require write access out of paranoia that the profile dump
	// might contain something sensitive.
	if !h.PermitWrite {
		http.Error(w, "profile access denied", http.StatusForbidden)
		return
	}
	if serveProfileFunc == nil {
		http.Error(w, "not implemented on this platform", http.StatusServiceUnavailable)
		return
	}
	serveProfileFunc(w, r)
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
	switch r.Method {
	case "PATCH":
		if !h.PermitWrite {
			http.Error(w, "prefs write access denied", http.StatusForbidden)
			return
		}
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
	case "GET", "HEAD":
		prefs = h.b.Prefs()
	default:
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
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
	suffix := strings.TrimPrefix(r.URL.EscapedPath(), "/localapi/v0/files/")
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

func writeErrorJSON(w http.ResponseWriter, err error) {
	if err == nil {
		err = errors.New("unexpected nil error")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)
	type E struct {
		Error string `json:"error"`
	}
	json.NewEncoder(w).Encode(E{err.Error()})
}

func (h *Handler) serveFileTargets(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "want GET to list targets", 400)
		return
	}
	fts, err := h.b.FileTargets()
	if err != nil {
		writeErrorJSON(w, err)
		return
	}
	makeNonNil(&fts)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fts)
}

// serveFilePut sends a file to another node.
//
// It's sometimes possible for clients to do this themselves, without
// tailscaled, except in the case of tailscaled running in
// userspace-networking ("netstack") mode, in which case tailscaled
// needs to a do a netstack dial out.
//
// Instead, the CLI also goes through tailscaled so it doesn't need to be
// aware of the network mode in use.
//
// macOS/iOS have always used this localapi method to simplify the GUI
// clients.
//
// The Windows client currently (2021-11-30) uses the peerapi (/v0/put/)
// directly, as the Windows GUI always runs in tun mode anyway.
//
// URL format:
//
//    * PUT /localapi/v0/file-put/:stableID/:escaped-filename
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
	stableIDStr, filenameEscaped, ok := strings.Cut(upath, "/")
	if !ok {
		http.Error(w, "bogus URL", 400)
		return
	}
	stableID := tailcfg.StableNodeID(stableIDStr)

	var ft *apitype.FileTarget
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
	rp.Transport = h.b.Dialer().PeerAPITransport()
	rp.ServeHTTP(w, outReq)
}

func (h *Handler) serveSetDNS(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "want POST", 400)
		return
	}
	ctx := r.Context()
	err := h.b.SetDNS(ctx, r.FormValue("name"), r.FormValue("value"))
	if err != nil {
		writeErrorJSON(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct{}{})
}

func (h *Handler) serveDERPMap(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "want GET", 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "\t")
	e.Encode(h.b.DERPMap())
}

// serveSetExpirySooner sets the expiry date on the current machine, specified
// by an `expiry` unix timestamp as POST or query param.
func (h *Handler) serveSetExpirySooner(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var expiryTime time.Time
	if v := r.FormValue("expiry"); v != "" {
		expiryInt, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "can't parse expiry time, expects a unix timestamp", http.StatusBadRequest)
			return
		}
		expiryTime = time.Unix(expiryInt, 0)
	} else {
		http.Error(w, "missing 'expiry' parameter, a unix timestamp", http.StatusBadRequest)
		return
	}
	err := h.b.SetExpirySooner(r.Context(), expiryTime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "done\n")
}

func (h *Handler) serveDial(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	const upgradeProto = "ts-dial"
	if !strings.Contains(r.Header.Get("Connection"), "upgrade") ||
		r.Header.Get("Upgrade") != upgradeProto {
		http.Error(w, "bad ts-dial upgrade", http.StatusBadRequest)
		return
	}
	hostStr, portStr := r.Header.Get("Dial-Host"), r.Header.Get("Dial-Port")
	if hostStr == "" || portStr == "" {
		http.Error(w, "missing Dial-Host or Dial-Port header", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "make request over HTTP/1", http.StatusBadRequest)
		return
	}

	addr := net.JoinHostPort(hostStr, portStr)
	outConn, err := h.b.Dialer().UserDial(r.Context(), "tcp", addr)
	if err != nil {
		http.Error(w, "dial failure: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer outConn.Close()

	w.Header().Set("Upgrade", upgradeProto)
	w.Header().Set("Connection", "upgrade")
	w.WriteHeader(http.StatusSwitchingProtocols)

	reqConn, brw, err := hijacker.Hijack()
	if err != nil {
		h.logf("localapi dial Hijack error: %v", err)
		return
	}
	defer reqConn.Close()
	if err := brw.Flush(); err != nil {
		return
	}
	reqConn = netutil.NewDrainBufConn(reqConn, brw.Reader)

	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(reqConn, outConn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(outConn, reqConn)
		errc <- err
	}()
	<-errc
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
func makeNonNil(ptr any) {
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
