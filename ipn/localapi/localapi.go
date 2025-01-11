// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package localapi contains the HTTP server handlers for tailscaled's API server.
package localapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/ptr"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/httpm"
	"tailscale.com/version"
)

type localAPIHandler func(*Handler, http.ResponseWriter, *http.Request)

// handler is the set of LocalAPI handlers, keyed by the part of the
// Request.URL.Path after "/localapi/v0/". If the key ends with a trailing slash
// then it's a prefix match.
var handler = map[string]localAPIHandler{
	// The prefix match handlers end with a slash:
	"profiles/": (*Handler).serveProfiles,

	// The other /localapi/v0/NAME handlers are exact matches and contain only NAME
	// without a trailing slash:
	"check-prefs":        (*Handler).serveCheckPrefs,
	"disconnect-control": (*Handler).disconnectControl,
	"goroutines":         (*Handler).serveGoroutines,
	"login-interactive":  (*Handler).serveLoginInteractive,
	"logout":             (*Handler).serveLogout,
	"metrics":            (*Handler).serveMetrics,
	"prefs":              (*Handler).servePrefs,
	"query-feature":      (*Handler).serveQueryFeature,
	"reload-config":      (*Handler).reloadConfig,
	"reset-auth":         (*Handler).serveResetAuth,
	"start":              (*Handler).serveStart,
	"status":             (*Handler).serveStatus,
	"watch-ipn-bus":      (*Handler).serveWatchIPNBus,
	"whois":              (*Handler).serveWhoIs,
}

var (
	// The clientmetrics package is stateful, but we want to expose a simple
	// imperative API to local clients, so we need to keep track of
	// clientmetric.Metric instances that we've created for them. These need to
	// be globals because we end up creating many Handler instances for the
	// lifetime of a client.
	metricsMu sync.Mutex
	metrics   = map[string]*clientmetric.Metric{}
)

// NewHandler creates a new LocalAPI HTTP handler. All parameters except netMon
// are required (if non-nil it's used to do faster interface lookups).
func NewHandler(b *ipnlocal.LocalBackend, logf logger.Logf, logID logid.PublicID) *Handler {
	return &Handler{b: b, logf: logf, backendLogID: logID, clock: tstime.StdClock{}}
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

	// Actor is the identity of the client connected to the Handler.
	Actor ipnauth.Actor

	b            *ipnlocal.LocalBackend
	logf         logger.Logf
	backendLogID logid.PublicID
	clock        tstime.Clock
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.b == nil {
		http.Error(w, "server has no local backend", http.StatusInternalServerError)
		return
	}
	if r.Referer() != "" || r.Header.Get("Origin") != "" || !h.validHost(r.Host) {
		metricInvalidRequests.Add(1)
		http.Error(w, "invalid localapi request", http.StatusForbidden)
		return
	}
	w.Header().Set("Tailscale-Version", version.Long())
	w.Header().Set("Tailscale-Cap", strconv.Itoa(int(tailcfg.CurrentCapabilityVersion)))
	w.Header().Set("Content-Security-Policy", `default-src 'none'; frame-ancestors 'none'; script-src 'none'; script-src-elem 'none'; script-src-attr 'none'`)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if h.RequiredPassword != "" {
		_, pass, ok := r.BasicAuth()
		if !ok {
			metricInvalidRequests.Add(1)
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		if pass != h.RequiredPassword {
			metricInvalidRequests.Add(1)
			http.Error(w, "bad password", http.StatusForbidden)
			return
		}
	}
	if fn, ok := handlerForPath(r.URL.Path); ok {
		fn(h, w, r)
	} else {
		http.NotFound(w, r)
	}
}

// validLocalHostForTesting allows loopback handlers without RequiredPassword for testing.
var validLocalHostForTesting = false

// validHost reports whether h is a valid Host header value for a LocalAPI request.
func (h *Handler) validHost(hostname string) bool {
	// The client code sends a hostname of "local-tailscaled.sock".
	switch hostname {
	case "", apitype.LocalAPIHost:
		return true
	}
	if !validLocalHostForTesting && h.RequiredPassword == "" {
		return false // only allow localhost with basic auth or in tests
	}
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// handlerForPath returns the LocalAPI handler for the provided Request.URI.Path.
// (the path doesn't include any query parameters)
func handlerForPath(urlPath string) (h localAPIHandler, ok bool) {
	if urlPath == "/" {
		return (*Handler).serveLocalAPIRoot, true
	}
	suff, ok := strings.CutPrefix(urlPath, "/localapi/v0/")
	if !ok {
		// Currently all LocalAPI methods start with "/localapi/v0/" to signal
		// to people that they're not necessarily stable APIs. In practice we'll
		// probably need to keep them pretty stable anyway, but for now treat
		// them as an internal implementation detail.
		return nil, false
	}
	if fn, ok := handler[suff]; ok {
		// Here we match exact handler suffixes like "status" or ones with a
		// slash already in their name, like "tka/status".
		return fn, true
	}
	// Otherwise, it might be a prefix match like "files/*" which we look up
	// by the prefix including first trailing slash.
	if i := strings.IndexByte(suff, '/'); i != -1 {
		suff = suff[:i+1]
		if fn, ok := handler[suff]; ok {
			return fn, true
		}
	}
	return nil, false
}

func (*Handler) serveLocalAPIRoot(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "tailscaled\n")
}

func (h *Handler) serveWhoIs(w http.ResponseWriter, r *http.Request) {
	h.serveWhoIsWithBackend(w, r, h.b)
}

// localBackendWhoIsMethods is the subset of ipn.LocalBackend as needed
// by the localapi WhoIs method.
type localBackendWhoIsMethods interface {
	WhoIs(string, netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool)
	WhoIsNodeKey(key.NodePublic) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool)
	PeerCaps(netip.Addr) tailcfg.PeerCapMap
}

func (h *Handler) serveWhoIsWithBackend(w http.ResponseWriter, r *http.Request, b localBackendWhoIsMethods) {
	if !h.PermitRead {
		http.Error(w, "whois access denied", http.StatusForbidden)
		return
	}
	var (
		n  tailcfg.NodeView
		u  tailcfg.UserProfile
		ok bool
	)
	var ipp netip.AddrPort
	if v := r.FormValue("addr"); v != "" {
		if strings.HasPrefix(v, "nodekey:") {
			var k key.NodePublic
			if err := k.UnmarshalText([]byte(v)); err != nil {
				http.Error(w, "invalid nodekey in 'addr' parameter", http.StatusBadRequest)
				return
			}
			n, u, ok = b.WhoIsNodeKey(k)
		} else if ip, err := netip.ParseAddr(v); err == nil {
			ipp = netip.AddrPortFrom(ip, 0)
		} else {
			var err error
			ipp, err = netip.ParseAddrPort(v)
			if err != nil {
				http.Error(w, "invalid 'addr' parameter", http.StatusBadRequest)
				return
			}
		}
		if ipp.IsValid() {
			n, u, ok = b.WhoIs(r.FormValue("proto"), ipp)
		}
	} else {
		http.Error(w, "missing 'addr' parameter", http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "no match for IP:port", http.StatusNotFound)
		return
	}
	res := &apitype.WhoIsResponse{
		Node:        n.AsStruct(), // always non-nil per WhoIsResponse contract
		UserProfile: &u,           // always non-nil per WhoIsResponse contract
	}
	if n.Addresses().Len() > 0 {
		res.CapMap = b.PeerCaps(n.Addresses().At(0).Addr())
	}
	j, err := json.MarshalIndent(res, "", "\t")
	if err != nil {
		http.Error(w, "JSON encoding error", http.StatusInternalServerError)
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
	metricDebugMetricsCalls.Add(1)
	// Require write access out of paranoia that the metrics
	// might contain something sensitive.
	if !h.PermitWrite {
		http.Error(w, "metric access denied", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	clientmetric.WritePrometheusExpositionFormat(w)
}

// disconnectControl is the handler for local API /disconnect-control endpoint that shuts down control client, so that
// node no longer communicates with control. Doing this makes control consider this node inactive. This can be used
// before shutting down a replica of HA subnet  router or app connector deployments to ensure that control tells the
// peers to switch over to another replica whilst still maintaining th existing peer connections.
func (h *Handler) disconnectControl(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	h.b.DisconnectControl()
}

func (h *Handler) reloadConfig(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	ok, err := h.b.ReloadConfig()
	var res apitype.ReloadConfigResponse
	res.Reloaded = ok
	if err != nil {
		res.Err = err.Error()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&res)
}

func (h *Handler) serveResetAuth(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "reset-auth modify access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	if err := h.b.ResetAuth(); err != nil {
		http.Error(w, "reset-auth failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func authorizeServeConfigForGOOSAndUserContext(goos string, configIn *ipn.ServeConfig, h *Handler) error {
	switch goos {
	case "windows", "linux", "darwin", "illumos", "solaris":
	default:
		return nil
	}
	// Only check for local admin on tailscaled-on-mac (based on "sudo"
	// permissions). On sandboxed variants (MacSys and AppStore), tailscaled
	// cannot serve files outside of the sandbox and this check is not
	// relevant.
	if goos == "darwin" && version.IsSandboxedMacOS() {
		return nil
	}
	if !configIn.HasPathHandler() {
		return nil
	}
	if h.Actor.IsLocalAdmin(h.b.OperatorUserID()) {
		return nil
	}
	switch goos {
	case "windows":
		return errors.New("must be a Windows local admin to serve a path")
	case "linux", "darwin", "illumos", "solaris":
		return errors.New("must be root, or be an operator and able to run 'sudo tailscale' to serve a path")
	default:
		// We filter goos at the start of the func, this default case
		// should never happen.
		panic("unreachable")
	}

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

// InUseOtherUserIPNStream reports whether r is a request for the watch-ipn-bus
// handler. If so, it writes an ipn.Notify InUseOtherUser message to the user
// and returns true. Otherwise it returns false, in which case it doesn't write
// to w.
//
// Unlike the regular watch-ipn-bus handler, this one doesn't block. The caller
// (in ipnserver.Server) provides the blocking until the connection is no longer
// in use.
func InUseOtherUserIPNStream(w http.ResponseWriter, r *http.Request, err error) (handled bool) {
	if r.Method != "GET" || r.URL.Path != "/localapi/v0/watch-ipn-bus" {
		return false
	}
	js, err := json.Marshal(&ipn.Notify{
		Version:    version.Long(),
		State:      ptr.To(ipn.InUseOtherUser),
		ErrMessage: ptr.To(err.Error()),
	})
	if err != nil {
		return false
	}
	js = append(js, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
	return true
}

func (h *Handler) serveWatchIPNBus(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "watch ipn bus access denied", http.StatusForbidden)
		return
	}
	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "not a flusher", http.StatusInternalServerError)
		return
	}

	var mask ipn.NotifyWatchOpt
	if s := r.FormValue("mask"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			http.Error(w, "bad mask", http.StatusBadRequest)
			return
		}
		mask = ipn.NotifyWatchOpt(v)
	}
	// Users with only read access must request private key filtering. If they
	// don't filter out private keys, require write access.
	if (mask & ipn.NotifyNoPrivateKeys) == 0 {
		if !h.PermitWrite {
			http.Error(w, "watch IPN bus access denied, must set ipn.NotifyNoPrivateKeys when not running as admin/root or operator", http.StatusForbidden)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()
	enc := json.NewEncoder(w)
	h.b.WatchNotificationsAs(ctx, h.Actor, mask, f.Flush, func(roNotify *ipn.Notify) (keepGoing bool) {
		err := enc.Encode(roNotify)
		if err != nil {
			h.logf("json.Encode: %v", err)
			return false
		}
		f.Flush()
		return true
	})
}

func (h *Handler) serveLoginInteractive(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "login access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "want POST", http.StatusBadRequest)
		return
	}
	h.b.StartLoginInteractiveAs(r.Context(), h.Actor)
	w.WriteHeader(http.StatusNoContent)
	return
}

func (h *Handler) serveStart(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "want POST", http.StatusBadRequest)
		return
	}
	var o ipn.Options
	if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := h.b.Start(o)
	if err != nil {
		// TODO(bradfitz): map error to a good HTTP error
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) serveLogout(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "logout access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "want POST", http.StatusBadRequest)
		return
	}
	err := h.b.Logout(r.Context())
	if err == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func (h *Handler) servePrefs(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "prefs access denied", http.StatusForbidden)
		return
	}
	var prefs ipn.PrefsView
	switch r.Method {
	case "PATCH":
		if !h.PermitWrite {
			http.Error(w, "prefs write access denied", http.StatusForbidden)
			return
		}
		mp := new(ipn.MaskedPrefs)
		if err := json.NewDecoder(r.Body).Decode(mp); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var err error
		prefs, err = h.b.EditPrefs(mp)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resJSON{Error: err.Error()})
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

type resJSON struct {
	Error string `json:",omitempty"`
}

func (h *Handler) serveCheckPrefs(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "checkprefs access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	p := new(ipn.Prefs)
	if err := json.NewDecoder(r.Body).Decode(p); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	err := h.b.CheckPrefs(p)
	var res resJSON
	if err != nil {
		res.Error = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func writeErrorJSON(w http.ResponseWriter, err error) {
	if err == nil {
		err = errors.New("unexpected nil error")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	type E struct {
		Error string `json:"error"`
	}
	json.NewEncoder(w).Encode(E{err.Error()})
}

// serveProfiles serves profile switching-related endpoints. Supported methods
// and paths are:
//   - GET /profiles/: list all profiles (JSON-encoded array of ipn.LoginProfiles)
//   - PUT /profiles/: add new profile (no response). A separate
//     StartLoginInteractive() is needed to populate and persist the new profile.
//   - GET /profiles/current: current profile (JSON-ecoded ipn.LoginProfile)
//   - GET /profiles/<id>: output profile (JSON-ecoded ipn.LoginProfile)
//   - POST /profiles/<id>: switch to profile (no response)
//   - DELETE /profiles/<id>: delete profile (no response)
func (h *Handler) serveProfiles(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "profiles access denied", http.StatusForbidden)
		return
	}
	suffix, ok := strings.CutPrefix(r.URL.EscapedPath(), "/localapi/v0/profiles/")
	if !ok {
		http.Error(w, "misconfigured", http.StatusInternalServerError)
		return
	}
	if suffix == "" {
		switch r.Method {
		case httpm.GET:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(h.b.ListProfiles())
		case httpm.PUT:
			err := h.b.NewProfile()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "use GET or PUT", http.StatusMethodNotAllowed)
		}
		return
	}
	suffix, err := url.PathUnescape(suffix)
	if err != nil {
		http.Error(w, "bad profile ID", http.StatusBadRequest)
		return
	}
	if suffix == "current" {
		switch r.Method {
		case httpm.GET:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(h.b.CurrentProfile())
		default:
			http.Error(w, "use GET", http.StatusMethodNotAllowed)
		}
		return
	}

	profileID := ipn.ProfileID(suffix)
	switch r.Method {
	case httpm.GET:
		profiles := h.b.ListProfiles()
		profileIndex := slices.IndexFunc(profiles, func(p ipn.LoginProfile) bool {
			return p.ID == profileID
		})
		if profileIndex == -1 {
			http.Error(w, "Profile not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(profiles[profileIndex])
	case httpm.POST:
		err := h.b.SwitchProfile(profileID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case httpm.DELETE:
		err := h.b.DeleteProfile(profileID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "use POST or DELETE", http.StatusMethodNotAllowed)
	}
}

// serveQueryFeature makes a request to the "/machine/feature/query"
// Noise endpoint to get instructions on how to enable a feature, such as
// Funnel, for the node's tailnet.
//
// This request itself does not directly enable the feature on behalf of
// the node, but rather returns information that can be presented to the
// acting user about where/how to enable the feature. If relevant, this
// includes a control URL the user can visit to explicitly consent to
// using the feature.
//
// See tailcfg.QueryFeatureResponse for full response structure.
func (h *Handler) serveQueryFeature(w http.ResponseWriter, r *http.Request) {
	feature := r.FormValue("feature")
	switch {
	case !h.PermitRead:
		http.Error(w, "access denied", http.StatusForbidden)
		return
	case r.Method != httpm.POST:
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	case feature == "":
		http.Error(w, "missing feature", http.StatusInternalServerError)
		return
	}
	nm := h.b.NetMap()
	if nm == nil {
		http.Error(w, "no netmap", http.StatusServiceUnavailable)
		return
	}

	b, err := json.Marshal(&tailcfg.QueryFeatureRequest{
		NodeKey: nm.NodeKey,
		Feature: feature,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(),
		"POST", "https://unused/machine/feature/query", bytes.NewReader(b))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := h.b.DoNoiseRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

func (h *Handler) serveDebugLog(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "debug-log access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	defer h.b.TryFlushLogs() // kick off upload after we're done logging

	type logRequestJSON struct {
		Lines  []string
		Prefix string
	}

	var logRequest logRequestJSON
	if err := json.NewDecoder(r.Body).Decode(&logRequest); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	prefix := logRequest.Prefix
	if prefix == "" {
		prefix = "debug-log"
	}
	logf := logger.WithPrefix(h.logf, prefix+": ")

	// We can write logs too fast for logtail to handle, even when
	// opting-out of rate limits. Limit ourselves to at most one message
	// per 20ms and a burst of 60 log lines, which should be fast enough to
	// not block for too long but slow enough that we can upload all lines.
	logf = logger.SlowLoggerWithClock(r.Context(), logf, 20*time.Millisecond, 60, h.clock.Now)

	for _, line := range logRequest.Lines {
		logf("%s", line)
	}

	w.WriteHeader(http.StatusNoContent)
}

var (
	metricInvalidRequests = clientmetric.NewCounter("localapi_invalid_requests")

	// User-visible LocalAPI endpoints.
	metricFilePutCalls      = clientmetric.NewCounter("localapi_file_put")
	metricDebugMetricsCalls = clientmetric.NewCounter("localapi_debugmetric_requests")
	metricUserMetricsCalls  = clientmetric.NewCounter("localapi_usermetric_requests")
)
