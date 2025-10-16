// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package localapi contains the HTTP server handlers for tailscaled's API server.
package localapi

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
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

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health/healthmsg"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/logtail"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/appctype"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/ptr"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/httpm"
	"tailscale.com/util/mak"
	"tailscale.com/util/osdiag"
	"tailscale.com/util/rands"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/version"
	"tailscale.com/wgengine/magicsock"
)

var (
	metricInvalidRequests   = clientmetric.NewCounter("localapi_invalid_requests")
	metricDebugMetricsCalls = clientmetric.NewCounter("localapi_debugmetric_requests")
	metricUserMetricsCalls  = clientmetric.NewCounter("localapi_usermetric_requests")
	metricBugReportRequests = clientmetric.NewCounter("localapi_bugreport_requests")
)

type LocalAPIHandler func(*Handler, http.ResponseWriter, *http.Request)

// handler is the set of LocalAPI handlers, keyed by the part of the
// Request.URL.Path after "/localapi/v0/". If the key ends with a trailing slash
// then it's a prefix match.
var handler = map[string]LocalAPIHandler{
	// The prefix match handlers end with a slash:
	"profiles/": (*Handler).serveProfiles,

	// The other /localapi/v0/NAME handlers are exact matches and contain only NAME
	// without a trailing slash:
	"check-prefs":       (*Handler).serveCheckPrefs,
	"derpmap":           (*Handler).serveDERPMap,
	"goroutines":        (*Handler).serveGoroutines,
	"login-interactive": (*Handler).serveLoginInteractive,
	"logout":            (*Handler).serveLogout,
	"ping":              (*Handler).servePing,
	"prefs":             (*Handler).servePrefs,
	"reload-config":     (*Handler).reloadConfig,
	"reset-auth":        (*Handler).serveResetAuth,
	"set-expiry-sooner": (*Handler).serveSetExpirySooner,
	"shutdown":          (*Handler).serveShutdown,
	"start":             (*Handler).serveStart,
	"status":            (*Handler).serveStatus,
	"whois":             (*Handler).serveWhoIs,
}

func init() {
	if buildfeatures.HasAppConnectors {
		Register("appc-route-info", (*Handler).serveGetAppcRouteInfo)
	}
	if buildfeatures.HasAdvertiseRoutes {
		Register("check-ip-forwarding", (*Handler).serveCheckIPForwarding)
		Register("check-udp-gro-forwarding", (*Handler).serveCheckUDPGROForwarding)
		Register("set-udp-gro-forwarding", (*Handler).serveSetUDPGROForwarding)
	}
	if buildfeatures.HasUseExitNode && runtime.GOOS == "linux" {
		Register("check-reverse-path-filtering", (*Handler).serveCheckReversePathFiltering)
	}
	if buildfeatures.HasClientMetrics {
		Register("upload-client-metrics", (*Handler).serveUploadClientMetrics)
	}
	if buildfeatures.HasClientUpdate {
		Register("update/check", (*Handler).serveUpdateCheck)
	}
	if buildfeatures.HasUseExitNode {
		Register("suggest-exit-node", (*Handler).serveSuggestExitNode)
		Register("set-use-exit-node-enabled", (*Handler).serveSetUseExitNodeEnabled)
	}
	if buildfeatures.HasACME {
		Register("set-dns", (*Handler).serveSetDNS)
	}
	if buildfeatures.HasDebug {
		Register("bugreport", (*Handler).serveBugReport)
		Register("pprof", (*Handler).servePprof)
	}
	if buildfeatures.HasDebug || buildfeatures.HasServe {
		Register("watch-ipn-bus", (*Handler).serveWatchIPNBus)
	}
	if buildfeatures.HasDNS {
		Register("dns-osconfig", (*Handler).serveDNSOSConfig)
		Register("dns-query", (*Handler).serveDNSQuery)
	}
	if buildfeatures.HasUserMetrics {
		Register("usermetrics", (*Handler).serveUserMetrics)
	}
	if buildfeatures.HasServe {
		Register("query-feature", (*Handler).serveQueryFeature)
	}
	if buildfeatures.HasOutboundProxy || buildfeatures.HasSSH {
		Register("dial", (*Handler).serveDial)
	}
	if buildfeatures.HasClientMetrics || buildfeatures.HasDebug {
		Register("metrics", (*Handler).serveMetrics)
	}
	if buildfeatures.HasDebug || buildfeatures.HasAdvertiseRoutes {
		Register("disconnect-control", (*Handler).disconnectControl)
	}
	// Alpha/experimental/debug features. These should be moved to
	// their own features if/when they graduate.
	if buildfeatures.HasDebug {
		Register("id-token", (*Handler).serveIDToken)
		Register("alpha-set-device-attrs", (*Handler).serveSetDeviceAttrs) // see tailscale/corp#24690
		Register("handle-push-message", (*Handler).serveHandlePushMessage)
		Register("set-push-device-token", (*Handler).serveSetPushDeviceToken)
	}
	if buildfeatures.HasDebug || runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		Register("set-gui-visible", (*Handler).serveSetGUIVisible)
	}
	if buildfeatures.HasLogTail {
		// TODO(bradfitz): separate out logtail tap functionality from upload
		// functionality to make this possible? But seems unlikely people would
		// want just this. They could "tail -f" or "journalctl -f" their logs
		// themselves.
		Register("logtap", (*Handler).serveLogTap)
	}
}

// Register registers a new LocalAPI handler for the given name.
func Register(name string, fn LocalAPIHandler) {
	if _, ok := handler[name]; ok {
		panic("duplicate LocalAPI handler registration: " + name)
	}
	handler[name] = fn
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

// NewHandler creates a new LocalAPI HTTP handler from the given config.
func NewHandler(cfg HandlerConfig) *Handler {
	return &Handler{
		Actor:        cfg.Actor,
		b:            cfg.Backend,
		logf:         cfg.Logf,
		backendLogID: cfg.LogID,
		clock:        tstime.StdClock{},
		eventBus:     cfg.EventBus,
	}
}

// HandlerConfig carries the settings for a local API handler.
// All fields are required.
type HandlerConfig struct {
	Actor    ipnauth.Actor
	Backend  *ipnlocal.LocalBackend
	Logf     logger.Logf
	LogID    logid.PublicID
	EventBus *eventbus.Bus
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

	// Actor is the identity of the client connected to the Handler.
	Actor ipnauth.Actor

	b            *ipnlocal.LocalBackend
	logf         logger.Logf
	backendLogID logid.PublicID
	clock        tstime.Clock
	eventBus     *eventbus.Bus // read-only after initialization
}

func (h *Handler) Logf(format string, args ...any) {
	h.logf(format, args...)
}

func (h *Handler) LocalBackend() *ipnlocal.LocalBackend {
	return h.b
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
func handlerForPath(urlPath string) (h LocalAPIHandler, ok bool) {
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

// serveIDToken handles requests to get an OIDC ID token.
func (h *Handler) serveIDToken(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "id-token access denied", http.StatusForbidden)
		return
	}
	nm := h.b.NetMap()
	if nm == nil {
		http.Error(w, "no netmap", http.StatusServiceUnavailable)
		return
	}
	aud := strings.TrimSpace(r.FormValue("aud"))
	if len(aud) == 0 {
		http.Error(w, "no audience requested", http.StatusBadRequest)
		return
	}
	req := &tailcfg.TokenRequest{
		CapVersion: tailcfg.CurrentCapabilityVersion,
		Audience:   aud,
		NodeKey:    nm.NodeKey,
	}
	b, err := json.Marshal(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	httpReq, err := http.NewRequest(httpm.POST, "https://unused/machine/id-token", bytes.NewReader(b))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := h.b.DoNoiseRequest(httpReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) serveBugReport(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "bugreport access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	defer h.b.TryFlushLogs() // kick off upload after bugreport's done logging

	logMarker := func() string {
		return fmt.Sprintf("BUG-%v-%v-%v", h.backendLogID, h.clock.Now().UTC().Format("20060102150405Z"), rands.HexString(16))
	}
	if envknob.NoLogsNoSupport() {
		logMarker = func() string { return "BUG-NO-LOGS-NO-SUPPORT-this-node-has-had-its-logging-disabled" }
	}

	startMarker := logMarker()
	h.logf("user bugreport: %s", startMarker)
	if note := r.URL.Query().Get("note"); len(note) > 0 {
		h.logf("user bugreport note: %s", note)
	}
	hi, _ := json.Marshal(hostinfo.New())
	h.logf("user bugreport hostinfo: %s", hi)
	if err := h.b.HealthTracker().OverallError(); err != nil {
		h.logf("user bugreport health: %s", err.Error())
	} else {
		h.logf("user bugreport health: ok")
	}

	// Information about the current node from the netmap
	if nm := h.b.NetMap(); nm != nil {
		if self := nm.SelfNode; self.Valid() {
			h.logf("user bugreport node info: nodeid=%q stableid=%q expiry=%q", self.ID(), self.StableID(), self.KeyExpiry().Format(time.RFC3339))
		}
		h.logf("user bugreport public keys: machine=%q node=%q", nm.MachineKey, nm.NodeKey)
	} else {
		h.logf("user bugreport netmap: no active netmap")
	}

	// Print all envknobs; we otherwise only print these on startup, and
	// printing them here ensures we don't have to go spelunking through
	// logs for them.
	envknob.LogCurrent(logger.WithPrefix(h.logf, "user bugreport: "))

	// OS-specific details
	h.logf.JSON(1, "UserBugReportOS", osdiag.SupportInfo(osdiag.LogSupportInfoReasonBugReport))

	// Tailnet Lock details
	st := h.b.NetworkLockStatus()
	if st.Enabled {
		h.logf.JSON(1, "UserBugReportTailnetLockStatus", st)
		if st.NodeKeySignature != nil {
			h.logf("user bugreport tailnet lock signature: %s", st.NodeKeySignature.String())
		}
	}

	if defBool(r.URL.Query().Get("diagnose"), false) {
		if f, ok := ipnlocal.HookDoctor.GetOk(); ok {
			f(r.Context(), h.b, logger.WithPrefix(h.logf, "diag: "))
		}
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, startMarker)

	// Nothing else to do if we're not in record mode; we wrote the marker
	// above, so we can just finish our response now.
	if !defBool(r.URL.Query().Get("record"), false) {
		return
	}

	until := h.clock.Now().Add(12 * time.Hour)

	var changed map[string]bool
	for _, component := range []string{"magicsock"} {
		if h.b.GetComponentDebugLogging(component).IsZero() {
			if err := h.b.SetComponentDebugLogging(component, until); err != nil {
				h.logf("bugreport: error setting component %q logging: %v", component, err)
				continue
			}

			mak.Set(&changed, component, true)
		}
	}
	defer func() {
		for component := range changed {
			h.b.SetComponentDebugLogging(component, time.Time{})
		}
	}()

	// NOTE(andrew): if we have anything else we want to do while recording
	// a bugreport, we can add it here.

	metricBugReportRequests.Add(1)

	// Read from the client; this will also return when the client closes
	// the connection.
	var buf [1]byte
	_, err := r.Body.Read(buf[:])

	switch {
	case err == nil:
		// good
	case errors.Is(err, io.EOF):
		// good
	case errors.Is(err, io.ErrUnexpectedEOF):
		// this happens when Ctrl-C'ing the tailscale client; don't
		// bother logging an error
	default:
		// Log but continue anyway.
		h.logf("user bugreport: error reading body: %v", err)
	}

	// Generate another log marker and return it to the client.
	endMarker := logMarker()
	h.logf("user bugreport end: %s", endMarker)
	fmt.Fprintln(w, endMarker)
}

func (h *Handler) serveWhoIs(w http.ResponseWriter, r *http.Request) {
	h.serveWhoIsWithBackend(w, r, h.b)
}

// serveSetDeviceAttrs is (as of 2024-12-30) an experimental LocalAPI handler to
// set device attributes via the control plane.
//
// See tailscale/corp#24690.
func (h *Handler) serveSetDeviceAttrs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !h.PermitWrite {
		http.Error(w, "set-device-attrs access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.PATCH {
		http.Error(w, "only PATCH allowed", http.StatusMethodNotAllowed)
		return
	}
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.b.SetDeviceAttrs(ctx, req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, "{}\n")
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

// serveLogTap taps into the tailscaled/logtail server output and streams
// it to the client.
func (h *Handler) serveLogTap(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Require write access (~root) as the logs could contain something
	// sensitive.
	if !h.PermitWrite {
		http.Error(w, "logtap access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.GET {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	io.WriteString(w, `{"text":"[logtap connected]\n"}`+"\n")
	f.Flush()

	msgc := make(chan string, 16)
	unreg := logtail.RegisterLogTap(msgc)
	defer unreg()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-msgc:
			io.WriteString(w, msg)
			f.Flush()
		}
	}
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

// serveUserMetrics returns user-facing metrics in Prometheus text
// exposition format.
func (h *Handler) serveUserMetrics(w http.ResponseWriter, r *http.Request) {
	metricUserMetricsCalls.Add(1)
	h.b.UserMetricsRegistry().Handler(w, r)
}

// servePprofFunc is the implementation of Handler.servePprof, after auth,
// for platforms where we want to link it in.
var servePprofFunc func(http.ResponseWriter, *http.Request)

func (h *Handler) servePprof(w http.ResponseWriter, r *http.Request) {
	// Require write access out of paranoia that the profile dump
	// might contain something sensitive.
	if !h.PermitWrite {
		http.Error(w, "profile access denied", http.StatusForbidden)
		return
	}
	if servePprofFunc == nil {
		http.Error(w, "not implemented on this platform", http.StatusServiceUnavailable)
		return
	}
	servePprofFunc(w, r)
}

// disconnectControl is the handler for local API /disconnect-control endpoint that shuts down control client, so that
// node no longer communicates with control. Doing this makes control consider this node inactive. This can be used
// before shutting down a replica of HA subnet router or app connector deployments to ensure that control tells the
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

func (h *Handler) serveCheckReversePathFiltering(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "reverse path filtering check access denied", http.StatusForbidden)
		return
	}
	var warning string

	state := h.b.Sys().NetMon.Get().InterfaceState()
	warn, err := netutil.CheckReversePathFiltering(state)
	if err == nil && len(warn) > 0 {
		var msg strings.Builder
		msg.WriteString(healthmsg.WarnExitNodeUsage + ":\n")
		for _, w := range warn {
			msg.WriteString("- " + w + "\n")
		}
		msg.WriteString(healthmsg.DisableRPFilter)
		warning = msg.String()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Warning string
	}{
		Warning: warning,
	})
}

func (h *Handler) serveCheckUDPGROForwarding(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "UDP GRO forwarding check access denied", http.StatusForbidden)
		return
	}
	var warning string
	if err := h.b.CheckUDPGROForwarding(); err != nil {
		warning = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Warning string
	}{
		Warning: warning,
	})
}

func (h *Handler) serveSetUDPGROForwarding(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasGRO {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	if !h.PermitWrite {
		http.Error(w, "UDP GRO forwarding set access denied", http.StatusForbidden)
		return
	}
	var warning string
	if err := h.b.SetUDPGROForwarding(); err != nil {
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

// InUseOtherUserIPNStream reports whether r is a request for the watch-ipn-bus
// handler. If so, it writes an ipn.Notify InUseOtherUser message to the user
// and returns true. Otherwise it returns false, in which case it doesn't write
// to w.
//
// Unlike the regular watch-ipn-bus handler, this one doesn't block. The caller
// (in ipnserver.Server) provides the blocking until the connection is no longer
// in use.
func InUseOtherUserIPNStream(w http.ResponseWriter, r *http.Request, err error) (handled bool) {
	if r.Method != httpm.GET || r.URL.Path != "/localapi/v0/watch-ipn-bus" {
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
	if r.Method != httpm.POST {
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
	if r.Method != httpm.POST {
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
	if r.Method != httpm.POST {
		http.Error(w, "want POST", http.StatusBadRequest)
		return
	}
	err := h.b.Logout(r.Context(), h.Actor)
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
	case httpm.PATCH:
		if !h.PermitWrite {
			http.Error(w, "prefs write access denied", http.StatusForbidden)
			return
		}
		mp := new(ipn.MaskedPrefs)
		if err := json.NewDecoder(r.Body).Decode(mp); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if buildfeatures.HasAppConnectors {
			if err := h.b.MaybeClearAppConnector(mp); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(resJSON{Error: err.Error()})
				return
			}
		}
		var err error
		prefs, err = h.b.EditPrefsAs(mp, h.Actor)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resJSON{Error: err.Error()})
			return
		}
	case httpm.GET, httpm.HEAD:
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
	if r.Method != httpm.POST {
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

// WriteErrorJSON writes a JSON object (with a single "error" string field) to w
// with the given error. If err is nil, "unexpected nil error" is used for the
// stringification instead.
func WriteErrorJSON(w http.ResponseWriter, err error) {
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

func (h *Handler) serveSetDNS(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "want POST", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	err := h.b.SetDNS(ctx, r.FormValue("name"), r.FormValue("value"))
	if err != nil {
		WriteErrorJSON(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct{}{})
}

func (h *Handler) serveDERPMap(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.GET {
		http.Error(w, "want GET", http.StatusBadRequest)
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
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
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

func (h *Handler) servePing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != httpm.POST {
		http.Error(w, "want POST", http.StatusBadRequest)
		return
	}
	ipStr := r.FormValue("ip")
	if ipStr == "" {
		http.Error(w, "missing 'ip' parameter", http.StatusBadRequest)
		return
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		http.Error(w, "invalid IP", http.StatusBadRequest)
		return
	}
	pingTypeStr := r.FormValue("type")
	if pingTypeStr == "" {
		http.Error(w, "missing 'type' parameter", http.StatusBadRequest)
		return
	}
	size := 0
	sizeStr := r.FormValue("size")
	if sizeStr != "" {
		size, err = strconv.Atoi(sizeStr)
		if err != nil {
			http.Error(w, "invalid 'size' parameter", http.StatusBadRequest)
			return
		}
		if size != 0 && tailcfg.PingType(pingTypeStr) != tailcfg.PingDisco {
			http.Error(w, "'size' parameter is only supported with disco pings", http.StatusBadRequest)
			return
		}
		if size > magicsock.MaxDiscoPingSize {
			http.Error(w, fmt.Sprintf("maximum value for 'size' is %v", magicsock.MaxDiscoPingSize), http.StatusBadRequest)
			return
		}
	}
	res, err := h.b.Ping(ctx, ip, tailcfg.PingType(pingTypeStr), size)
	if err != nil {
		WriteErrorJSON(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (h *Handler) serveDial(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.POST {
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

	network := cmp.Or(r.Header.Get("Dial-Network"), "tcp")

	addr := net.JoinHostPort(hostStr, portStr)
	outConn, err := h.b.Dialer().UserDial(r.Context(), network, addr)
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

func (h *Handler) serveSetPushDeviceToken(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "set push device token access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	var params apitype.SetPushDeviceTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	h.b.SetPushDeviceToken(params.PushDeviceToken)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) serveHandlePushMessage(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "handle push message not allowed", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	var pushMessageBody map[string]any
	if err := json.NewDecoder(r.Body).Decode(&pushMessageBody); err != nil {
		http.Error(w, "failed to decode JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// TODO(bradfitz): do something with pushMessageBody
	h.logf("localapi: got push message: %v", logger.AsJSON(pushMessageBody))

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) serveUploadClientMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.POST {
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	type clientMetricJSON struct {
		Name  string `json:"name"`
		Type  string `json:"type"`  // one of "counter" or "gauge"
		Value int    `json:"value"` // amount to increment metric by
	}

	var clientMetrics []clientMetricJSON
	if err := json.NewDecoder(r.Body).Decode(&clientMetrics); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	metricsMu.Lock()
	defer metricsMu.Unlock()

	for _, m := range clientMetrics {
		if metric, ok := metrics[m.Name]; ok {
			metric.Add(int64(m.Value))
		} else {
			if clientmetric.HasPublished(m.Name) {
				http.Error(w, "Already have a metric named "+m.Name, http.StatusBadRequest)
				return
			}
			var metric *clientmetric.Metric
			switch m.Type {
			case "counter":
				metric = clientmetric.NewCounter(m.Name)
			case "gauge":
				metric = clientmetric.NewGauge(m.Name)
			default:
				http.Error(w, "Unknown metric type "+m.Type, http.StatusBadRequest)
				return
			}
			metrics[m.Name] = metric
			metric.Add(int64(m.Value))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct{}{})
}

func (h *Handler) serveSetGUIVisible(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	type setGUIVisibleRequest struct {
		IsVisible bool   // whether the Tailscale client UI is now presented to the user
		SessionID string // the last SessionID sent to the client in ipn.Notify.SessionID
	}
	var req setGUIVisibleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// TODO(bradfitz): use `req.IsVisible == true` to flush netmap

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) serveSetUseExitNodeEnabled(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasUseExitNode {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	v, err := strconv.ParseBool(r.URL.Query().Get("enabled"))
	if err != nil {
		http.Error(w, "invalid 'enabled' parameter", http.StatusBadRequest)
		return
	}
	prefs, err := h.b.SetUseExitNodeEnabled(h.Actor, v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "\t")
	e.Encode(prefs)
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
		profileIndex := slices.IndexFunc(profiles, func(p ipn.LoginProfileView) bool {
			return p.ID() == profileID
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
		httpm.POST, "https://unused/machine/feature/query", bytes.NewReader(b))
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

// serveUpdateCheck returns the ClientVersion from Status, which contains
// information on whether an update is available, and if so, what version,
// *if* we support auto-updates on this platform. If we don't, this endpoint
// always returns a ClientVersion saying we're running the newest version.
// Effectively, it tells us whether serveUpdateInstall will be able to install
// an update for us.
func (h *Handler) serveUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.GET {
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	cv := h.b.StatusWithoutPeers().ClientVersion
	// ipnstate.Status documentation notes that ClientVersion may be nil on some
	// platforms where this information is unavailable. In that case, return a
	// ClientVersion that says we're up to date, since we have no information on
	// whether an update is possible.
	if cv == nil {
		cv = &tailcfg.ClientVersion{RunningLatest: true}
	}

	json.NewEncoder(w).Encode(cv)
}

// serveDNSOSConfig serves the current system DNS configuration as a JSON object, if
// supported by the OS.
func (h *Handler) serveDNSOSConfig(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasDNS {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	if r.Method != httpm.GET {
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	// Require write access for privacy reasons.
	if !h.PermitWrite {
		http.Error(w, "dns-osconfig dump access denied", http.StatusForbidden)
		return
	}
	bCfg, err := h.b.GetDNSOSConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	nameservers := make([]string, 0, len(bCfg.Nameservers))
	for _, ns := range bCfg.Nameservers {
		nameservers = append(nameservers, ns.String())
	}
	searchDomains := make([]string, 0, len(bCfg.SearchDomains))
	for _, sd := range bCfg.SearchDomains {
		searchDomains = append(searchDomains, sd.WithoutTrailingDot())
	}
	matchDomains := make([]string, 0, len(bCfg.MatchDomains))
	for _, md := range bCfg.MatchDomains {
		matchDomains = append(matchDomains, md.WithoutTrailingDot())
	}
	response := apitype.DNSOSConfig{
		Nameservers:   nameservers,
		SearchDomains: searchDomains,
		MatchDomains:  matchDomains,
	}
	json.NewEncoder(w).Encode(response)
}

// serveDNSQuery provides the ability to perform DNS queries using the internal
// DNS forwarder. This is useful for debugging and testing purposes.
// URL parameters:
//   - name: the domain name to query
//   - type: the DNS record type to query as a number (default if empty: A = '1')
//
// The response if successful is a DNSQueryResponse JSON object.
func (h *Handler) serveDNSQuery(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasDNS {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	if r.Method != httpm.GET {
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	// Require write access for privacy reasons.
	if !h.PermitWrite {
		http.Error(w, "dns-query access denied", http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	name := q.Get("name")
	queryType := q.Get("type")
	qt := dnsmessage.TypeA
	if queryType != "" {
		t, err := dnsMessageTypeForString(queryType)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		qt = t
	}

	res, rrs, err := h.b.QueryDNS(name, qt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&apitype.DNSQueryResponse{
		Bytes:     res,
		Resolvers: rrs,
	})
}

// dnsMessageTypeForString returns the dnsmessage.Type for the given string.
// For example, DNSMessageTypeForString("A") returns dnsmessage.TypeA.
func dnsMessageTypeForString(s string) (t dnsmessage.Type, err error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	switch s {
	case "AAAA":
		return dnsmessage.TypeAAAA, nil
	case "ALL":
		return dnsmessage.TypeALL, nil
	case "A":
		return dnsmessage.TypeA, nil
	case "CNAME":
		return dnsmessage.TypeCNAME, nil
	case "HINFO":
		return dnsmessage.TypeHINFO, nil
	case "MINFO":
		return dnsmessage.TypeMINFO, nil
	case "MX":
		return dnsmessage.TypeMX, nil
	case "NS":
		return dnsmessage.TypeNS, nil
	case "OPT":
		return dnsmessage.TypeOPT, nil
	case "PTR":
		return dnsmessage.TypePTR, nil
	case "SOA":
		return dnsmessage.TypeSOA, nil
	case "SRV":
		return dnsmessage.TypeSRV, nil
	case "TXT":
		return dnsmessage.TypeTXT, nil
	case "WKS":
		return dnsmessage.TypeWKS, nil
	}
	return 0, errors.New("unknown DNS message type: " + s)
}

// serveSuggestExitNode serves a POST endpoint for returning a suggested exit node.
func (h *Handler) serveSuggestExitNode(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasUseExitNode {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	if r.Method != httpm.GET {
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	res, err := h.b.SuggestExitNode()
	if err != nil {
		WriteErrorJSON(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// Shutdown is an eventbus value published when tailscaled shutdown
// is requested via LocalAPI. Its only consumer is [ipnserver.Server].
type Shutdown struct{}

// serveShutdown shuts down tailscaled. It requires write access
// and the [pkey.AllowTailscaledRestart] policy to be enabled.
// See tailscale/corp#32674.
func (h *Handler) serveShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.POST {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.PermitWrite {
		http.Error(w, "shutdown access denied", http.StatusForbidden)
		return
	}

	polc := h.b.Sys().PolicyClientOrDefault()
	if permitShutdown, _ := polc.GetBoolean(pkey.AllowTailscaledRestart, false); !permitShutdown {
		http.Error(w, "shutdown access denied by policy", http.StatusForbidden)
		return
	}

	ec := h.eventBus.Client("localapi.Handler")
	defer ec.Close()

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	eventbus.Publish[Shutdown](ec).Publish(Shutdown{})
}

func (h *Handler) serveGetAppcRouteInfo(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasAppConnectors {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	if r.Method != httpm.GET {
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	res, err := h.b.ReadRouteInfo()
	if err != nil {
		if errors.Is(err, ipn.ErrStateNotExist) {
			res = &appctype.RouteInfo{}
		} else {
			WriteErrorJSON(w, err)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}
