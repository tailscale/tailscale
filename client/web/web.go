// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package web provides the Tailscale client for web.
package web

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/csrf"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/clientupdate"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/licenses"
	"tailscale.com/net/netutil"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/httpm"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

// ListenPort is the static port used for the web client when run inside tailscaled.
// (5252 are the numbers above the letters "TSTS" on a qwerty keyboard.)
const ListenPort = 5252

// Server is the backend server for a Tailscale web client.
type Server struct {
	mode ServerMode

	logf    logger.Logf
	lc      *tailscale.LocalClient
	timeNow func() time.Time

	// devMode indicates that the server run with frontend assets
	// served by a Vite dev server, allowing for local development
	// on the web client frontend.
	devMode    bool
	cgiMode    bool
	pathPrefix string

	apiHandler    http.Handler // serves api endpoints; csrf-protected
	assetsHandler http.Handler // serves frontend assets
	assetsCleanup func()       // called from Server.Shutdown

	// browserSessions is an in-memory cache of browser sessions for the
	// full management web client, which is only accessible over Tailscale.
	//
	// Users obtain a valid browser session by connecting to the web client
	// over Tailscale and verifying their identity by authenticating on the
	// control server.
	//
	// browserSessions get reset on every Server restart.
	//
	// The map provides a lookup of the session by cookie value
	// (browserSession.ID => browserSession).
	browserSessions sync.Map

	// newAuthURL creates a new auth URL that can be used to validate
	// a browser session to manage this web client.
	newAuthURL func(ctx context.Context, src tailcfg.NodeID) (*tailcfg.WebClientAuthResponse, error)
	// waitWebClientAuthURL blocks until the associated auth URL has
	// been completed by its user, or until ctx is canceled.
	waitAuthURL func(ctx context.Context, id string, src tailcfg.NodeID) (*tailcfg.WebClientAuthResponse, error)
}

// ServerMode specifies the mode of a running web.Server.
type ServerMode string

const (
	// LoginServerMode serves a readonly login client for logging a
	// node into a tailnet, and viewing a readonly interface of the
	// node's current Tailscale settings.
	//
	// In this mode, API calls are authenticated via platform auth.
	LoginServerMode ServerMode = "login"

	// ReadOnlyServerMode is identical to LoginServerMode,
	// but does not present a login button to switch to manage mode,
	// even if the management client is running and reachable.
	//
	// This is designed for platforms where the device is configured by other means,
	// such as Home Assistant's declarative YAML configuration.
	ReadOnlyServerMode ServerMode = "readonly"

	// ManageServerMode serves a management client for editing tailscale
	// settings of a node.
	//
	// This mode restricts the app to only being assessible over Tailscale,
	// and API calls are authenticated via browser sessions associated with
	// the source's Tailscale identity. If the source browser does not have
	// a valid session, a readonly version of the app is displayed.
	ManageServerMode ServerMode = "manage"
)

var (
	exitNodeRouteV4 = netip.MustParsePrefix("0.0.0.0/0")
	exitNodeRouteV6 = netip.MustParsePrefix("::/0")
)

// ServerOpts contains options for constructing a new Server.
type ServerOpts struct {
	// Mode specifies the mode of web client being constructed.
	Mode ServerMode

	// CGIMode indicates if the server is running as a CGI script.
	CGIMode bool

	// PathPrefix is the URL prefix added to requests by CGI or reverse proxy.
	PathPrefix string

	// LocalClient is the tailscale.LocalClient to use for this web server.
	// If nil, a new one will be created.
	LocalClient *tailscale.LocalClient

	// TimeNow optionally provides a time function.
	// time.Now is used as default.
	TimeNow func() time.Time

	// Logf optionally provides a logger function.
	// log.Printf is used as default.
	Logf logger.Logf

	// The following two fields are required and used exclusively
	// in ManageServerMode to facilitate the control server login
	// check step for authorizing browser sessions.

	// NewAuthURL should be provided as a function that generates
	// a new tailcfg.WebClientAuthResponse.
	// This field is required for ManageServerMode mode.
	NewAuthURL func(ctx context.Context, src tailcfg.NodeID) (*tailcfg.WebClientAuthResponse, error)
	// WaitAuthURL should be provided as a function that blocks until
	// the associated tailcfg.WebClientAuthResponse has been marked
	// as completed.
	// This field is required for ManageServerMode mode.
	WaitAuthURL func(ctx context.Context, id string, src tailcfg.NodeID) (*tailcfg.WebClientAuthResponse, error)
}

// NewServer constructs a new Tailscale web client server.
// If err is empty, s is always non-nil.
// ctx is only required to live the duration of the NewServer call,
// and not the lifespan of the web server.
func NewServer(opts ServerOpts) (s *Server, err error) {
	switch opts.Mode {
	case LoginServerMode, ReadOnlyServerMode, ManageServerMode:
		// valid types
	case "":
		return nil, fmt.Errorf("must specify a Mode")
	default:
		return nil, fmt.Errorf("invalid Mode provided")
	}
	if opts.LocalClient == nil {
		opts.LocalClient = &tailscale.LocalClient{}
	}
	s = &Server{
		mode:        opts.Mode,
		logf:        opts.Logf,
		devMode:     envknob.Bool("TS_DEBUG_WEB_CLIENT_DEV"),
		lc:          opts.LocalClient,
		cgiMode:     opts.CGIMode,
		pathPrefix:  opts.PathPrefix,
		timeNow:     opts.TimeNow,
		newAuthURL:  opts.NewAuthURL,
		waitAuthURL: opts.WaitAuthURL,
	}
	if opts.PathPrefix != "" {
		// Enforce that path prefix always has a single leading '/'
		// so that it is treated as a relative URL path.
		// We strip multiple leading '/' to prevent schema-less offsite URLs like "//example.com".
		//
		// See https://github.com/tailscale/corp/issues/16268.
		s.pathPrefix = "/" + strings.TrimLeft(path.Clean(opts.PathPrefix), "/\\")
	}
	if s.mode == ManageServerMode {
		if opts.NewAuthURL == nil {
			return nil, fmt.Errorf("must provide a NewAuthURL implementation")
		}
		if opts.WaitAuthURL == nil {
			return nil, fmt.Errorf("must provide WaitAuthURL implementation")
		}
	}
	if s.timeNow == nil {
		s.timeNow = time.Now
	}
	if s.logf == nil {
		s.logf = log.Printf
	}
	s.assetsHandler, s.assetsCleanup = assetsHandler(s.devMode)

	var metric string // clientmetric to report on startup

	// Create handler for "/api" requests with CSRF protection.
	// We don't require secure cookies, since the web client is regularly used
	// on network appliances that are served on local non-https URLs.
	// The client is secured by limiting the interface it listens on,
	// or by authenticating requests before they reach the web client.
	csrfProtect := csrf.Protect(s.csrfKey(), csrf.Secure(false))
	switch s.mode {
	case LoginServerMode:
		s.apiHandler = csrfProtect(http.HandlerFunc(s.serveLoginAPI))
		metric = "web_login_client_initialization"
	case ReadOnlyServerMode:
		s.apiHandler = csrfProtect(http.HandlerFunc(s.serveLoginAPI))
		metric = "web_readonly_client_initialization"
	case ManageServerMode:
		s.apiHandler = csrfProtect(http.HandlerFunc(s.serveAPI))
		metric = "web_client_initialization"
	}

	// Don't block startup on reporting metric.
	// Report in separate go routine with 5 second timeout.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.lc.IncrementCounter(ctx, metric, 1)
	}()

	return s, nil
}

func (s *Server) Shutdown() {
	s.logf("web.Server: shutting down")
	if s.assetsCleanup != nil {
		s.assetsCleanup()
	}
}

// ServeHTTP processes all requests for the Tailscale web client.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := s.serve

	// if path prefix is defined, strip it from requests.
	if s.cgiMode && s.pathPrefix != "" {
		handler = enforcePrefix(s.pathPrefix, handler)
	}

	handler(w, r)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if s.mode == ManageServerMode {
		// In manage mode, requests must be sent directly to the bare Tailscale IP address.
		// If a request comes in on any other hostname, redirect.
		if s.requireTailscaleIP(w, r) {
			return // user was redirected
		}

		// serve HTTP 204 on /ok requests as connectivity check
		if r.Method == httpm.GET && r.URL.Path == "/ok" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if !s.devMode {
			// This hash corresponds to the inline script in index.html that runs when the react app is unavailable.
			// It was generated from https://csplite.com/csp/sha/.
			// If the contents of the script are changed, this hash must be updated.
			const indexScriptHash = "sha384-CW2AYVfS14P7QHZN27thEkMLKiCj3YNURPoLc1elwiEkMVHeuYTWkJOEki1F3nZc"

			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src * data:; script-src 'self' '"+indexScriptHash+"'")
			w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		}
	}

	if strings.HasPrefix(r.URL.Path, "/api/") {
		switch {
		case r.URL.Path == "/api/auth" && r.Method == httpm.GET:
			s.serveAPIAuth(w, r) // serve auth status
			return
		case r.URL.Path == "/api/auth/session/new" && r.Method == httpm.GET:
			s.serveAPIAuthSessionNew(w, r) // create new session
			return
		case r.URL.Path == "/api/auth/session/wait" && r.Method == httpm.GET:
			s.serveAPIAuthSessionWait(w, r) // wait for session to be authorized
			return
		}
		if ok := s.authorizeRequest(w, r); !ok {
			http.Error(w, "not authorized", http.StatusUnauthorized)
			return
		}
		// Pass API requests through to the API handler.
		s.apiHandler.ServeHTTP(w, r)
		return
	}
	s.assetsHandler.ServeHTTP(w, r)
}

// requireTailscaleIP redirects an incoming request if the HTTP request was not made to a bare Tailscale IP address.
// The request will be redirected to the Tailscale IP, port 5252, with the original request path.
// This allows any custom hostname to be used to access the device, but protects against DNS rebinding attacks.
// Returns true if the request has been fully handled, either be returning a redirect or an HTTP error.
func (s *Server) requireTailscaleIP(w http.ResponseWriter, r *http.Request) (handled bool) {
	const (
		ipv4ServiceHost = tsaddr.TailscaleServiceIPString
		ipv6ServiceHost = "[" + tsaddr.TailscaleServiceIPv6String + "]"
	)
	// allow requests on quad-100 (or ipv6 equivalent)
	if r.Host == ipv4ServiceHost || r.Host == ipv6ServiceHost {
		return false
	}

	st, err := s.lc.StatusWithoutPeers(r.Context())
	if err != nil {
		s.logf("error getting status: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}

	ipv4, ipv6 := s.selfNodeAddresses(r, st)
	if r.Host == fmt.Sprintf("%s:%d", ipv4.String(), ListenPort) {
		return false // already accessing over Tailscale IP
	}
	if r.Host == fmt.Sprintf("[%s]:%d", ipv6.String(), ListenPort) {
		return false // already accessing over Tailscale IP
	}

	// Not currently accessing via Tailscale IP,
	// redirect them.

	var preferV6 bool
	if ap, err := netip.ParseAddrPort(r.Host); err == nil {
		// If Host was already ipv6, keep them on same protocol.
		preferV6 = ap.Addr().Is6()
	}

	newURL := *r.URL
	if (preferV6 && ipv6.IsValid()) || !ipv4.IsValid() {
		newURL.Host = fmt.Sprintf("[%s]:%d", ipv6.String(), ListenPort)
	} else {
		newURL.Host = fmt.Sprintf("%s:%d", ipv4.String(), ListenPort)
	}
	http.Redirect(w, r, newURL.String(), http.StatusMovedPermanently)
	return true
}

// selfNodeAddresses return the Tailscale IPv4 and IPv6 addresses for the self node.
// st is expected to be a status with peers included.
func (s *Server) selfNodeAddresses(r *http.Request, st *ipnstate.Status) (ipv4, ipv6 netip.Addr) {
	for _, ip := range st.Self.TailscaleIPs {
		if ip.Is4() {
			ipv4 = ip
		} else if ip.Is6() {
			ipv6 = ip
		}
		if ipv4.IsValid() && ipv6.IsValid() {
			break // found both IPs
		}
	}
	if whois, err := s.lc.WhoIs(r.Context(), r.RemoteAddr); err == nil {
		// The source peer connecting to this node may know it by a different
		// IP than the node knows itself as. Specifically, this may be the case
		// if the peer is coming from a different tailnet (sharee node), as IPs
		// are specific to each tailnet.
		// Here, we check if the source peer knows the node by a different IP,
		// and return the peer's version if so.
		if knownIPv4 := whois.Node.SelfNodeV4MasqAddrForThisPeer; knownIPv4 != nil {
			ipv4 = *knownIPv4
		}
		if knownIPv6 := whois.Node.SelfNodeV6MasqAddrForThisPeer; knownIPv6 != nil {
			ipv6 = *knownIPv6
		}
	}
	return ipv4, ipv6
}

// authorizeRequest reports whether the request from the web client
// is authorized to be completed.
// It reports true if the request is authorized, and false otherwise.
// authorizeRequest manages writing out any relevant authorization
// errors to the ResponseWriter itself.
func (s *Server) authorizeRequest(w http.ResponseWriter, r *http.Request) (ok bool) {
	if s.mode == ManageServerMode { // client using tailscale auth
		session, _, _, err := s.getSession(r)
		switch {
		case errors.Is(err, errNotUsingTailscale):
			// All requests must be made over tailscale.
			http.Error(w, "must access over tailscale", http.StatusUnauthorized)
			return false
		case r.URL.Path == "/api/data" && r.Method == httpm.GET:
			// Readonly endpoint allowed without valid browser session.
			return true
		case r.URL.Path == "/api/device-details-click" && r.Method == httpm.POST:
			// Special case metric endpoint that is allowed without a browser session.
			return true
		case strings.HasPrefix(r.URL.Path, "/api/"):
			// All other /api/ endpoints require a valid browser session.
			if err != nil || !session.isAuthorized(s.timeNow()) {
				http.Error(w, "no valid session", http.StatusUnauthorized)
				return false
			}
			return true
		default:
			// No additional auth on non-api (assets, index.html, etc).
			return true
		}
	}
	// Client using system-specific auth.
	switch distro.Get() {
	case distro.Synology:
		authorized, _ := authorizeSynology(r)
		return authorized
	case distro.QNAP:
		authorized, _ := authorizeQNAP(r)
		return authorized
	default:
		return true // no additional auth for this distro
	}
}

// serveLoginAPI serves requests for the web login client.
// It should only be called by Server.ServeHTTP, via Server.apiHandler,
// which protects the handler using gorilla csrf.
func (s *Server) serveLoginAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	switch {
	case r.URL.Path == "/api/data" && r.Method == httpm.GET:
		s.serveGetNodeData(w, r)
	case r.URL.Path == "/api/up" && r.Method == httpm.POST:
		s.serveTailscaleUp(w, r)
	case r.URL.Path == "/api/device-details-click" && r.Method == httpm.POST:
		s.serveDeviceDetailsClick(w, r)
	default:
		http.Error(w, "invalid endpoint or method", http.StatusNotFound)
	}
}

type apiHandler[data any] struct {
	s *Server
	w http.ResponseWriter
	r *http.Request

	// permissionCheck allows for defining whether a requesting peer's
	// capabilities grant them access to make the given data update.
	// If permissionCheck reports false, the request fails as unauthorized.
	permissionCheck func(data data, peer peerCapabilities) bool
}

// newHandler constructs a new api handler which restricts the given request
// to the specified permission check. If the permission check fails for
// the peer associated with the request, an unauthorized error is returned
// to the client.
func newHandler[data any](s *Server, w http.ResponseWriter, r *http.Request, permissionCheck func(data data, peer peerCapabilities) bool) *apiHandler[data] {
	return &apiHandler[data]{
		s:               s,
		w:               w,
		r:               r,
		permissionCheck: permissionCheck,
	}
}

// alwaysAllowed can be passed as the permissionCheck argument to newHandler
// for requests that are always allowed to complete regardless of a peer's
// capabilities.
func alwaysAllowed[data any](_ data, _ peerCapabilities) bool { return true }

func (a *apiHandler[data]) getPeer() (peerCapabilities, error) {
	// TODO(tailscale/corp#16695,sonia): We also call StatusWithoutPeers and
	// WhoIs when originally checking for a session from authorizeRequest.
	// Would be nice if we could pipe those through to here so we don't end
	// up having to re-call them to grab the peer capabilities.
	status, err := a.s.lc.StatusWithoutPeers(a.r.Context())
	if err != nil {
		return nil, err
	}
	whois, err := a.s.lc.WhoIs(a.r.Context(), a.r.RemoteAddr)
	if err != nil {
		return nil, err
	}
	peer, err := toPeerCapabilities(status, whois)
	if err != nil {
		return nil, err
	}
	return peer, nil
}

type noBodyData any // empty type, for use from serveAPI for endpoints with empty body

// handle runs the given handler if the source peer satisfies the
// constraints for running this request.
//
// handle is expected for use when `data` type is empty, or set to
// `noBodyData` in practice. For requests that expect JSON body data
// to be attached, use handleJSON instead.
func (a *apiHandler[data]) handle(h http.HandlerFunc) {
	peer, err := a.getPeer()
	if err != nil {
		http.Error(a.w, err.Error(), http.StatusInternalServerError)
		return
	}
	var body data // not used
	if !a.permissionCheck(body, peer) {
		http.Error(a.w, "not allowed", http.StatusUnauthorized)
		return
	}
	h(a.w, a.r)
}

// handleJSON manages decoding the request's body JSON and passing
// it on to the provided function if the source peer satisfies the
// constraints for running this request.
func (a *apiHandler[data]) handleJSON(h func(ctx context.Context, data data) error) {
	defer a.r.Body.Close()
	var body data
	if err := json.NewDecoder(a.r.Body).Decode(&body); err != nil {
		http.Error(a.w, err.Error(), http.StatusInternalServerError)
		return
	}
	peer, err := a.getPeer()
	if err != nil {
		http.Error(a.w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !a.permissionCheck(body, peer) {
		http.Error(a.w, "not allowed", http.StatusUnauthorized)
		return
	}

	if err := h(a.r.Context(), body); err != nil {
		http.Error(a.w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.w.WriteHeader(http.StatusOK)
}

// serveAPI serves requests for the web client api.
// It should only be called by Server.ServeHTTP, via Server.apiHandler,
// which protects the handler using gorilla csrf.
func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == httpm.PATCH {
		// Enforce that PATCH requests are always application/json.
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
	}

	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	path := strings.TrimPrefix(r.URL.Path, "/api")
	switch {
	case path == "/data" && r.Method == httpm.GET:
		newHandler[noBodyData](s, w, r, alwaysAllowed).
			handle(s.serveGetNodeData)
		return
	case path == "/exit-nodes" && r.Method == httpm.GET:
		newHandler[noBodyData](s, w, r, alwaysAllowed).
			handle(s.serveGetExitNodes)
		return
	case path == "/routes" && r.Method == httpm.POST:
		peerAllowed := func(d postRoutesRequest, p peerCapabilities) bool {
			if d.SetExitNode && !p.canEdit(capFeatureExitNodes) {
				return false
			} else if d.SetRoutes && !p.canEdit(capFeatureSubnets) {
				return false
			}
			return true
		}
		newHandler[postRoutesRequest](s, w, r, peerAllowed).
			handleJSON(s.servePostRoutes)
		return
	case path == "/device-details-click" && r.Method == httpm.POST:
		newHandler[noBodyData](s, w, r, alwaysAllowed).
			handle(s.serveDeviceDetailsClick)
		return
	case path == "/local/v0/logout" && r.Method == httpm.POST:
		peerAllowed := func(_ noBodyData, peer peerCapabilities) bool {
			return peer.canEdit(capFeatureAccount)
		}
		newHandler[noBodyData](s, w, r, peerAllowed).
			handle(s.proxyRequestToLocalAPI)
		return
	case path == "/local/v0/prefs" && r.Method == httpm.PATCH:
		peerAllowed := func(data maskedPrefs, peer peerCapabilities) bool {
			if data.RunSSHSet && !peer.canEdit(capFeatureSSH) {
				return false
			}
			return true
		}
		newHandler[maskedPrefs](s, w, r, peerAllowed).
			handleJSON(s.serveUpdatePrefs)
		return
	case path == "/local/v0/update/check" && r.Method == httpm.GET:
		newHandler[noBodyData](s, w, r, alwaysAllowed).
			handle(s.proxyRequestToLocalAPI)
		return
	case path == "/local/v0/update/check" && r.Method == httpm.POST:
		peerAllowed := func(_ noBodyData, peer peerCapabilities) bool {
			return peer.canEdit(capFeatureAccount)
		}
		newHandler[noBodyData](s, w, r, peerAllowed).
			handle(s.proxyRequestToLocalAPI)
		return
	case path == "/local/v0/update/progress" && r.Method == httpm.POST:
		newHandler[noBodyData](s, w, r, alwaysAllowed).
			handle(s.proxyRequestToLocalAPI)
		return
	case path == "/local/v0/upload-client-metrics" && r.Method == httpm.POST:
		newHandler[noBodyData](s, w, r, alwaysAllowed).
			handle(s.proxyRequestToLocalAPI)
		return
	}
	http.Error(w, "invalid endpoint", http.StatusNotFound)
}

type authResponse struct {
	ServerMode     ServerMode      `json:"serverMode"`
	Authorized     bool            `json:"authorized"` // has an authorized management session
	ViewerIdentity *viewerIdentity `json:"viewerIdentity,omitempty"`
	NeedsSynoAuth  bool            `json:"needsSynoAuth,omitempty"`
}

// viewerIdentity is the Tailscale identity of the source node
// connected to this web client.
type viewerIdentity struct {
	LoginName     string           `json:"loginName"`
	NodeName      string           `json:"nodeName"`
	NodeIP        string           `json:"nodeIP"`
	ProfilePicURL string           `json:"profilePicUrl,omitempty"`
	Capabilities  peerCapabilities `json:"capabilities"` // features peer is allowed to edit
}

// serverAPIAuth handles requests to the /api/auth endpoint
// and returns an authResponse indicating the current auth state and any steps the user needs to take.
func (s *Server) serveAPIAuth(w http.ResponseWriter, r *http.Request) {
	var resp authResponse
	resp.ServerMode = s.mode
	session, whois, status, sErr := s.getSession(r)
	var caps peerCapabilities

	if whois != nil {
		var err error
		caps, err = toPeerCapabilities(status, whois)
		if err != nil {
			http.Error(w, sErr.Error(), http.StatusInternalServerError)
			return
		}
		resp.ViewerIdentity = &viewerIdentity{
			LoginName:     whois.UserProfile.LoginName,
			NodeName:      whois.Node.Name,
			ProfilePicURL: whois.UserProfile.ProfilePicURL,
			Capabilities:  caps,
		}
		if addrs := whois.Node.Addresses; len(addrs) > 0 {
			resp.ViewerIdentity.NodeIP = addrs[0].Addr().String()
		}
	}

	// First verify platform auth.
	// If platform auth is needed, this should happen first.
	if s.mode == LoginServerMode || s.mode == ReadOnlyServerMode {
		switch distro.Get() {
		case distro.Synology:
			authorized, err := authorizeSynology(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			if !authorized {
				resp.NeedsSynoAuth = true
				writeJSON(w, resp)
				return
			}
		case distro.QNAP:
			if _, err := authorizeQNAP(r); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		default:
			// no additional auth for this distro
		}
	}

	switch {
	case sErr != nil && errors.Is(sErr, errNotUsingTailscale):
		s.lc.IncrementCounter(r.Context(), "web_client_viewing_local", 1)
		resp.Authorized = false // restricted to the readonly view
	case sErr != nil && errors.Is(sErr, errNotOwner):
		s.lc.IncrementCounter(r.Context(), "web_client_viewing_not_owner", 1)
		resp.Authorized = false // restricted to the readonly view
	case sErr != nil && errors.Is(sErr, errTaggedLocalSource):
		s.lc.IncrementCounter(r.Context(), "web_client_viewing_local_tag", 1)
		resp.Authorized = false // restricted to the readonly view
	case sErr != nil && errors.Is(sErr, errTaggedRemoteSource):
		s.lc.IncrementCounter(r.Context(), "web_client_viewing_remote_tag", 1)
		resp.Authorized = false // restricted to the readonly view
	case sErr != nil && !errors.Is(sErr, errNoSession):
		// Any other error.
		http.Error(w, sErr.Error(), http.StatusInternalServerError)
		return
	case session.isAuthorized(s.timeNow()):
		if whois.Node.StableID == status.Self.ID {
			s.lc.IncrementCounter(r.Context(), "web_client_managing_local", 1)
		} else {
			s.lc.IncrementCounter(r.Context(), "web_client_managing_remote", 1)
		}
		// User has a valid session. They're now authorized to edit if they
		// have any edit capabilities. In practice, they won't be sent through
		// the auth flow if they don't have edit caps, but their ACL granted
		// permissions may change at any time. The frontend views and backend
		// endpoints are always restricted to their current capabilities in
		// addition to a valid session.
		//
		// But, we also check the caps here for a better user experience on
		// the frontend login toggle, which uses resp.Authorized to display
		// "viewing" vs "managing" copy. If they don't have caps, we want to
		// display "viewing" even if they have a valid session.
		resp.Authorized = !caps.isEmpty()
	default:
		if whois == nil || (whois.Node.StableID == status.Self.ID) {
			// whois being nil implies local as the request did not come over Tailscale.
			s.lc.IncrementCounter(r.Context(), "web_client_viewing_local", 1)
		} else {
			s.lc.IncrementCounter(r.Context(), "web_client_viewing_remote", 1)
		}
		resp.Authorized = false // not yet authorized
	}

	writeJSON(w, resp)
}

type newSessionAuthResponse struct {
	AuthURL string `json:"authUrl,omitempty"`
}

// serveAPIAuthSessionNew handles requests to the /api/auth/session/new endpoint.
func (s *Server) serveAPIAuthSessionNew(w http.ResponseWriter, r *http.Request) {
	session, whois, _, err := s.getSession(r)
	if err != nil && !errors.Is(err, errNoSession) {
		// Source associated with request not allowed to create
		// a session for this web client.
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if session == nil {
		// Create a new session.
		// If one already existed, we return that authURL rather than creating a new one.
		session, err = s.newSession(r.Context(), whois)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Set the cookie on browser.
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    session.ID,
			Raw:      session.ID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Expires:  session.expires(),
			// We can't set Secure to true because we serve over HTTP
			// (but only on Tailscale IPs, hence over encrypted
			// connections that a LAN-local attacker cannot sniff).
			// In the future, we could support HTTPS requests using
			// the full MagicDNS hostname, and could set this.
			// Secure:  true,
		})
	}

	writeJSON(w, newSessionAuthResponse{AuthURL: session.AuthURL})
}

// serveAPIAuthSessionWait handles requests to the /api/auth/session/wait endpoint.
func (s *Server) serveAPIAuthSessionWait(w http.ResponseWriter, r *http.Request) {
	session, _, _, err := s.getSession(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if session.isAuthorized(s.timeNow()) {
		return // already authorized
	}
	if err := s.awaitUserAuth(r.Context(), session); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
}

type nodeData struct {
	ID          tailcfg.StableNodeID
	Status      string
	DeviceName  string
	TailnetName string // TLS cert name
	DomainName  string
	IPv4        string
	IPv6        string
	OS          string
	IPNVersion  string

	Profile  tailcfg.UserProfile
	IsTagged bool
	Tags     []string

	KeyExpiry  string // time.RFC3339
	KeyExpired bool

	TUNMode     bool
	IsSynology  bool
	DSMVersion  int // 6 or 7, if IsSynology=true
	IsUnraid    bool
	UnraidToken string
	URLPrefix   string // if set, the URL prefix the client is served behind

	UsingExitNode               *exitNode
	AdvertisingExitNode         bool
	AdvertisingExitNodeApproved bool          // whether running this node as an exit node has been approved by an admin
	AdvertisedRoutes            []subnetRoute // excludes exit node routes
	RunningSSHServer            bool

	ClientVersion *tailcfg.ClientVersion

	// whether tailnet ACLs allow access to port 5252 on this device
	ACLAllowsAnyIncomingTraffic bool

	ControlAdminURL string
	LicensesURL     string

	// Features is the set of available features for use on the
	// current platform. e.g. "ssh", "advertise-exit-node", etc.
	// Map value is true if the given feature key is available.
	//
	// See web.availableFeatures func for population of this field.
	// Contents are expected to match values defined in node-data.ts
	// on the frontend.
	Features map[string]bool
}

type subnetRoute struct {
	Route    string
	Approved bool // approved by control server
}

func (s *Server) serveGetNodeData(w http.ResponseWriter, r *http.Request) {
	st, err := s.lc.Status(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	prefs, err := s.lc.GetPrefs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	filterRules, _ := s.lc.DebugPacketFilterRules(r.Context())
	data := &nodeData{
		ID:               st.Self.ID,
		Status:           st.BackendState,
		DeviceName:       strings.Split(st.Self.DNSName, ".")[0],
		OS:               st.Self.OS,
		IPNVersion:       strings.Split(st.Version, "-")[0],
		Profile:          st.User[st.Self.UserID],
		IsTagged:         st.Self.IsTagged(),
		KeyExpired:       st.Self.Expired,
		TUNMode:          st.TUN,
		IsSynology:       distro.Get() == distro.Synology || envknob.Bool("TS_FAKE_SYNOLOGY"),
		DSMVersion:       distro.DSMVersion(),
		IsUnraid:         distro.Get() == distro.Unraid,
		UnraidToken:      os.Getenv("UNRAID_CSRF_TOKEN"),
		RunningSSHServer: prefs.RunSSH,
		URLPrefix:        strings.TrimSuffix(s.pathPrefix, "/"),
		ControlAdminURL:  prefs.AdminPageURL(),
		LicensesURL:      licenses.LicensesURL(),
		Features:         availableFeatures(),

		ACLAllowsAnyIncomingTraffic: s.aclsAllowAccess(filterRules),
	}

	ipv4, ipv6 := s.selfNodeAddresses(r, st)
	data.IPv4 = ipv4.String()
	data.IPv6 = ipv6.String()

	if hostinfo.GetEnvType() == hostinfo.HomeAssistantAddOn && data.URLPrefix == "" {
		// X-Ingress-Path is the path prefix in use for Home Assistant
		// https://developers.home-assistant.io/docs/add-ons/presentation#ingress
		data.URLPrefix = r.Header.Get("X-Ingress-Path")
	}

	cv, err := s.lc.CheckUpdate(r.Context())
	if err != nil {
		s.logf("could not check for updates: %v", err)
	} else {
		data.ClientVersion = cv
	}

	if st.CurrentTailnet != nil {
		data.TailnetName = st.CurrentTailnet.MagicDNSSuffix
		data.DomainName = st.CurrentTailnet.Name
	}
	if st.Self.Tags != nil {
		data.Tags = st.Self.Tags.AsSlice()
	}
	if st.Self.KeyExpiry != nil {
		data.KeyExpiry = st.Self.KeyExpiry.Format(time.RFC3339)
	}

	routeApproved := func(route netip.Prefix) bool {
		if st.Self == nil || st.Self.AllowedIPs == nil {
			return false
		}
		return st.Self.AllowedIPs.ContainsFunc(func(p netip.Prefix) bool {
			return p == route
		})
	}
	data.AdvertisingExitNodeApproved = routeApproved(exitNodeRouteV4) || routeApproved(exitNodeRouteV6)

	for _, r := range prefs.AdvertiseRoutes {
		if r == exitNodeRouteV4 || r == exitNodeRouteV6 {
			data.AdvertisingExitNode = true
		} else {
			data.AdvertisedRoutes = append(data.AdvertisedRoutes, subnetRoute{
				Route:    r.String(),
				Approved: routeApproved(r),
			})
		}
	}
	if e := st.ExitNodeStatus; e != nil {
		data.UsingExitNode = &exitNode{
			ID:     e.ID,
			Online: e.Online,
		}
		for _, ps := range st.Peer {
			if ps.ID == e.ID {
				data.UsingExitNode.Name = ps.DNSName
				data.UsingExitNode.Location = ps.Location
				break
			}
		}
		if data.UsingExitNode.Name == "" {
			// Falling back to TailscaleIP/StableNodeID when the peer
			// is no longer included in status.
			if len(e.TailscaleIPs) > 0 {
				data.UsingExitNode.Name = e.TailscaleIPs[0].Addr().String()
			} else {
				data.UsingExitNode.Name = string(e.ID)
			}
		}
	}
	writeJSON(w, *data)
}

func availableFeatures() map[string]bool {
	env := hostinfo.GetEnvType()
	features := map[string]bool{
		"advertise-exit-node": true, // available on all platforms
		"advertise-routes":    true, // available on all platforms
		"use-exit-node":       canUseExitNode(env) == nil,
		"ssh":                 envknob.CanRunTailscaleSSH() == nil,
		"auto-update":         version.IsUnstableBuild() && clientupdate.CanAutoUpdate(),
	}
	if env == hostinfo.HomeAssistantAddOn {
		// Setting SSH on Home Assistant causes trouble on startup
		// (since the flag is not being passed to `tailscale up`).
		// Although Tailscale SSH does work here,
		// it's not terribly useful since it's running in a separate container.
		features["ssh"] = false
	}
	return features
}

func canUseExitNode(env hostinfo.EnvType) error {
	switch dist := distro.Get(); dist {
	case distro.Synology, // see https://github.com/tailscale/tailscale/issues/1995
		distro.QNAP,
		distro.Unraid:
		return fmt.Errorf("Tailscale exit nodes cannot be used on %s.", dist)
	}
	if env == hostinfo.HomeAssistantAddOn {
		return errors.New("Tailscale exit nodes cannot be used on Home Assistant.")
	}
	return nil
}

// aclsAllowAccess returns whether tailnet ACLs (as expressed in the provided filter rules)
// permit any devices to access the local web client.
// This does not currently check whether a specific device can connect, just any device.
func (s *Server) aclsAllowAccess(rules []tailcfg.FilterRule) bool {
	for _, rule := range rules {
		for _, dp := range rule.DstPorts {
			if dp.Ports.Contains(ListenPort) {
				return true
			}
		}
	}
	return false
}

type exitNode struct {
	ID       tailcfg.StableNodeID
	Name     string
	Location *tailcfg.Location
	Online   bool
}

func (s *Server) serveGetExitNodes(w http.ResponseWriter, r *http.Request) {
	st, err := s.lc.Status(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var exitNodes []*exitNode
	for _, ps := range st.Peer {
		if !ps.ExitNodeOption {
			continue
		}
		exitNodes = append(exitNodes, &exitNode{
			ID:       ps.ID,
			Name:     ps.DNSName,
			Location: ps.Location,
			Online:   ps.Online,
		})
	}
	writeJSON(w, exitNodes)
}

// maskedPrefs is the subset of ipn.MaskedPrefs that are
// allowed to be editable via the web UI.
type maskedPrefs struct {
	RunSSHSet bool
	RunSSH    bool
}

func (s *Server) serveUpdatePrefs(ctx context.Context, prefs maskedPrefs) error {
	_, err := s.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		RunSSHSet: prefs.RunSSHSet,
		Prefs: ipn.Prefs{
			RunSSH: prefs.RunSSH,
		},
	})
	return err
}

type postRoutesRequest struct {
	SetExitNode       bool // when set, UseExitNode and AdvertiseExitNode values are applied
	SetRoutes         bool // when set, AdvertiseRoutes value is applied
	UseExitNode       tailcfg.StableNodeID
	AdvertiseExitNode bool
	AdvertiseRoutes   []string
}

func (s *Server) servePostRoutes(ctx context.Context, data postRoutesRequest) error {
	prefs, err := s.lc.GetPrefs(ctx)
	if err != nil {
		return err
	}
	var currNonExitRoutes []string
	var currAdvertisingExitNode bool
	for _, r := range prefs.AdvertiseRoutes {
		if r == exitNodeRouteV4 || r == exitNodeRouteV6 {
			currAdvertisingExitNode = true
			continue
		}
		currNonExitRoutes = append(currNonExitRoutes, r.String())
	}
	// Set non-edited fields to their current values.
	if data.SetExitNode {
		data.AdvertiseRoutes = currNonExitRoutes
	} else if data.SetRoutes {
		data.AdvertiseExitNode = currAdvertisingExitNode
		data.UseExitNode = prefs.ExitNodeID
	}

	// Calculate routes.
	routesStr := strings.Join(data.AdvertiseRoutes, ",")
	routes, err := netutil.CalcAdvertiseRoutes(routesStr, data.AdvertiseExitNode)
	if err != nil {
		return err
	}

	hasExitNodeRoute := func(all []netip.Prefix) bool {
		return slices.Contains(all, exitNodeRouteV4) ||
			slices.Contains(all, exitNodeRouteV6)
	}

	if !data.UseExitNode.IsZero() && hasExitNodeRoute(routes) {
		return errors.New("cannot use and advertise exit node at same time")
	}

	// Make prefs update.
	p := &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
		ExitNodeIDSet:      true,
		Prefs: ipn.Prefs{
			ExitNodeID:      data.UseExitNode,
			AdvertiseRoutes: routes,
		},
	}
	_, err = s.lc.EditPrefs(ctx, p)
	return err
}

// tailscaleUp starts the daemon with the provided options.
// If reauthentication has been requested, an authURL is returned to complete device registration.
func (s *Server) tailscaleUp(ctx context.Context, st *ipnstate.Status, opt tailscaleUpOptions) (authURL string, retErr error) {
	origAuthURL := st.AuthURL
	isRunning := st.BackendState == ipn.Running.String()

	if !opt.Reauthenticate {
		switch {
		case origAuthURL != "":
			return origAuthURL, nil
		case isRunning:
			return "", nil
		case st.BackendState == ipn.Stopped.String():
			// stopped and not reauthenticating, so just start running
			_, err := s.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					WantRunning: true,
				},
				WantRunningSet: true,
			})
			return "", err
		}
	}

	// printAuthURL reports whether we should print out the
	// provided auth URL from an IPN notify.
	printAuthURL := func(url string) bool {
		return url != origAuthURL
	}

	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	watcher, err := s.lc.WatchIPNBus(watchCtx, 0)
	if err != nil {
		return "", err
	}
	defer watcher.Close()

	go func() {
		if !isRunning {
			ipnOptions := ipn.Options{AuthKey: opt.AuthKey}
			if opt.ControlURL != "" {
				_, err := s.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
					Prefs: ipn.Prefs{
						ControlURL: opt.ControlURL,
					},
					ControlURLSet: true,
				})
				if err != nil {
					s.logf("edit prefs: %v", err)
				}
			}
			if err := s.lc.Start(ctx, ipnOptions); err != nil {
				s.logf("start: %v", err)
			}
		}
		if opt.Reauthenticate {
			if err := s.lc.StartLoginInteractive(ctx); err != nil {
				s.logf("startLogin: %v", err)
			}
		}
	}()

	for {
		n, err := watcher.Next()
		if err != nil {
			return "", err
		}
		if n.State != nil && *n.State == ipn.Running {
			return "", nil
		}
		if n.ErrMessage != nil {
			msg := *n.ErrMessage
			return "", fmt.Errorf("backend error: %v", msg)
		}
		if url := n.BrowseToURL; url != nil && printAuthURL(*url) {
			return *url, nil
		}
	}
}

type tailscaleUpOptions struct {
	// If true, force reauthentication of the client.
	// Otherwise simply reconnect, the same as running `tailscale up`.
	Reauthenticate bool

	ControlURL string
	AuthKey    string
}

// serveTailscaleUp serves requests to /api/up.
// If the user needs to authenticate, an authURL is provided in the response.
func (s *Server) serveTailscaleUp(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	st, err := s.lc.Status(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var opt tailscaleUpOptions
	type mi map[string]any
	if err := json.NewDecoder(r.Body).Decode(&opt); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	s.logf("tailscaleUp(reauth=%v) ...", opt.Reauthenticate)
	url, err := s.tailscaleUp(r.Context(), st, opt)
	s.logf("tailscaleUp = (URL %v, %v)", url != "", err)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}
	if url != "" {
		json.NewEncoder(w).Encode(mi{"url": url})
	} else {
		io.WriteString(w, "{}")
	}
}

// serveDeviceDetailsClick increments the web_client_device_details_click metric
// by one.
//
// Metric logging from the frontend typically is proxied to the localapi. This event
// has been special cased as access to the localapi is gated upon having a valid
// session which is not always the case when we want to be logging this metric (e.g.,
// when in readonly mode).
//
// Other metrics should not be logged in this way without a good reason.
func (s *Server) serveDeviceDetailsClick(w http.ResponseWriter, r *http.Request) {
	s.lc.IncrementCounter(r.Context(), "web_client_device_details_click", 1)

	io.WriteString(w, "{}")
}

// proxyRequestToLocalAPI proxies the web API request to the localapi.
//
// The web API request path is expected to exactly match a localapi path,
// with prefix /api/local/ rather than /localapi/.
func (s *Server) proxyRequestToLocalAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/local")
	if r.URL.Path == path { // missing prefix
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	localAPIURL := "http://" + apitype.LocalAPIHost + "/localapi" + path
	req, err := http.NewRequestWithContext(r.Context(), r.Method, localAPIURL, r.Body)
	if err != nil {
		http.Error(w, "failed to construct request", http.StatusInternalServerError)
		return
	}

	// Make request to tailscaled localapi.
	resp, err := s.lc.DoLocalRequest(req)
	if err != nil {
		http.Error(w, err.Error(), resp.StatusCode)
		return
	}
	defer resp.Body.Close()

	// Send response back to web frontend.
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// csrfKey returns a key that can be used for CSRF protection.
// If an error occurs during key creation, the error is logged and the active process terminated.
// If the server is running in CGI mode, the key is cached to disk and reused between requests.
// If an error occurs during key storage, the error is logged and the active process terminated.
func (s *Server) csrfKey() []byte {
	csrfFile := filepath.Join(os.TempDir(), "tailscale-web-csrf.key")

	// if running in CGI mode, try to read from disk, but ignore errors
	if s.cgiMode {
		key, _ := os.ReadFile(csrfFile)
		if len(key) == 32 {
			return key
		}
	}

	// create a new key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("error generating CSRF key: %v", err)
	}

	// if running in CGI mode, try to write the newly created key to disk, and exit if it fails.
	if s.cgiMode {
		if err := os.WriteFile(csrfFile, key, 0600); err != nil {
			log.Fatalf("unable to store CSRF key: %v", err)
		}
	}

	return key
}

// enforcePrefix returns a HandlerFunc that enforces a given path prefix is used in requests,
// then strips it before invoking h.
// Unlike http.StripPrefix, it does not return a 404 if the prefix is not present.
// Instead, it returns a redirect to the prefix path.
func enforcePrefix(prefix string, h http.HandlerFunc) http.HandlerFunc {
	if prefix == "" {
		return h
	}

	// ensure that prefix always has both a leading and trailing slash so
	// that relative links for JS and CSS assets work correctly.
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.Redirect(w, r, prefix, http.StatusFound)
			return
		}
		prefix = strings.TrimSuffix(prefix, "/")
		http.StripPrefix(prefix, h).ServeHTTP(w, r)
	}
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		w.Header().Set("Content-Type", "text/plain")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
