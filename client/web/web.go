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
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/csrf"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/licenses"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/httpm"
	"tailscale.com/version/distro"
)

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

	// ManageServerMode serves a management client for editing tailscale
	// settings of a node.
	//
	// This mode restricts the app to only being assessible over Tailscale,
	// and API calls are authenticated via browser sessions associated with
	// the source's Tailscale identity. If the source browser does not have
	// a valid session, a readonly version of the app is displayed.
	ManageServerMode ServerMode = "manage"

	// LegacyServerMode serves the legacy web client, visible to users
	// prior to release of tailscale/corp#14335.
	LegacyServerMode ServerMode = "legacy"
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
}

// NewServer constructs a new Tailscale web client server.
// If err is empty, s is always non-nil.
// ctx is only required to live the duration of the NewServer call,
// and not the lifespan of the web server.
func NewServer(opts ServerOpts) (s *Server, err error) {
	switch opts.Mode {
	case LoginServerMode, ManageServerMode, LegacyServerMode:
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
		mode:       opts.Mode,
		logf:       opts.Logf,
		devMode:    envknob.Bool("TS_DEBUG_WEB_CLIENT_DEV"),
		lc:         opts.LocalClient,
		cgiMode:    opts.CGIMode,
		pathPrefix: opts.PathPrefix,
		timeNow:    opts.TimeNow,
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
	if s.mode == LoginServerMode {
		s.apiHandler = csrfProtect(http.HandlerFunc(s.serveLoginAPI))
		metric = "web_login_client_initialization"
	} else {
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
	if s.pathPrefix != "" {
		handler = enforcePrefix(s.pathPrefix, handler)
	}

	handler(w, r)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method == httpm.GET && r.URL.Path == "/api/auth" {
			s.serveAPIAuth(w, r)
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
	if !s.devMode {
		s.lc.IncrementCounter(r.Context(), "web_client_page_load", 1)
	}
	s.assetsHandler.ServeHTTP(w, r)
}

// authorizeRequest reports whether the request from the web client
// is authorized to be completed.
// It reports true if the request is authorized, and false otherwise.
// authorizeRequest manages writing out any relevant authorization
// errors to the ResponseWriter itself.
func (s *Server) authorizeRequest(w http.ResponseWriter, r *http.Request) (ok bool) {
	if s.mode == ManageServerMode { // client using tailscale auth
		_, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
		switch {
		case err != nil:
			// All requests must be made over tailscale.
			http.Error(w, "must access over tailscale", http.StatusUnauthorized)
			return false
		case r.URL.Path == "/api/data" && r.Method == httpm.GET:
			// Readonly endpoint allowed without browser session.
			return true
		case strings.HasPrefix(r.URL.Path, "/api/"):
			// All other /api/ endpoints require a valid browser session.
			//
			// TODO(sonia): s.getSession calls whois again,
			// should try and use the above call instead of running another
			// localapi request.
			session, _, err := s.getSession(r)
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
		resp, _ := authorizeSynology(r)
		return resp.OK
	case distro.QNAP:
		resp, _ := authorizeQNAP(r)
		return resp.OK
	default:
		return true // no additional auth for this distro
	}
}

// serveLoginAPI serves requests for the web login client.
// It should only be called by Server.ServeHTTP, via Server.apiHandler,
// which protects the handler using gorilla csrf.
func (s *Server) serveLoginAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	if r.URL.Path != "/api/data" { // only endpoint allowed for login client
		http.Error(w, "invalid endpoint", http.StatusNotFound)
		return
	}
	switch r.Method {
	case httpm.GET:
		// TODO(soniaappasamy): we may want a minimal node data response here
		s.serveGetNodeData(w, r)
		return
	}
	http.Error(w, "invalid endpoint", http.StatusNotFound)
	return
}

type authType string

var (
	synoAuth      authType = "synology"  // user needs a SynoToken for subsequent API calls
	tailscaleAuth authType = "tailscale" // user needs to complete Tailscale check mode
)

type authResponse struct {
	OK         bool     `json:"ok"`                   // true when user has valid auth session
	AuthURL    string   `json:"authUrl,omitempty"`    // filled when user has control auth action to take
	AuthNeeded authType `json:"authNeeded,omitempty"` // filled when user needs to complete a specific type of auth
}

// serverAPIAuth handles requests to the /api/auth endpoint
// and returns an authResponse indicating the current auth state and any steps the user needs to take.
func (s *Server) serveAPIAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.GET {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var resp authResponse

	session, whois, err := s.getSession(r)
	switch {
	case err != nil && errors.Is(err, errNotUsingTailscale):
		// not using tailscale, so perform platform auth
		switch distro.Get() {
		case distro.Synology:
			resp, err = authorizeSynology(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		case distro.QNAP:
			resp, err = authorizeQNAP(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		default:
			resp.OK = true // no additional auth for this distro
		}
	case err != nil && !errors.Is(err, errNoSession):
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	case session == nil:
		// Create a new session.
		session, err := s.newSession(r.Context(), whois)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Set the cookie on browser.
		http.SetCookie(w, &http.Cookie{
			Name:    sessionCookieName,
			Value:   session.ID,
			Raw:     session.ID,
			Path:    "/",
			Expires: session.expires(),
		})
		resp = authResponse{OK: false, AuthURL: session.AuthURL}
	case !session.isAuthorized(s.timeNow()):
		if r.URL.Query().Get("wait") == "true" {
			// Client requested we block until user completes auth.
			if err := s.awaitUserAuth(r.Context(), session); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		}
		if session.isAuthorized(s.timeNow()) {
			resp = authResponse{OK: true}
		} else {
			resp = authResponse{OK: false, AuthURL: session.AuthURL}
		}
	default:
		resp = authResponse{OK: true}
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
}

// serveAPI serves requests for the web client api.
// It should only be called by Server.ServeHTTP, via Server.apiHandler,
// which protects the handler using gorilla csrf.
func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	path := strings.TrimPrefix(r.URL.Path, "/api")
	switch {
	case path == "/data":
		switch r.Method {
		case httpm.GET:
			s.serveGetNodeData(w, r)
		case httpm.POST:
			s.servePostNodeUpdate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	case strings.HasPrefix(path, "/local/"):
		s.proxyRequestToLocalAPI(w, r)
		return
	}
	http.Error(w, "invalid endpoint", http.StatusNotFound)
}

type nodeData struct {
	Profile           tailcfg.UserProfile
	Status            string
	DeviceName        string
	IP                string
	AdvertiseExitNode bool
	AdvertiseRoutes   string
	LicensesURL       string
	TUNMode           bool
	IsSynology        bool
	DSMVersion        int // 6 or 7, if IsSynology=true
	IsUnraid          bool
	UnraidToken       string
	IPNVersion        string
	DebugMode         string // empty when not running in any debug mode
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
	profile := st.User[st.Self.UserID]
	deviceName := strings.Split(st.Self.DNSName, ".")[0]
	versionShort := strings.Split(st.Version, "-")[0]
	var debugMode string
	if s.mode == ManageServerMode {
		debugMode = "full"
	} else if s.mode == LoginServerMode {
		debugMode = "login"
	}
	data := &nodeData{
		Profile:     profile,
		Status:      st.BackendState,
		DeviceName:  deviceName,
		LicensesURL: licenses.LicensesURL(),
		TUNMode:     st.TUN,
		IsSynology:  distro.Get() == distro.Synology || envknob.Bool("TS_FAKE_SYNOLOGY"),
		DSMVersion:  distro.DSMVersion(),
		IsUnraid:    distro.Get() == distro.Unraid,
		UnraidToken: os.Getenv("UNRAID_CSRF_TOKEN"),
		IPNVersion:  versionShort,
		DebugMode:   debugMode, // TODO(sonia,will): just pass back s.mode directly?
	}
	for _, r := range prefs.AdvertiseRoutes {
		if r == exitNodeRouteV4 || r == exitNodeRouteV6 {
			data.AdvertiseExitNode = true
		} else {
			if data.AdvertiseRoutes != "" {
				data.AdvertiseRoutes += ","
			}
			data.AdvertiseRoutes += r.String()
		}
	}
	if len(st.TailscaleIPs) != 0 {
		data.IP = st.TailscaleIPs[0].String()
	}
	if err := json.NewEncoder(w).Encode(*data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
}

type nodeUpdate struct {
	AdvertiseRoutes   string
	AdvertiseExitNode bool
	Reauthenticate    bool
	ForceLogout       bool
}

func (s *Server) servePostNodeUpdate(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	st, err := s.lc.Status(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var postData nodeUpdate
	type mi map[string]any
	if err := json.NewDecoder(r.Body).Decode(&postData); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}

	prefs, err := s.lc.GetPrefs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	isCurrentlyExitNode := slices.Contains(prefs.AdvertiseRoutes, exitNodeRouteV4) || slices.Contains(prefs.AdvertiseRoutes, exitNodeRouteV6)

	if postData.AdvertiseExitNode != isCurrentlyExitNode {
		if postData.AdvertiseExitNode {
			s.lc.IncrementCounter(r.Context(), "web_client_advertise_exitnode_enable", 1)
		} else {
			s.lc.IncrementCounter(r.Context(), "web_client_advertise_exitnode_disable", 1)
		}
	}

	routes, err := netutil.CalcAdvertiseRoutes(postData.AdvertiseRoutes, postData.AdvertiseExitNode)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}
	mp := &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
		WantRunningSet:     true,
	}
	mp.Prefs.WantRunning = true
	mp.Prefs.AdvertiseRoutes = routes
	s.logf("Doing edit: %v", mp.Pretty())

	if _, err := s.lc.EditPrefs(r.Context(), mp); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	var reauth, logout bool
	if postData.Reauthenticate {
		reauth = true
	}
	if postData.ForceLogout {
		logout = true
	}
	s.logf("tailscaleUp(reauth=%v, logout=%v) ...", reauth, logout)
	url, err := s.tailscaleUp(r.Context(), st, postData)
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

func (s *Server) tailscaleUp(ctx context.Context, st *ipnstate.Status, postData nodeUpdate) (authURL string, retErr error) {
	if postData.ForceLogout {
		if err := s.lc.Logout(ctx); err != nil {
			return "", fmt.Errorf("Logout error: %w", err)
		}
		return "", nil
	}

	origAuthURL := st.AuthURL
	isRunning := st.BackendState == ipn.Running.String()

	forceReauth := postData.Reauthenticate
	if !forceReauth {
		if origAuthURL != "" {
			return origAuthURL, nil
		}
		if isRunning {
			return "", nil
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
			s.lc.Start(ctx, ipn.Options{})
		}
		if forceReauth {
			s.lc.StartLoginInteractive(ctx)
		}
	}()

	for {
		n, err := watcher.Next()
		if err != nil {
			return "", err
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

// proxyRequestToLocalAPI proxies the web API request to the localapi.
//
// The web API request path is expected to exactly match a localapi path,
// with prefix /api/local/ rather than /localapi/.
//
// If the localapi path is not included in localapiAllowlist,
// the request is rejected.
func (s *Server) proxyRequestToLocalAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/local")
	if r.URL.Path == path { // missing prefix
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !slices.Contains(localapiAllowlist, path) {
		http.Error(w, fmt.Sprintf("%s not allowed from localapi proxy", path), http.StatusForbidden)
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

// localapiAllowlist is an allowlist of localapi endpoints the
// web client is allowed to proxy to the client's localapi.
//
// Rather than exposing all localapi endpoints over the proxy,
// this limits to just the ones actually used from the web
// client frontend.
//
// TODO(sonia,will): Shouldn't expand this beyond the existing
// localapi endpoints until the larger web client auth story
// is worked out (tailscale/corp#14335).
var localapiAllowlist = []string{
	"/v0/logout",
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
