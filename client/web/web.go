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
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/httpm"
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
	case LoginServerMode, ManageServerMode:
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
			w.Header().Set("X-Frame-Options", "DENY")
			// TODO: use CSP nonce or hash to eliminate need for unsafe-inline
			w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; img-src * data:")
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
	if !s.devMode {
		s.lc.IncrementCounter(r.Context(), "web_client_page_load", 1)
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

	var ipv4 string // store the first IPv4 address we see for redirect later
	for _, ip := range st.Self.TailscaleIPs {
		if ip.Is4() {
			if r.Host == fmt.Sprintf("%s:%d", ip, ListenPort) {
				return false
			}
			ipv4 = ip.String()
		}
		if ip.Is6() && r.Host == fmt.Sprintf("[%s]:%d", ip, ListenPort) {
			return false
		}
	}
	newURL := *r.URL
	newURL.Host = fmt.Sprintf("%s:%d", ipv4, ListenPort)
	http.Redirect(w, r, newURL.String(), http.StatusMovedPermanently)
	return true
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
	default:
		http.Error(w, "invalid endpoint or method", http.StatusNotFound)
	}
}

type authType string

var (
	synoAuth      authType = "synology"  // user needs a SynoToken for subsequent API calls
	tailscaleAuth authType = "tailscale" // user needs to complete Tailscale check mode
)

type authResponse struct {
	AuthNeeded     authType        `json:"authNeeded,omitempty"` // filled when user needs to complete a specific type of auth
	CanManageNode  bool            `json:"canManageNode"`
	ViewerIdentity *viewerIdentity `json:"viewerIdentity,omitempty"`
}

// viewerIdentity is the Tailscale identity of the source node
// connected to this web client.
type viewerIdentity struct {
	LoginName     string `json:"loginName"`
	NodeName      string `json:"nodeName"`
	NodeIP        string `json:"nodeIP"`
	ProfilePicURL string `json:"profilePicUrl,omitempty"`
}

// serverAPIAuth handles requests to the /api/auth endpoint
// and returns an authResponse indicating the current auth state and any steps the user needs to take.
func (s *Server) serveAPIAuth(w http.ResponseWriter, r *http.Request) {
	var resp authResponse

	session, whois, err := s.getSession(r)
	switch {
	case err != nil && errors.Is(err, errNotUsingTailscale):
		// not using tailscale, so perform platform auth
		switch distro.Get() {
		case distro.Synology:
			authorized, err := authorizeSynology(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			if !authorized {
				resp.AuthNeeded = synoAuth
			}
		case distro.QNAP:
			if _, err := authorizeQNAP(r); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		default:
			// no additional auth for this distro
		}
	case err != nil && (errors.Is(err, errNotOwner) ||
		errors.Is(err, errNotUsingTailscale) ||
		errors.Is(err, errTaggedLocalSource) ||
		errors.Is(err, errTaggedRemoteSource)):
		// These cases are all restricted to the readonly view.
		// No auth action to take.
		resp.AuthNeeded = ""
	case err != nil && !errors.Is(err, errNoSession):
		// Any other error.
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	case session.isAuthorized(s.timeNow()):
		resp.CanManageNode = true
		resp.AuthNeeded = ""
	default:
		resp.AuthNeeded = tailscaleAuth
	}

	if whois != nil {
		resp.ViewerIdentity = &viewerIdentity{
			LoginName:     whois.UserProfile.LoginName,
			NodeName:      whois.Node.Name,
			ProfilePicURL: whois.UserProfile.ProfilePicURL,
		}
		if addrs := whois.Node.Addresses; len(addrs) > 0 {
			resp.ViewerIdentity.NodeIP = addrs[0].Addr().String()
		}
	}
	writeJSON(w, resp)
}

type newSessionAuthResponse struct {
	AuthURL string `json:"authUrl,omitempty"`
}

// serveAPIAuthSessionNew handles requests to the /api/auth/session/new endpoint.
func (s *Server) serveAPIAuthSessionNew(w http.ResponseWriter, r *http.Request) {
	session, whois, err := s.getSession(r)
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
			Name:    sessionCookieName,
			Value:   session.ID,
			Raw:     session.ID,
			Path:    "/",
			Expires: session.expires(),
		})
	}

	writeJSON(w, newSessionAuthResponse{AuthURL: session.AuthURL})
}

// serveAPIAuthSessionWait handles requests to the /api/auth/session/wait endpoint.
func (s *Server) serveAPIAuthSessionWait(w http.ResponseWriter, r *http.Request) {
	session, _, err := s.getSession(r)
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
	case path == "/exit-nodes" && r.Method == httpm.GET:
		s.serveGetExitNodes(w, r)
		return
	case strings.HasPrefix(path, "/local/"):
		s.proxyRequestToLocalAPI(w, r)
		return
	}
	http.Error(w, "invalid endpoint", http.StatusNotFound)
}

type nodeData struct {
	ID          tailcfg.StableNodeID
	Status      string
	DeviceName  string
	TailnetName string // TLS cert name
	DomainName  string
	IP          string // IPv4
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

	ExitNodeStatus    *exitNodeWithStatus
	AdvertiseExitNode bool
	AdvertiseRoutes   string
	RunningSSHServer  bool

	ClientVersion *tailcfg.ClientVersion

	LicensesURL string
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
		LicensesURL:      licenses.LicensesURL(),
	}
	cv, err := s.lc.CheckUpdate(r.Context())
	if err != nil {
		s.logf("could not check for updates: %v", err)
	} else {
		data.ClientVersion = cv
	}
	for _, ip := range st.TailscaleIPs {
		if ip.Is4() {
			data.IP = ip.String()
		} else if ip.Is6() {
			data.IPv6 = ip.String()
		}
		if data.IP != "" && data.IPv6 != "" {
			break
		}
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
	if e := st.ExitNodeStatus; e != nil {
		data.ExitNodeStatus = &exitNodeWithStatus{
			exitNode: exitNode{ID: e.ID},
			Online:   e.Online,
		}
		for _, ps := range st.Peer {
			if ps.ID == e.ID {
				data.ExitNodeStatus.Name = ps.DNSName
				data.ExitNodeStatus.Location = ps.Location
				break
			}
		}
		if data.ExitNodeStatus.Name == "" {
			// Falling back to TailscaleIP/StableNodeID when the peer
			// is no longer included in status.
			if len(e.TailscaleIPs) > 0 {
				data.ExitNodeStatus.Name = e.TailscaleIPs[0].Addr().String()
			} else {
				data.ExitNodeStatus.Name = string(e.ID)
			}
		}
	}
	writeJSON(w, *data)
}

type exitNode struct {
	ID       tailcfg.StableNodeID
	Name     string
	Location *tailcfg.Location
}

type exitNodeWithStatus struct {
	exitNode
	Online bool
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
		})
	}
	writeJSON(w, exitNodes)
}

type nodeUpdate struct {
	AdvertiseRoutes   string
	AdvertiseExitNode bool
}

func (s *Server) servePostNodeUpdate(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

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
	io.WriteString(w, "{}")
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
				ipnOptions.UpdatePrefs = &ipn.Prefs{ControlURL: opt.ControlURL}
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
var localapiAllowlist = []string{
	"/v0/logout",
	"/v0/prefs",
	"/v0/update/check",
	"/v0/update/install",
	"/v0/update/progress",
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
