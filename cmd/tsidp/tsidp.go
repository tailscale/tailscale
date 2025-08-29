// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tsidp command is an OpenID Connect Identity Provider server.
//
// See https://github.com/tailscale/tailscale/issues/10263 for background.
package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"tailscale.com/types/lazy"
	"tailscale.com/types/opt"
	"tailscale.com/types/views"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
	"tailscale.com/util/rands"
	"tailscale.com/version"
)

// ctxConn is a key to look up a net.Conn stored in an HTTP request's context.
type ctxConn struct{}

// funnelClientsFile is the file where client IDs and secrets for OIDC clients
// accessing the IDP over Funnel are persisted.
const funnelClientsFile = "oidc-funnel-clients.json"

// oauthClientsFile is the new file name for OAuth clients when running in secure mode.
const oauthClientsFile = "oauth-clients.json"

// deprecatedFunnelClientsFile is the name used when renaming the old file.
const deprecatedFunnelClientsFile = "deprecated-oidc-funnel-clients.json"

// oidcKeyFile is where the OIDC private key is persisted.
const oidcKeyFile = "oidc-key.json"

var (
	flagVerbose                       = flag.Bool("verbose", false, "be verbose")
	flagPort                          = flag.Int("port", 443, "port to listen on")
	flagLocalPort                     = flag.Int("local-port", -1, "allow requests from localhost")
	flagUseLocalTailscaled            = flag.Bool("use-local-tailscaled", false, "use local tailscaled instead of tsnet")
	flagFunnel                        = flag.Bool("funnel", false, "use Tailscale Funnel to make tsidp available on the public internet")
	flagHostname                      = flag.String("hostname", "idp", "tsnet hostname to use instead of idp")
	flagDir                           = flag.String("dir", "", "tsnet state directory; a default one will be created if not provided")
	flagAllowInsecureRegistrationBool opt.Bool
	flagAllowInsecureRegistration     = opt.BoolFlag{Bool: &flagAllowInsecureRegistrationBool}
)

// getAllowInsecureRegistration returns whether to allow OAuth flows without pre-registered clients.
// Default is true for backward compatibility; explicitly set to false for strict OAuth compliance.
func getAllowInsecureRegistration() bool {
	v, ok := flagAllowInsecureRegistration.Get()
	if !ok {
		// Flag not set, default to true (allow insecure for backward compatibility)
		return true
	}
	return v
}

func main() {
	flag.Var(&flagAllowInsecureRegistration, "allow-insecure-registration", "allow OAuth flows without pre-registered client credentials (default: true for backward compatibility; set to false for strict OAuth compliance)")
	flag.Parse()
	ctx := context.Background()
	if !envknob.UseWIPCode() {
		log.Fatal("cmd/tsidp is a work in progress and has not been security reviewed;\nits use requires TAILSCALE_USE_WIP_CODE=1 be set in the environment for now.")
	}

	var (
		lc          *local.Client
		st          *ipnstate.Status
		rootPath    string
		err         error
		watcherChan chan error
		cleanup     func()

		lns []net.Listener
	)

	if *flagUseLocalTailscaled {
		lc = &local.Client{}
		st, err = lc.StatusWithoutPeers(ctx)
		if err != nil {
			log.Fatalf("getting status: %v", err)
		}
		portStr := fmt.Sprint(*flagPort)
		anySuccess := false
		for _, ip := range st.TailscaleIPs {
			ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), portStr))
			if err != nil {
				log.Printf("failed to listen on %v: %v", ip, err)
				continue
			}
			anySuccess = true
			ln = tls.NewListener(ln, &tls.Config{
				GetCertificate: lc.GetCertificate,
			})
			lns = append(lns, ln)
		}
		if !anySuccess {
			log.Fatalf("failed to listen on any of %v", st.TailscaleIPs)
		}

		if flagDir == nil || *flagDir == "" {
			// use user config directory as storage for tsidp oidc key
			configDir, err := os.UserConfigDir()
			if err != nil {
				log.Fatalf("getting user config directory: %v", err)
			}
			rootPath = filepath.Join(configDir, "tsidp")
		}

		// tailscaled needs to be setting an HTTP header for funneled requests
		// that older versions don't provide.
		// TODO(naman): is this the correct check?
		if *flagFunnel && !version.AtLeast(st.Version, "1.71.0") {
			log.Fatalf("Local tailscaled not new enough to support -funnel. Update Tailscale or use tsnet mode.")
		}
		cleanup, watcherChan, err = serveOnLocalTailscaled(ctx, lc, st, uint16(*flagPort), *flagFunnel)
		if err != nil {
			log.Fatalf("could not serve on local tailscaled: %v", err)
		}
		defer cleanup()
	} else {
		hostinfo.SetApp("tsidp")
		ts := &tsnet.Server{
			Hostname: *flagHostname,
			Dir:      *flagDir,
		}
		if *flagVerbose {
			ts.Logf = log.Printf
		}
		st, err = ts.Up(ctx)
		if err != nil {
			log.Fatal(err)
		}
		lc, err = ts.LocalClient()
		if err != nil {
			log.Fatalf("getting local client: %v", err)
		}
		var ln net.Listener
		if *flagFunnel {
			if err := ipn.CheckFunnelAccess(uint16(*flagPort), st.Self); err != nil {
				log.Fatalf("%v", err)
			}
			ln, err = ts.ListenFunnel("tcp", fmt.Sprintf(":%d", *flagPort))
		} else {
			ln, err = ts.ListenTLS("tcp", fmt.Sprintf(":%d", *flagPort))
		}
		if err != nil {
			log.Fatal(err)
		}
		lns = append(lns, ln)

		rootPath = ts.GetRootPath()
		log.Printf("tsidp root path: %s", rootPath)
	}

	srv := &idpServer{
		lc:                        lc,
		funnel:                    *flagFunnel,
		localTSMode:               *flagUseLocalTailscaled,
		rootPath:                  rootPath,
		allowInsecureRegistration: getAllowInsecureRegistration(),
	}

	if *flagPort != 443 {
		srv.serverURL = fmt.Sprintf("https://%s:%d", strings.TrimSuffix(st.Self.DNSName, "."), *flagPort)
	} else {
		srv.serverURL = fmt.Sprintf("https://%s", strings.TrimSuffix(st.Self.DNSName, "."))
	}

	// If allowInsecureRegistration is enabled, the old oidc-funnel-clients.json path is used.
	// If allowInsecureRegistration is disabled, attempt to migrate the old path to oidc-clients.json and use this new path.
	var clientsFilePath string
	if !srv.allowInsecureRegistration {
		clientsFilePath, err = migrateOAuthClients(rootPath)
		if err != nil {
			log.Fatalf("could not migrate OAuth clients: %v", err)
		}
	} else {
		clientsFilePath, err = getConfigFilePath(rootPath, funnelClientsFile)
		if err != nil {
			log.Fatalf("could not get funnel clients file path: %v", err)
		}
	}

	f, err := os.Open(clientsFilePath)
	if err == nil {
		if err := json.NewDecoder(f).Decode(&srv.funnelClients); err != nil {
			log.Fatalf("could not parse %s: %v", clientsFilePath, err)
		}
		f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("could not open %s: %v", clientsFilePath, err)
	}

	log.Printf("Running tsidp at %s ...", srv.serverURL)

	if *flagLocalPort != -1 {
		log.Printf("Also running tsidp at %s ...", srv.loopbackURL)
		srv.loopbackURL = fmt.Sprintf("http://localhost:%d", *flagLocalPort)
		ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *flagLocalPort))
		if err != nil {
			log.Fatal(err)
		}
		lns = append(lns, ln)
	}

	for _, ln := range lns {
		server := http.Server{
			Handler: srv,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, ctxConn{}, c)
			},
		}
		go server.Serve(ln)
	}
	// need to catch os.Interrupt, otherwise deferred cleanup code doesn't run
	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, os.Interrupt)
	select {
	case <-exitChan:
		log.Printf("interrupt, exiting")
		return
	case <-watcherChan:
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			log.Printf("watcher closed, exiting")
			return
		}
		log.Fatalf("watcher error: %v", err)
		return
	}
}

// serveOnLocalTailscaled starts a serve session using an already-running
// tailscaled instead of starting a fresh tsnet server, making something
// listening on clientDNSName:dstPort accessible over serve/funnel.
func serveOnLocalTailscaled(ctx context.Context, lc *local.Client, st *ipnstate.Status, dstPort uint16, shouldFunnel bool) (cleanup func(), watcherChan chan error, err error) {
	// In order to support funneling out in local tailscaled mode, we need
	// to add a serve config to forward the listeners we bound above and
	// allow those forwarders to be funneled out.
	sc, err := lc.GetServeConfig(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get serve config: %v", err)
	}
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	// We watch the IPN bus just to get a session ID. The session expires
	// when we stop watching the bus, and that auto-deletes the foreground
	// serve/funnel configs we are creating below.
	watcher, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialState|ipn.NotifyNoPrivateKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("could not set up ipn bus watcher: %v", err)
	}
	defer func() {
		if err != nil {
			watcher.Close()
		}
	}()
	n, err := watcher.Next()
	if err != nil {
		return nil, nil, fmt.Errorf("could not get initial state from ipn bus watcher: %v", err)
	}
	if n.SessionID == "" {
		err = fmt.Errorf("missing sessionID in ipn.Notify")
		return nil, nil, err
	}
	watcherChan = make(chan error)
	go func() {
		for {
			_, err = watcher.Next()
			if err != nil {
				watcherChan <- err
				return
			}
		}
	}()

	// Create a foreground serve config that gets cleaned up when tsidp
	// exits and the session ID associated with this config is invalidated.
	foregroundSc := new(ipn.ServeConfig)
	mak.Set(&sc.Foreground, n.SessionID, foregroundSc)
	serverURL := strings.TrimSuffix(st.Self.DNSName, ".")
	fmt.Printf("setting funnel for %s:%v\n", serverURL, dstPort)

	foregroundSc.SetFunnel(serverURL, dstPort, shouldFunnel)
	foregroundSc.SetWebHandler(&ipn.HTTPHandler{
		Proxy: fmt.Sprintf("https://%s", net.JoinHostPort(serverURL, strconv.Itoa(int(dstPort)))),
	}, serverURL, uint16(*flagPort), "/", true, st.CurrentTailnet.MagicDNSSuffix)
	err = lc.SetServeConfig(ctx, sc)
	if err != nil {
		return nil, watcherChan, fmt.Errorf("could not set serve config: %v", err)
	}

	return func() { watcher.Close() }, watcherChan, nil
}

type idpServer struct {
	lc                        *local.Client
	loopbackURL               string
	serverURL                 string // "https://foo.bar.ts.net"
	funnel                    bool
	localTSMode               bool
	rootPath                  string // root path, used for storing state files
	allowInsecureRegistration bool   // If true, allow OAuth without pre-registered clients

	lazyMux        lazy.SyncValue[*http.ServeMux]
	lazySigningKey lazy.SyncValue[*signingKey]
	lazySigner     lazy.SyncValue[jose.Signer]

	mu            sync.Mutex               // guards the fields below
	code          map[string]*authRequest  // keyed by random hex
	accessToken   map[string]*authRequest  // keyed by random hex
	funnelClients map[string]*funnelClient // keyed by client ID
}

type authRequest struct {
	// localRP is true if the request is from a relying party running on the
	// same machine as the idp server. It is mutually exclusive with rpNodeID
	// and funnelRP.
	localRP bool

	// rpNodeID is the NodeID of the relying party (who requested the auth, such
	// as Proxmox or Synology), not the user node who is being authenticated. It
	// is mutually exclusive with localRP and funnelRP.
	rpNodeID tailcfg.NodeID

	// funnelRP is non-nil if the request is from a relying party outside the
	// tailnet, via Tailscale Funnel. It is mutually exclusive with rpNodeID
	// and localRP.
	funnelRP *funnelClient

	// clientID is the "client_id" sent in the authorized request.
	clientID string

	// nonce presented in the request.
	nonce string

	// redirectURI is the redirect_uri presented in the request.
	redirectURI string

	// remoteUser is the user who is being authenticated.
	remoteUser *apitype.WhoIsResponse

	// validTill is the time until which the token is valid.
	// As of 2023-11-14, it is 5 minutes.
	// TODO: add routine to delete expired tokens.
	validTill time.Time
}

// allowRelyingParty validates that a relying party identified either by a
// known remoteAddr or a valid client ID/secret pair is allowed to proceed
// with the authorization flow associated with this authRequest.
func (ar *authRequest) allowRelyingParty(r *http.Request, lc *local.Client) error {
	if ar.localRP {
		ra, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil {
			return err
		}
		if !ra.Addr().IsLoopback() {
			return fmt.Errorf("tsidp: request from non-loopback address")
		}
		return nil
	}
	if ar.funnelRP != nil {
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			clientID = r.FormValue("client_id")
			clientSecret = r.FormValue("client_secret")
		}
		clientIDcmp := subtle.ConstantTimeCompare([]byte(clientID), []byte(ar.funnelRP.ID))
		clientSecretcmp := subtle.ConstantTimeCompare([]byte(clientSecret), []byte(ar.funnelRP.Secret))
		if clientIDcmp != 1 || clientSecretcmp != 1 {
			return fmt.Errorf("tsidp: invalid client credentials")
		}
		return nil
	}
	who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		return fmt.Errorf("tsidp: error getting WhoIs: %w", err)
	}
	if ar.rpNodeID != who.Node.ID {
		return fmt.Errorf("tsidp: token for different node")
	}
	return nil
}

func (s *idpServer) authorize(w http.ResponseWriter, r *http.Request) {

	// This URL is visited by the user who is being authenticated. If they are
	// visiting the URL over Funnel, that means they are not part of the
	// tailnet that they are trying to be authenticated for.
	// NOTE: Funnel request behavior is the same regardless of secure or insecure mode.
	if isFunnelRequest(r) {
		http.Error(w, "tsidp: unauthorized", http.StatusUnauthorized)
		return
	}
	uq := r.URL.Query()

	redirectURI := uq.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "tsidp: must specify redirect_uri", http.StatusBadRequest)
		return
	}

	clientID := uq.Get("client_id")
	if clientID == "" {
		http.Error(w, "tsidp: must specify client_id", http.StatusBadRequest)
		return
	}

	if !s.allowInsecureRegistration {
		// When insecure registration is NOT allowed, validate client_id exists but defer client_secret validation to token endpoint
		// This follows RFC 6749 which specifies client authentication should occur at token endpoint, not authorization endpoint

		s.mu.Lock()
		c, ok := s.funnelClients[clientID]
		s.mu.Unlock()
		if !ok {
			http.Error(w, "tsidp: invalid client ID", http.StatusBadRequest)
			return
		}

		// Validate client_id matches (public identifier validation)
		clientIDcmp := subtle.ConstantTimeCompare([]byte(clientID), []byte(c.ID))
		if clientIDcmp != 1 {
			http.Error(w, "tsidp: invalid client ID", http.StatusBadRequest)
			return
		}

		// Validate redirect URI
		if redirectURI != c.RedirectURI {
			http.Error(w, "tsidp: redirect_uri mismatch", http.StatusBadRequest)
			return
		}

		// Get user information
		var remoteAddr string
		if s.localTSMode {
			remoteAddr = r.Header.Get("X-Forwarded-For")
		} else {
			remoteAddr = r.RemoteAddr
		}

		// Check who is visiting the authorize endpoint.
		var who *apitype.WhoIsResponse
		var err error
		who, err = s.lc.WhoIs(r.Context(), remoteAddr)
		if err != nil {
			log.Printf("Error getting WhoIs: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		code := rands.HexString(32)
		ar := &authRequest{
			nonce:       uq.Get("nonce"),
			remoteUser:  who,
			redirectURI: redirectURI,
			clientID:    clientID,
			funnelRP:    c, // Store the validated client
		}

		s.mu.Lock()
		mak.Set(&s.code, code, ar)
		s.mu.Unlock()

		q := make(url.Values)
		q.Set("code", code)
		if state := uq.Get("state"); state != "" {
			q.Set("state", state)
		}
		parsedURL, err := url.Parse(redirectURI)
		if err != nil {
			http.Error(w, "invalid redirect URI", http.StatusInternalServerError)
			return
		}
		parsedURL.RawQuery = q.Encode()
		u := parsedURL.String()
		log.Printf("Redirecting to %q", u)

		http.Redirect(w, r, u, http.StatusFound)
		return
	}

	var remoteAddr string
	if s.localTSMode {
		// in local tailscaled mode, the local tailscaled is forwarding us
		// HTTP requests, so reading r.RemoteAddr will just get us our own
		// address.
		remoteAddr = r.Header.Get("X-Forwarded-For")
	} else {
		remoteAddr = r.RemoteAddr
	}
	who, err := s.lc.WhoIs(r.Context(), remoteAddr)
	if err != nil {
		log.Printf("Error getting WhoIs: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	code := rands.HexString(32)
	ar := &authRequest{
		nonce:       uq.Get("nonce"),
		remoteUser:  who,
		redirectURI: redirectURI,
		clientID:    clientID,
	}

	if r.URL.Path == "/authorize/funnel" {
		s.mu.Lock()
		c, ok := s.funnelClients[ar.clientID]
		s.mu.Unlock()
		if !ok {
			http.Error(w, "tsidp: invalid client ID", http.StatusBadRequest)
			return
		}
		if ar.redirectURI != c.RedirectURI {
			http.Error(w, "tsidp: redirect_uri mismatch", http.StatusBadRequest)
			return
		}
		ar.funnelRP = c
	} else if r.URL.Path == "/authorize/localhost" {
		ar.localRP = true
	} else {
		var ok bool
		ar.rpNodeID, ok = parseID[tailcfg.NodeID](strings.TrimPrefix(r.URL.Path, "/authorize/"))
		if !ok {
			http.Error(w, "tsidp: invalid node ID suffix after /authorize/", http.StatusBadRequest)
			return
		}
	}

	s.mu.Lock()
	mak.Set(&s.code, code, ar)
	s.mu.Unlock()

	q := make(url.Values)
	q.Set("code", code)
	if state := uq.Get("state"); state != "" {
		q.Set("state", state)
	}
	parsedURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect URI", http.StatusInternalServerError)
		return
	}
	parsedURL.RawQuery = q.Encode()
	u := parsedURL.String()
	log.Printf("Redirecting to %q", u)

	http.Redirect(w, r, u, http.StatusFound)
}

func (s *idpServer) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(oidcJWKSPath, s.serveJWKS)
	mux.HandleFunc(oidcConfigPath, s.serveOpenIDConfig)
	if !s.allowInsecureRegistration {
		// When insecure registration is NOT allowed, use a single /authorize endpoint
		mux.HandleFunc("/authorize", s.authorize)
	} else {
		// When insecure registration is allowed, preserve original behavior with path-based routing
		mux.HandleFunc("/authorize/", s.authorize)
	}
	mux.HandleFunc("/userinfo", s.serveUserInfo)
	mux.HandleFunc("/token", s.serveToken)
	mux.HandleFunc("/clients/", s.serveClients)
	mux.HandleFunc("/", s.handleUI)
	return mux
}

func (s *idpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%v %v", r.Method, r.URL)
	s.lazyMux.Get(s.newMux).ServeHTTP(w, r)
}

func (s *idpServer) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tk, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "tsidp: invalid Authorization header", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	ar, ok := s.accessToken[tk]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "tsidp: invalid token", http.StatusBadRequest)
		return
	}

	if ar.validTill.Before(time.Now()) {
		http.Error(w, "tsidp: token expired", http.StatusBadRequest)
		s.mu.Lock()
		delete(s.accessToken, tk)
		s.mu.Unlock()
		return
	}

	if !s.allowInsecureRegistration {
		// When insecure registration is NOT allowed, validate that the token was issued to a valid client.
		if ar.clientID == "" {
			http.Error(w, "tsidp: no client associated with token", http.StatusBadRequest)
			return
		}

		// Validate client still exists
		s.mu.Lock()
		_, clientExists := s.funnelClients[ar.clientID]
		s.mu.Unlock()
		if !clientExists {
			http.Error(w, "tsidp: client no longer exists", http.StatusUnauthorized)
			return
		}
	}

	ui := userInfo{}
	if ar.remoteUser.Node.IsTagged() {
		http.Error(w, "tsidp: tagged nodes not supported", http.StatusBadRequest)
		return
	}

	ui.Sub = ar.remoteUser.Node.User.String()
	ui.Name = ar.remoteUser.UserProfile.DisplayName
	ui.Email = ar.remoteUser.UserProfile.LoginName
	ui.Picture = ar.remoteUser.UserProfile.ProfilePicURL

	// TODO(maisem): not sure if this is the right thing to do
	ui.UserName, _, _ = strings.Cut(ar.remoteUser.UserProfile.LoginName, "@")

	rules, err := tailcfg.UnmarshalCapJSON[capRule](ar.remoteUser.CapMap, tailcfg.PeerCapabilityTsIDP)
	if err != nil {
		http.Error(w, "tsidp: failed to unmarshal capability: %v", http.StatusBadRequest)
		return
	}

	// Only keep rules where IncludeInUserInfo is true
	var filtered []capRule
	for _, r := range rules {
		if r.IncludeInUserInfo {
			filtered = append(filtered, r)
		}
	}

	userInfo, err := withExtraClaims(ui, filtered)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Write the final result
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type userInfo struct {
	Sub      string `json:"sub"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Picture  string `json:"picture"`
	UserName string `json:"username"`
}

type capRule struct {
	IncludeInUserInfo bool           `json:"includeInUserInfo"`
	ExtraClaims       map[string]any `json:"extraClaims,omitempty"` // list of features peer is allowed to edit
}

// flattenExtraClaims merges all ExtraClaims from a slice of capRule into a single map.
// It deduplicates values for each claim and preserves the original input type:
// scalar values remain scalars, and slices are returned as deduplicated []any slices.
func flattenExtraClaims(rules []capRule) map[string]any {
	// sets stores deduplicated stringified values for each claim key.
	sets := make(map[string]map[string]struct{})

	// isSlice tracks whether each claim was originally provided as a slice.
	isSlice := make(map[string]bool)

	for _, rule := range rules {
		for claim, raw := range rule.ExtraClaims {
			// Track whether the claim was provided as a slice
			switch raw.(type) {
			case []string, []any:
				isSlice[claim] = true
			default:
				// Only mark as scalar if this is the first time we've seen this claim
				if _, seen := isSlice[claim]; !seen {
					isSlice[claim] = false
				}
			}

			// Add the claim value(s) into the deduplication set
			addClaimValue(sets, claim, raw)
		}
	}

	// Build final result: either scalar or slice depending on original type
	result := make(map[string]any)
	for claim, valSet := range sets {
		if isSlice[claim] {
			// Claim was provided as a slice: output as []any
			var vals []any
			for val := range valSet {
				vals = append(vals, val)
			}
			result[claim] = vals
		} else {
			// Claim was a scalar: return a single value
			for val := range valSet {
				result[claim] = val
				break // only one value is expected
			}
		}
	}

	return result
}

// addClaimValue adds a claim value to the deduplication set for a given claim key.
// It accepts scalars (string, int, float64), slices of strings or interfaces,
// and recursively handles nested slices. Unsupported types are ignored with a log message.
func addClaimValue(sets map[string]map[string]struct{}, claim string, val any) {
	switch v := val.(type) {
	case string, float64, int, int64:
		// Ensure the claim set is initialized
		if sets[claim] == nil {
			sets[claim] = make(map[string]struct{})
		}
		// Add the stringified scalar to the set
		sets[claim][fmt.Sprintf("%v", v)] = struct{}{}

	case []string:
		// Ensure the claim set is initialized
		if sets[claim] == nil {
			sets[claim] = make(map[string]struct{})
		}
		// Add each string value to the set
		for _, s := range v {
			sets[claim][s] = struct{}{}
		}

	case []any:
		// Recursively handle each item in the slice
		for _, item := range v {
			addClaimValue(sets, claim, item)
		}

	default:
		// Log unsupported types for visibility and debugging
		log.Printf("Unsupported claim type for %q: %#v (type %T)", claim, val, val)
	}
}

// withExtraClaims merges flattened extra claims from a list of capRule into the provided struct v,
// returning a map[string]any that combines both sources.
//
// v is any struct whose fields represent static claims; it is first marshaled to JSON, then unmarshalled into a generic map.
// rules is a slice of capRule objects that may define additional (extra) claims to merge.
//
// These extra claims are flattened and merged into the base map unless they conflict with protected claims.
// Claims defined in openIDSupportedClaims are considered protected and cannot be overwritten.
// If an extra claim attempts to overwrite a protected claim, an error is returned.
//
// Returns the merged claims map or an error if any protected claim is violated or JSON (un)marshaling fails.
func withExtraClaims(v any, rules []capRule) (map[string]any, error) {
	// Marshal the static struct
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	// Unmarshal into a generic map
	var claimMap map[string]any
	if err := json.Unmarshal(data, &claimMap); err != nil {
		return nil, err
	}

	// Convert views.Slice to a map[string]struct{} for efficient lookup
	protected := make(map[string]struct{}, len(openIDSupportedClaims.AsSlice()))
	for _, claim := range openIDSupportedClaims.AsSlice() {
		protected[claim] = struct{}{}
	}

	// Merge extra claims
	extra := flattenExtraClaims(rules)
	for k, v := range extra {
		if _, isProtected := protected[k]; isProtected {
			log.Printf("Skip overwriting of existing claim %q", k)
			return nil, fmt.Errorf("extra claim %q overwriting existing claim", k)
		}

		claimMap[k] = v
	}

	return claimMap, nil
}

func (s *idpServer) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.FormValue("grant_type") != "authorization_code" {
		http.Error(w, "tsidp: grant_type not supported", http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "tsidp: code is required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	ar, ok := s.code[code]
	if ok {
		delete(s.code, code)
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, "tsidp: code not found", http.StatusBadRequest)
		return
	}

	if !s.allowInsecureRegistration {
		// When insecure registration is NOT allowed, always validate client credentials regardless of request source
		clientID := r.FormValue("client_id")
		clientSecret := r.FormValue("client_secret")

		// Try basic auth if form values are empty
		if clientID == "" || clientSecret == "" {
			if basicClientID, basicClientSecret, ok := r.BasicAuth(); ok {
				if clientID == "" {
					clientID = basicClientID
				}
				if clientSecret == "" {
					clientSecret = basicClientSecret
				}
			}
		}

		if clientID == "" || clientSecret == "" {
			http.Error(w, "tsidp: client credentials required in when insecure registration is not allowed", http.StatusUnauthorized)
			return
		}

		// Validate against the stored auth request
		if ar.clientID != clientID {
			http.Error(w, "tsidp: client_id mismatch", http.StatusBadRequest)
			return
		}

		// Validate client credentials against stored clients
		if ar.funnelRP == nil {
			http.Error(w, "tsidp: no client information found", http.StatusBadRequest)
			return
		}

		clientIDcmp := subtle.ConstantTimeCompare([]byte(clientID), []byte(ar.funnelRP.ID))
		clientSecretcmp := subtle.ConstantTimeCompare([]byte(clientSecret), []byte(ar.funnelRP.Secret))
		if clientIDcmp != 1 || clientSecretcmp != 1 {
			http.Error(w, "tsidp: invalid client credentials", http.StatusUnauthorized)
			return
		}
	} else {
		// Original behavior when insecure registration is allowed
		// Only checks ClientID and Client Secret when over funnel.
		// Local connections are allowed and tailnet connections only check matching nodeIDs.
		if err := ar.allowRelyingParty(r, s.lc); err != nil {
			log.Printf("Error allowing relying party: %v", err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
	}

	if ar.redirectURI != r.FormValue("redirect_uri") {
		http.Error(w, "tsidp: redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	signer, err := s.oidcSigner()
	if err != nil {
		log.Printf("Error getting signer: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jti := rands.HexString(32)
	who := ar.remoteUser

	// TODO(maisem): not sure if this is the right thing to do
	userName, _, _ := strings.Cut(ar.remoteUser.UserProfile.LoginName, "@")
	n := who.Node.View()
	if n.IsTagged() {
		http.Error(w, "tsidp: tagged nodes not supported", http.StatusBadRequest)
		return
	}

	now := time.Now()
	_, tcd, _ := strings.Cut(n.Name(), ".")
	tsClaims := tailscaleClaims{
		Claims: jwt.Claims{
			Audience:  jwt.Audience{ar.clientID},
			Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.serverURL,
			NotBefore: jwt.NewNumericDate(now),
			Subject:   n.User().String(),
		},
		Nonce:     ar.nonce,
		Key:       n.Key(),
		Addresses: n.Addresses(),
		NodeID:    n.ID(),
		NodeName:  n.Name(),
		Tailnet:   tcd,
		UserID:    n.User(),
		Email:     who.UserProfile.LoginName,
		UserName:  userName,
	}
	if ar.localRP {
		tsClaims.Issuer = s.loopbackURL
	}

	rules, err := tailcfg.UnmarshalCapJSON[capRule](who.CapMap, tailcfg.PeerCapabilityTsIDP)
	if err != nil {
		log.Printf("tsidp: failed to unmarshal capability: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tsClaimsWithExtra, err := withExtraClaims(tsClaims, rules)
	if err != nil {
		log.Printf("tsidp: failed to merge extra claims: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create an OIDC token using this issuer's signer.
	token, err := jwt.Signed(signer).Claims(tsClaimsWithExtra).CompactSerialize()
	if err != nil {
		log.Printf("Error getting token: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	at := rands.HexString(32)
	s.mu.Lock()
	ar.validTill = now.Add(5 * time.Minute)
	mak.Set(&s.accessToken, at, ar)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(oidcTokenResponse{
		AccessToken: at,
		TokenType:   "Bearer",
		ExpiresIn:   5 * 60,
		IDToken:     token,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type oidcTokenResponse struct {
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
}

const (
	oidcJWKSPath   = "/.well-known/jwks.json"
	oidcConfigPath = "/.well-known/openid-configuration"
)

func (s *idpServer) oidcSigner() (jose.Signer, error) {
	return s.lazySigner.GetErr(func() (jose.Signer, error) {
		sk, err := s.oidcPrivateKey()
		if err != nil {
			return nil, err
		}
		return jose.NewSigner(jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       sk.k,
		}, &jose.SignerOptions{EmbedJWK: false, ExtraHeaders: map[jose.HeaderKey]any{
			jose.HeaderType: "JWT",
			"kid":           fmt.Sprint(sk.kid),
		}})
	})
}

func (s *idpServer) oidcPrivateKey() (*signingKey, error) {
	return s.lazySigningKey.GetErr(func() (*signingKey, error) {
		keyPath, err := getConfigFilePath(s.rootPath, oidcKeyFile)
		if err != nil {
			return nil, fmt.Errorf("could not get OIDC key file path: %w", err)
		}
		var sk signingKey
		b, err := os.ReadFile(keyPath)
		if err == nil {
			if err := sk.UnmarshalJSON(b); err == nil {
				return &sk, nil
			} else {
				log.Printf("Error unmarshaling key: %v", err)
			}
		}
		id, k := mustGenRSAKey(2048)
		sk.k = k
		sk.kid = id
		b, err = sk.MarshalJSON()
		if err != nil {
			log.Fatalf("Error marshaling key: %v", err)
		}
		if err := os.WriteFile(keyPath, b, 0600); err != nil {
			log.Fatalf("Error writing key: %v", err)
		}
		return &sk, nil
	})
}

func (s *idpServer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != oidcJWKSPath {
		http.Error(w, "tsidp: not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	sk, err := s.oidcPrivateKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// TODO(maisem): maybe only marshal this once and reuse?
	// TODO(maisem): implement key rotation.
	je := json.NewEncoder(w)
	je.SetIndent("", "  ")
	if err := je.Encode(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       sk.k.Public(),
				Algorithm: string(jose.RS256),
				Use:       "sig",
				KeyID:     fmt.Sprint(sk.kid),
			},
		},
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// openIDProviderMetadata is a partial representation of
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata.
type openIDProviderMetadata struct {
	Issuer                           string              `json:"issuer"`
	AuthorizationEndpoint            string              `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                    string              `json:"token_endpoint,omitempty"`
	UserInfoEndpoint                 string              `json:"userinfo_endpoint,omitempty"`
	JWKS_URI                         string              `json:"jwks_uri"`
	ScopesSupported                  views.Slice[string] `json:"scopes_supported"`
	ResponseTypesSupported           views.Slice[string] `json:"response_types_supported"`
	SubjectTypesSupported            views.Slice[string] `json:"subject_types_supported"`
	ClaimsSupported                  views.Slice[string] `json:"claims_supported"`
	IDTokenSigningAlgValuesSupported views.Slice[string] `json:"id_token_signing_alg_values_supported"`
	// TODO(maisem): maybe add other fields?
	// Currently we fill out the REQUIRED fields, scopes_supported and claims_supported.
}

type tailscaleClaims struct {
	jwt.Claims `json:",inline"`
	Nonce      string                    `json:"nonce,omitempty"` // the nonce from the request
	Key        key.NodePublic            `json:"key"`             // the node public key
	Addresses  views.Slice[netip.Prefix] `json:"addresses"`       // the Tailscale IPs of the node
	NodeID     tailcfg.NodeID            `json:"nid"`             // the stable node ID
	NodeName   string                    `json:"node"`            // name of the node
	Tailnet    string                    `json:"tailnet"`         // tailnet (like tail-scale.ts.net)

	// Email is the "emailish" value with an '@' sign. It might not be a valid email.
	Email  string         `json:"email,omitempty"` // user emailish (like "alice@github" or "bob@example.com")
	UserID tailcfg.UserID `json:"uid,omitempty"`

	// UserName is the local part of Email (without '@' and domain).
	// It is a temporary (2023-11-15) hack during development.
	// We should probably let this be configured via grants.
	UserName string `json:"username,omitempty"`
}

var (
	openIDSupportedClaims = views.SliceOf([]string{
		// Standard claims, these correspond to fields in jwt.Claims.
		"sub", "aud", "exp", "iat", "iss", "jti", "nbf", "username", "email",

		// Tailscale claims, these correspond to fields in tailscaleClaims.
		"key", "addresses", "nid", "node", "tailnet", "tags", "user", "uid",
	})

	// As defined in the OpenID spec this should be "openid".
	openIDSupportedScopes = views.SliceOf([]string{"openid", "email", "profile"})

	// We only support getting the id_token.
	openIDSupportedReponseTypes = views.SliceOf([]string{"id_token", "code"})

	// The type of the "sub" field in the JWT, which means it is globally unique identifier.
	// The other option is "pairwise", which means the identifier is different per receiving 3p.
	openIDSupportedSubjectTypes = views.SliceOf([]string{"public"})

	// The algo used for signing. The OpenID spec says "The algorithm RS256 MUST be included."
	// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	openIDSupportedSigningAlgos = views.SliceOf([]string{string(jose.RS256)})
)

func (s *idpServer) serveOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Method", "GET, OPTIONS")
	// allow all to prevent errors from client sending their own bespoke headers
	// and having the server reject the request.
	h.Set("Access-Control-Allow-Headers", "*")

	// early return for pre-flight OPTIONS requests.
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path != oidcConfigPath {
		http.Error(w, "tsidp: not found", http.StatusNotFound)
		return
	}

	var authorizeEndpoint string
	rpEndpoint := s.serverURL

	if !s.allowInsecureRegistration {
		// When insecure registration is NOT allowed, use a single authorization endpoint for all request types
		// This will be the same regardless of if the user is on localhost, tailscale, or funnel.
		authorizeEndpoint = fmt.Sprintf("%s/authorize", s.serverURL)
		rpEndpoint = s.serverURL
	} else {
		// When insecure registration is allowed TSIDP uses the requestors nodeID
		// (typically that of the resource server during auto discovery) when on the tailnet
		// and adds it to the authorize URL as a replacement clientID for when the user authorizes.
		// The behavior over funnel drops the nodeID & clientID replacement behvaior and does require a
		// previously created clientID and client secret.
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil {
			log.Printf("Error parsing remote addr: %v", err)
			return
		}
		if isFunnelRequest(r) {
			authorizeEndpoint = fmt.Sprintf("%s/authorize/funnel", s.serverURL)
		} else if who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr); err == nil {
			authorizeEndpoint = fmt.Sprintf("%s/authorize/%d", s.serverURL, who.Node.ID)
		} else if ap.Addr().IsLoopback() {
			rpEndpoint = s.loopbackURL
			authorizeEndpoint = fmt.Sprintf("%s/authorize/localhost", s.serverURL)
		} else {
			log.Printf("Error getting WhoIs: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	je := json.NewEncoder(w)
	je.SetIndent("", "  ")
	if err := je.Encode(openIDProviderMetadata{
		AuthorizationEndpoint:            authorizeEndpoint,
		Issuer:                           rpEndpoint,
		JWKS_URI:                         rpEndpoint + oidcJWKSPath,
		UserInfoEndpoint:                 rpEndpoint + "/userinfo",
		TokenEndpoint:                    rpEndpoint + "/token",
		ScopesSupported:                  openIDSupportedScopes,
		ResponseTypesSupported:           openIDSupportedReponseTypes,
		SubjectTypesSupported:            openIDSupportedSubjectTypes,
		ClaimsSupported:                  openIDSupportedClaims,
		IDTokenSigningAlgValuesSupported: openIDSupportedSigningAlgos,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// funnelClient represents an OIDC client/relying party that is accessing the
// IDP over Funnel.
type funnelClient struct {
	ID          string `json:"client_id"`
	Secret      string `json:"client_secret,omitempty"`
	Name        string `json:"name,omitempty"`
	RedirectURI string `json:"redirect_uri"`
}

// /clients is a privileged endpoint that allows the visitor to create new
// Funnel-capable OIDC clients, so it is only accessible over the tailnet.
func (s *idpServer) serveClients(w http.ResponseWriter, r *http.Request) {
	if isFunnelRequest(r) {
		http.Error(w, "tsidp: not found", http.StatusNotFound)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/clients/")

	if path == "new" {
		s.serveNewClient(w, r)
		return
	}

	if path == "" {
		s.serveGetClientsList(w, r)
		return
	}

	s.mu.Lock()
	c, ok := s.funnelClients[path]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "tsidp: not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case "DELETE":
		s.serveDeleteClient(w, r, path)
	case "GET":
		json.NewEncoder(w).Encode(&funnelClient{
			ID:          c.ID,
			Name:        c.Name,
			Secret:      "",
			RedirectURI: c.RedirectURI,
		})
	default:
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *idpServer) serveNewClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "tsidp: must provide redirect_uri", http.StatusBadRequest)
		return
	}
	clientID := rands.HexString(32)
	clientSecret := rands.HexString(64)
	newClient := funnelClient{
		ID:          clientID,
		Secret:      clientSecret,
		Name:        r.FormValue("name"),
		RedirectURI: redirectURI,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	mak.Set(&s.funnelClients, clientID, &newClient)
	if err := s.storeFunnelClientsLocked(); err != nil {
		log.Printf("could not write funnel clients db: %v", err)
		http.Error(w, "tsidp: could not write funnel clients to db", http.StatusInternalServerError)
		// delete the new client to avoid inconsistent state between memory
		// and disk
		delete(s.funnelClients, clientID)
		return
	}
	json.NewEncoder(w).Encode(newClient)
}

func (s *idpServer) serveGetClientsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	redactedClients := make([]funnelClient, 0, len(s.funnelClients))
	for _, c := range s.funnelClients {
		redactedClients = append(redactedClients, funnelClient{
			ID:          c.ID,
			Name:        c.Name,
			Secret:      "",
			RedirectURI: c.RedirectURI,
		})
	}
	s.mu.Unlock()
	json.NewEncoder(w).Encode(redactedClients)
}

func (s *idpServer) serveDeleteClient(w http.ResponseWriter, r *http.Request, clientID string) {
	if r.Method != "DELETE" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.funnelClients == nil {
		http.Error(w, "tsidp: client not found", http.StatusNotFound)
		return
	}
	if _, ok := s.funnelClients[clientID]; !ok {
		http.Error(w, "tsidp: client not found", http.StatusNotFound)
		return
	}
	deleted := s.funnelClients[clientID]
	delete(s.funnelClients, clientID)
	if err := s.storeFunnelClientsLocked(); err != nil {
		log.Printf("could not write funnel clients db: %v", err)
		http.Error(w, "tsidp: could not write funnel clients to db", http.StatusInternalServerError)
		// restore the deleted value to avoid inconsistent state between memory
		// and disk
		s.funnelClients[clientID] = deleted
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// storeFunnelClientsLocked writes the current mapping of OIDC client ID/secret
// pairs for RPs that access the IDP. When insecure registration is NOT allowed, uses oauth-clients.json;
// otherwise uses oidc-funnel-clients.json. s.mu must be held while calling this.
func (s *idpServer) storeFunnelClientsLocked() error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(s.funnelClients); err != nil {
		return err
	}

	var clientsFilePath string
	var err error
	if !s.allowInsecureRegistration {
		clientsFilePath, err = getConfigFilePath(s.rootPath, oauthClientsFile)
	} else {
		clientsFilePath, err = getConfigFilePath(s.rootPath, funnelClientsFile)
	}

	if err != nil {
		return fmt.Errorf("storeFunnelClientsLocked: %v", err)
	}

	return os.WriteFile(clientsFilePath, buf.Bytes(), 0600)
}

const (
	minimumRSAKeySize = 2048
)

// mustGenRSAKey generates a new RSA key with the provided number of bits. It
// panics on failure. bits must be at least minimumRSAKeySizeBytes * 8.
func mustGenRSAKey(bits int) (kid uint64, k *rsa.PrivateKey) {
	if bits < minimumRSAKeySize {
		panic("request to generate a too-small RSA key")
	}
	kid = must.Get(readUint64(crand.Reader))
	k = must.Get(rsa.GenerateKey(crand.Reader, bits))
	return
}

// readUint64 reads from r until 8 bytes represent a non-zero uint64.
func readUint64(r io.Reader) (uint64, error) {
	for {
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		if v := binary.BigEndian.Uint64(b[:]); v != 0 {
			return v, nil
		}
	}
}

// rsaPrivateKeyJSONWrapper is the the JSON serialization
// format used by RSAPrivateKey.
type rsaPrivateKeyJSONWrapper struct {
	Key string
	ID  uint64
}

type signingKey struct {
	k   *rsa.PrivateKey
	kid uint64
}

func (sk *signingKey) MarshalJSON() ([]byte, error) {
	b := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(sk.k),
	}
	bts := pem.EncodeToMemory(&b)
	return json.Marshal(rsaPrivateKeyJSONWrapper{
		Key: base64.URLEncoding.EncodeToString(bts),
		ID:  sk.kid,
	})
}

func (sk *signingKey) UnmarshalJSON(b []byte) error {
	var wrapper rsaPrivateKeyJSONWrapper
	if err := json.Unmarshal(b, &wrapper); err != nil {
		return err
	}
	if len(wrapper.Key) == 0 {
		return nil
	}
	b64dec, err := base64.URLEncoding.DecodeString(wrapper.Key)
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(b64dec)
	k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return err
	}
	sk.k = k
	sk.kid = wrapper.ID
	return nil
}

// parseID takes a string input and returns a typed IntID T and true, or a zero
// value and false if the input is unhandled syntax or out of a valid range.
func parseID[T ~int64](input string) (_ T, ok bool) {
	if input == "" {
		return 0, false
	}
	i, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return 0, false
	}
	if i < 0 {
		return 0, false
	}
	return T(i), true
}

// isFunnelRequest checks if an HTTP request is coming over Tailscale Funnel.
func isFunnelRequest(r *http.Request) bool {
	// If we're funneling through the local tailscaled, it will set this HTTP
	// header.
	if r.Header.Get("Tailscale-Funnel-Request") != "" {
		return true
	}

	// If the funneled connection is from tsnet, then the net.Conn will be of
	// type ipn.FunnelConn.
	netConn := r.Context().Value(ctxConn{})
	// if the conn is wrapped inside TLS, unwrap it
	if tlsConn, ok := netConn.(*tls.Conn); ok {
		netConn = tlsConn.NetConn()
	}
	if _, ok := netConn.(*ipn.FunnelConn); ok {
		return true
	}
	return false
}

// migrateOAuthClients migrates from oidc-funnel-clients.json to oauth-clients.json.
// If oauth-clients.json already exists, no migration is performed.
// If both files are missing a new configuration is created.
// The path to the new configuration file is returned.
func migrateOAuthClients(rootPath string) (string, error) {
	// First, check for oauth-clients.json (new file)
	oauthPath, err := getConfigFilePath(rootPath, oauthClientsFile)
	if err != nil {
		return "", fmt.Errorf("could not get oauth clients file path: %w", err)
	}
	if _, err := os.Stat(oauthPath); err == nil {
		// oauth-clients.json already exists, use it
		return oauthPath, nil
	}

	// Check for old oidc-funnel-clients.json
	oldPath, err := getConfigFilePath(rootPath, funnelClientsFile)
	if err != nil {
		return "", fmt.Errorf("could not get funnel clients file path: %w", err)
	}
	if _, err := os.Stat(oldPath); err == nil {
		// Old file exists, migrate it
		log.Printf("Migrating OAuth clients from %s to %s", oldPath, oauthPath)

		// Read the old file
		data, err := os.ReadFile(oldPath)
		if err != nil {
			return "", fmt.Errorf("could not read old funnel clients file: %w", err)
		}

		// Write to new location
		if err := os.WriteFile(oauthPath, data, 0600); err != nil {
			return "", fmt.Errorf("could not write new oauth clients file: %w", err)
		}

		// Rename old file to deprecated name
		deprecatedPath, err := getConfigFilePath(rootPath, deprecatedFunnelClientsFile)
		if err != nil {
			return "", fmt.Errorf("could not get deprecated file path: %w", err)
		}
		if err := os.Rename(oldPath, deprecatedPath); err != nil {
			log.Printf("Warning: could not rename old file to deprecated name: %v", err)
		} else {
			log.Printf("Renamed old file to %s", deprecatedPath)
		}

		return oauthPath, nil
	}

	// Neither file exists, create empty oauth-clients.json
	log.Printf("Creating empty OAuth clients file at %s", oauthPath)
	if err := os.WriteFile(oauthPath, []byte("{}"), 0600); err != nil {
		return "", fmt.Errorf("could not create empty oauth clients file: %w", err)
	}

	return oauthPath, nil
}

// getConfigFilePath returns the path to the config file for the given file name.
// The oidc-key.json and funnel-clients.json files were originally opened and written
// to without paths, and ended up in /root or home directory of the user running
// the process. To maintain backward compatibility, we return the naked file name if that
// file exists already, otherwise we return the full path in the rootPath.
func getConfigFilePath(rootPath string, fileName string) (string, error) {
	if _, err := os.Stat(fileName); err == nil {
		return fileName, nil
	} else if errors.Is(err, os.ErrNotExist) {
		return filepath.Join(rootPath, fileName), nil
	} else {
		return "", err
	}
}
