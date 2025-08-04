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
	"crypto/sha256"
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

var (
	flagVerbose            = flag.Bool("verbose", false, "be verbose")
	flagPort               = flag.Int("port", 443, "port to listen on")
	flagLocalPort          = flag.Int("local-port", -1, "allow requests from localhost")
	flagUseLocalTailscaled = flag.Bool("use-local-tailscaled", false, "use local tailscaled instead of tsnet")
	flagFunnel             = flag.Bool("funnel", false, "use Tailscale Funnel to make tsidp available on the public internet")
	flagHostname           = flag.String("hostname", "idp", "tsnet hostname to use instead of idp")
	flagDir                = flag.String("dir", "", "tsnet state directory; a default one will be created if not provided")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	if !envknob.UseWIPCode() {
		log.Fatal("cmd/tsidp is a work in progress and has not been security reviewed;\nits use requires TAILSCALE_USE_WIP_CODE=1 be set in the environment for now.")
	}

	var (
		lc          *local.Client
		st          *ipnstate.Status
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
	}

	srv := &idpServer{
		lc:          lc,
		funnel:      *flagFunnel,
		localTSMode: *flagUseLocalTailscaled,
	}
	if *flagPort != 443 {
		srv.serverURL = fmt.Sprintf("https://%s:%d", strings.TrimSuffix(st.Self.DNSName, "."), *flagPort)
	} else {
		srv.serverURL = fmt.Sprintf("https://%s", strings.TrimSuffix(st.Self.DNSName, "."))
	}

	// Load funnel clients from disk if they exist, regardless of whether funnel is enabled
	// This ensures OIDC clients persist across restarts
	f, err := os.Open(funnelClientsFile)
	if err == nil {
		if err := json.NewDecoder(f).Decode(&srv.funnelClients); err != nil {
			log.Fatalf("could not parse %s: %v", funnelClientsFile, err)
		}
		f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("could not open %s: %v", funnelClientsFile, err)
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

	// Start token cleanup routine
	cleanupCtx, cleanupCancel := context.WithCancel(ctx)
	defer cleanupCancel()

	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				srv.cleanupExpiredTokens()
				if *flagVerbose {
					log.Printf("Cleaned up expired tokens")
				}
			case <-cleanupCtx.Done():
				return
			}
		}
	}()

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
	lc          *local.Client
	loopbackURL string
	serverURL   string // "https://foo.bar.ts.net"
	funnel      bool
	localTSMode bool

	lazyMux        lazy.SyncValue[*http.ServeMux]
	lazySigningKey lazy.SyncValue[*signingKey]
	lazySigner     lazy.SyncValue[jose.Signer]

	mu            sync.Mutex               // guards the fields below
	code          map[string]*authRequest  // keyed by random hex
	accessToken   map[string]*authRequest  // keyed by random hex
	refreshToken  map[string]*authRequest  // keyed by random hex
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

	// resources are the resource URIs from RFC 8707 that the client is
	// requesting access to. These are validated at token issuance time.
	resources []string

	// scopes are the OAuth 2.0 scopes requested by the client.
	// These are validated against supported scopes at authorization time.
	scopes []string

	// codeChallenge is the PKCE code challenge from RFC 7636.
	// It is a derived value from the code_verifier that the client
	// will send during token exchange.
	codeChallenge string

	// codeChallengeMethod is the method used to derive codeChallenge
	// from the code_verifier. Valid values are "plain" and "S256".
	// If empty, PKCE is not used for this request.
	codeChallengeMethod string

	// remoteUser is the user who is being authenticated.
	remoteUser *apitype.WhoIsResponse

	// validTill is the time until which the token is valid.
	// Authorization codes expire after 5 minutes per OAuth 2.0 best practices (RFC 6749 recommends max 10 minutes).
	validTill time.Time
}

// validateScopes checks if the requested scopes are valid and supported.
// It returns the validated scopes or an error if any scope is unsupported.
func (s *idpServer) validateScopes(requestedScopes []string) ([]string, error) {
	if len(requestedScopes) == 0 {
		// Default to openid scope if none specified
		return []string{"openid"}, nil
	}

	validatedScopes := make([]string, 0, len(requestedScopes))
	supportedScopes := openIDSupportedScopes.AsSlice()

	for _, scope := range requestedScopes {
		supported := false
		for _, supportedScope := range supportedScopes {
			if scope == supportedScope {
				supported = true
				break
			}
		}
		if !supported {
			return nil, fmt.Errorf("unsupported scope: %q", scope)
		}
		validatedScopes = append(validatedScopes, scope)
	}

	return validatedScopes, nil
}

// validateResourcesForUser checks if the user is allowed to access the requested resources
func (s *idpServer) validateResourcesForUser(who *apitype.WhoIsResponse, requestedResources []string) ([]string, error) {
	// Check ACL grant using the same capability as we would use for STS token exchange
	rules, err := tailcfg.UnmarshalCapJSON[stsCapRule](who.CapMap, "test-tailscale.com/idp/sts/openly-allow")
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal capability: %w", err)
	}

	// Filter resources based on what the user is allowed to access
	var allowedResources []string
	for _, resource := range requestedResources {
		allowed := false
		for _, rule := range rules {
			// Check if user matches (support wildcard or specific user)
			userMatches := false
			for _, user := range rule.Users {
				if user == "*" || user == who.UserProfile.LoginName {
					userMatches = true
					break
				}
			}

			if userMatches {
				// Check if resource matches
				for _, allowedResource := range rule.Resources {
					if allowedResource == resource || allowedResource == "*" {
						allowed = true
						break
					}
				}
			}

			if allowed {
				break
			}
		}

		if allowed {
			allowedResources = append(allowedResources, resource)
		}
	}

	if len(allowedResources) == 0 && len(requestedResources) > 0 {
		return nil, fmt.Errorf("access denied for requested resources")
	}

	return allowedResources, nil
}

// validateCodeVerifier validates that a code_verifier matches the stored code_challenge
// using the specified method, as defined in RFC 7636.
func validateCodeVerifier(verifier, challenge, method string) error {
	// Validate code_verifier format (43-128 characters, unreserved characters only)
	if len(verifier) < 43 || len(verifier) > 128 {
		return fmt.Errorf("code_verifier must be 43-128 characters")
	}

	// Check that verifier only contains unreserved characters: A-Z a-z 0-9 - . _ ~
	for _, r := range verifier {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '.' || r == '_' || r == '~') {
			return fmt.Errorf("code_verifier contains invalid characters")
		}
	}

	// Generate the challenge from the verifier and compare
	generatedChallenge, err := generateCodeChallenge(verifier, method)
	if err != nil {
		return err
	}

	if generatedChallenge != challenge {
		return fmt.Errorf("invalid code_verifier")
	}

	return nil
}

// generateCodeChallenge creates a code challenge from a code verifier using the specified method.
// Supports "plain" and "S256" methods as defined in RFC 7636.
func generateCodeChallenge(verifier, method string) (string, error) {
	switch method {
	case "plain":
		return verifier, nil
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(h[:]), nil
	default:
		return "", fmt.Errorf("unsupported code_challenge_method: %s", method)
	}
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
	if isFunnelRequest(r) {
		http.Error(w, "tsidp: unauthorized", http.StatusUnauthorized)
		return
	}

	uq := r.URL.Query()
	state := uq.Get("state")

	redirectURI := uq.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "tsidp: must specify redirect_uri", http.StatusBadRequest)
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
		redirectAuthError(w, r, redirectURI, "server_error", "internal server error", state)
		return
	}

	code := rands.HexString(32)
	ar := &authRequest{
		nonce:       uq.Get("nonce"),
		remoteUser:  who,
		redirectURI: redirectURI,
		clientID:    uq.Get("client_id"),
		resources:   uq["resource"], // RFC 8707: multiple resource parameters are allowed
	}

	// Parse space-delimited scopes
	if scopeParam := uq.Get("scope"); scopeParam != "" {
		ar.scopes = strings.Fields(scopeParam)
	}

	// Validate scopes
	validatedScopes, err := s.validateScopes(ar.scopes)
	if err != nil {
		redirectAuthError(w, r, redirectURI, "invalid_scope", fmt.Sprintf("invalid scope: %v", err), state)
		return
	}
	ar.scopes = validatedScopes

	// Handle PKCE parameters (RFC 7636)
	if codeChallenge := uq.Get("code_challenge"); codeChallenge != "" {
		ar.codeChallenge = codeChallenge

		// code_challenge_method defaults to "plain" if not specified
		ar.codeChallengeMethod = uq.Get("code_challenge_method")
		if ar.codeChallengeMethod == "" {
			ar.codeChallengeMethod = "plain"
		}

		// Validate the code_challenge_method
		if ar.codeChallengeMethod != "plain" && ar.codeChallengeMethod != "S256" {
			redirectAuthError(w, r, redirectURI, "invalid_request", "unsupported code_challenge_method", state)
			return
		}
	}

	if r.URL.Path == "/authorize/funnel" {
		s.mu.Lock()
		c, ok := s.funnelClients[ar.clientID]
		s.mu.Unlock()
		if !ok {
			redirectAuthError(w, r, redirectURI, "invalid_request", "invalid client ID", state)
			return
		}
		// Validate redirect_uri against the client's registered redirect URIs
		validRedirect := false
		for _, uri := range c.RedirectURIs {
			if ar.redirectURI == uri {
				validRedirect = true
				break
			}
		}
		if !validRedirect {
			redirectAuthError(w, r, redirectURI, "invalid_request", "redirect_uri mismatch", state)
			return
		}
		ar.funnelRP = c
	} else if r.URL.Path == "/authorize/localhost" {
		ar.localRP = true
	} else {
		var ok bool
		ar.rpNodeID, ok = parseID[tailcfg.NodeID](strings.TrimPrefix(r.URL.Path, "/authorize/"))
		if !ok {
			redirectAuthError(w, r, redirectURI, "invalid_request", "invalid node ID suffix after /authorize/", state)
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
	u := redirectURI + "?" + q.Encode()
	log.Printf("Redirecting to %q", u)

	http.Redirect(w, r, u, http.StatusFound)
}

func (s *idpServer) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(oidcJWKSPath, s.serveJWKS)
	mux.HandleFunc(oidcConfigPath, s.serveOpenIDConfig)
	mux.HandleFunc(oauthMetadataPath, s.serveOAuthMetadata)
	mux.HandleFunc("/authorize/", s.authorize)
	mux.HandleFunc("/userinfo", s.serveUserInfo)
	mux.HandleFunc("/token", s.serveToken)
	mux.HandleFunc("/introspect", s.serveIntrospect)
	mux.HandleFunc("/register", s.serveDynamicClientRegistration)
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
		writeBearerError(w, http.StatusBadRequest, "invalid_request", "invalid Authorization header")
		return
	}

	s.mu.Lock()
	ar, ok := s.accessToken[tk]
	s.mu.Unlock()
	if !ok {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "invalid token")
		return
	}

	if ar.validTill.Before(time.Now()) {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "token expired")
		s.mu.Lock()
		delete(s.accessToken, tk)
		s.mu.Unlock()
		return
	}

	ui := userInfo{}
	if ar.remoteUser.Node.IsTagged() {
		http.Error(w, "tsidp: tagged nodes not supported", http.StatusBadRequest)
		return
	}

	// Sub is always included (openid scope is mandatory)
	ui.Sub = ar.remoteUser.Node.User.String()
	
	// Check scopes and only include claims that were authorized
	for _, scope := range ar.scopes {
		switch scope {
		case "profile":
			ui.Name = ar.remoteUser.UserProfile.DisplayName
			ui.Picture = ar.remoteUser.UserProfile.ProfilePicURL
			if username, _, ok := strings.Cut(ar.remoteUser.UserProfile.LoginName, "@"); ok {
				ui.PreferredUsername = username
			}
		case "email":
			ui.Email = ar.remoteUser.UserProfile.LoginName
		}
	}

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
	Sub                string `json:"sub"`
	Name               string `json:"name,omitempty"`
	Email              string `json:"email,omitempty"`
	Picture            string `json:"picture,omitempty"`
	PreferredUsername  string `json:"preferred_username,omitempty"`
}

type capRule struct {
	IncludeInUserInfo bool           `json:"includeInUserInfo"`
	ExtraClaims       map[string]any `json:"extraClaims,omitempty"` // list of features peer is allowed to edit
}

// stsCapRule represents a capability rule for future STS token exchange and (current) resource indicators.
// It defines which users are allowed to exchange tokens for which audiences/resources.
// This is used with the ACL capability key "tailscale.com/idp/sts/openly-allow".
type stsCapRule struct {
	Users     []string `json:"users"`     // list of users allowed to access resources (supports "*" wildcard)
	Resources []string `json:"resources"` // list of audience/resource URIs the user can access
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

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r)
	default:
		writeTokenEndpointError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func (s *idpServer) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == "" {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	s.mu.Lock()
	ar, ok := s.code[code]
	if ok {
		delete(s.code, code)
	}
	s.mu.Unlock()
	if !ok {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_grant", "code not found")
		return
	}
	if err := ar.allowRelyingParty(r, s.lc); err != nil {
		log.Printf("Error allowing relying party: %v", err)
		writeTokenEndpointError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	if ar.redirectURI != r.FormValue("redirect_uri") {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// PKCE validation (RFC 7636)
	if ar.codeChallenge != "" {
		codeVerifier := r.FormValue("code_verifier")
		if codeVerifier == "" {
			writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "code_verifier is required")
			return
		}

		if err := validateCodeVerifier(codeVerifier, ar.codeChallenge, ar.codeChallengeMethod); err != nil {
			writeTokenEndpointError(w, http.StatusBadRequest, "invalid_grant", err.Error())
			return
		}
	}

	// RFC 8707: Check for resource parameter in token request
	resources := r.Form["resource"]
	if len(resources) > 0 {
		// Validate requested resources using the same capability would be used for STS
		validatedResources, err := s.validateResourcesForUser(ar.remoteUser, resources)
		if err != nil {
			log.Printf("Error validating resources: %v", err)
			writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "invalid resource")
			return
		}
		ar.resources = validatedResources
	}
	// If no resources in token request, use the ones from authorization

	s.issueTokens(w, ar)
}

func (s *idpServer) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	rt := r.FormValue("refresh_token")
	if rt == "" {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	s.mu.Lock()
	ar, ok := s.refreshToken[rt]
	if ok && ar.validTill.Before(time.Now()) {
		// Token expired, remove it
		delete(s.refreshToken, rt)
		ok = false
	}
	s.mu.Unlock()

	if !ok {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	}

	// Validate client authentication
	if err := ar.allowRelyingParty(r, s.lc); err != nil {
		log.Printf("Error allowing relying party: %v", err)
		writeTokenEndpointError(w, http.StatusUnauthorized, "invalid_client", "")
		return
	}

	// RFC 8707: Check for resource parameter in refresh token request
	resources := r.Form["resource"]
	if len(resources) > 0 {
		// Validate requested resources are a subset of original grant
		validatedResources, err := s.validateResourcesForUser(ar.remoteUser, resources)
		if err != nil {
			log.Printf("Error validating resources: %v", err)
			writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "invalid resource")
			return
		}

		// Ensure requested resources are subset of original grant
		if len(ar.resources) > 0 {
			for _, requested := range validatedResources {
				found := false
				for _, allowed := range ar.resources {
					if requested == allowed {
						found = true
						break
					}
				}
				if !found {
					writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "requested resource not in original grant")
					return
				}
			}
		}

		// Create a copy of authRequest with downscoped resources
		arCopy := *ar
		arCopy.resources = validatedResources
		ar = &arCopy
	}

	// Delete the old refresh token (rotation for security)
	s.mu.Lock()
	delete(s.refreshToken, rt)
	s.mu.Unlock()

	s.issueTokens(w, ar)
}

func (s *idpServer) issueTokens(w http.ResponseWriter, ar *authRequest) {
	signer, err := s.oidcSigner()
	if err != nil {
		log.Printf("Error getting signer: %v", err)
		writeTokenEndpointError(w, http.StatusInternalServerError, "server_error", "internal server error")
		return
	}
	jti := rands.HexString(32)
	who := ar.remoteUser

	n := who.Node.View()
	if n.IsTagged() {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "tagged nodes not supported")
		return
	}

	now := time.Now()
	_, tcd, _ := strings.Cut(n.Name(), ".")

	// RFC 8707: Include resources in the audience claim
	audience := jwt.Audience{ar.clientID}
	if len(ar.resources) > 0 {
		// Add resources to the audience list
		audience = append(audience, ar.resources...)
	}

	tsClaims := tailscaleClaims{
		Claims: jwt.Claims{
			Audience:  audience,
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
	}
	
	// Only include email and preferred_username if the appropriate scopes were granted
	for _, scope := range ar.scopes {
		switch scope {
		case "email":
			tsClaims.Email = who.UserProfile.LoginName
		case "profile":
			if username, _, ok := strings.Cut(who.UserProfile.LoginName, "@"); ok {
				tsClaims.PreferredUsername = username
			}
			tsClaims.Picture = who.UserProfile.ProfilePicURL
		}
	}
	if ar.localRP {
		tsClaims.Issuer = s.loopbackURL
	}

	rules, err := tailcfg.UnmarshalCapJSON[capRule](who.CapMap, tailcfg.PeerCapabilityTsIDP)
	if err != nil {
		log.Printf("tsidp: failed to unmarshal capability: %v", err)
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "failed to unmarshal capability")
		return
	}

	tsClaimsWithExtra, err := withExtraClaims(tsClaims, rules)
	if err != nil {
		log.Printf("tsidp: failed to merge extra claims: %v", err)
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "failed to merge extra claims")
		return
	}

	// Create an OIDC token using this issuer's signer.
	token, err := jwt.Signed(signer).Claims(tsClaimsWithExtra).CompactSerialize()
	if err != nil {
		log.Printf("Error getting token: %v", err)
		writeTokenEndpointError(w, http.StatusInternalServerError, "server_error", "internal server error")
		return
	}

	at := rands.HexString(32)
	rt := rands.HexString(32)
	s.mu.Lock()
	ar.validTill = now.Add(5 * time.Minute)
	mak.Set(&s.accessToken, at, ar)
	// Create a new authRequest for refresh token with longer validity
	rtAuth := *ar                                   // copy the authRequest
	rtAuth.validTill = now.Add(30 * 24 * time.Hour) // 30 days
	mak.Set(&s.refreshToken, rt, &rtAuth)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(oidcTokenResponse{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    5 * 60,
		IDToken:      token,
		RefreshToken: rt,
	}); err != nil {
		writeTokenEndpointError(w, http.StatusInternalServerError, "server_error", "internal server error")
	}
}

func (s *idpServer) serveIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the token parameter
	token := r.FormValue("token")
	if token == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	// token_type_hint is optional, we can ignore it for now
	// since we only have one type of token (access tokens)

	// Look up the token
	s.mu.Lock()
	ar, tokenExists := s.accessToken[token]
	s.mu.Unlock()

	// Initialize response with active: false (default for invalid/expired tokens)
	resp := map[string]any{
		"active": false,
	}

	// Check if token exists and handle expiration
	if tokenExists {
		now := time.Now()
		if ar.validTill.Before(now) {
			// Token expired, clean it up
			s.mu.Lock()
			delete(s.accessToken, token)
			s.mu.Unlock()
			tokenExists = false
		}
	}

	// If token exists and is not expired, we need to authenticate the client
	if tokenExists {
		// For introspection, we need to authenticate the client making the request
		// This is different from token endpoint where we authenticate using the authRequest

		// Get client credentials from the request
		clientID, clientSecret, hasBasicAuth := r.BasicAuth()
		if !hasBasicAuth {
			clientID = r.FormValue("client_id")
			clientSecret = r.FormValue("client_secret")
		}

		// Determine if the client is authorized to introspect this token
		authorized := false

		if ar.funnelRP != nil {
			// For funnel clients, verify client credentials match
			if subtle.ConstantTimeCompare([]byte(clientID), []byte(ar.funnelRP.ID)) == 1 &&
				subtle.ConstantTimeCompare([]byte(clientSecret), []byte(ar.funnelRP.Secret)) == 1 {
				authorized = true
			}
		} else if ar.localRP {
			// For local clients, check if request is from loopback
			ra, err := netip.ParseAddrPort(r.RemoteAddr)
			if err == nil && ra.Addr().IsLoopback() {
				authorized = true
			}
		} else if ar.rpNodeID != 0 && s.lc != nil {
			// For node-based clients, verify the requesting node
			who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
			if err == nil && who.Node.ID == ar.rpNodeID {
				authorized = true
			}
		}

		if !authorized {
			// Return inactive token for unauthorized clients
			// This prevents token scanning attacks
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Token is valid and client is authorized, return active with metadata
		resp["active"] = true
		resp["client_id"] = ar.clientID
		resp["exp"] = ar.validTill.Unix()
		resp["iat"] = ar.validTill.Add(-5 * time.Minute).Unix() // issued 5 min before expiry
		resp["token_type"] = "Bearer"

		if ar.remoteUser != nil && ar.remoteUser.Node != nil {
			resp["sub"] = fmt.Sprintf("%d", ar.remoteUser.Node.User)
			
			// Only include claims based on granted scopes
			for _, scope := range ar.scopes {
				switch scope {
				case "profile":
					if ar.remoteUser.UserProfile != nil {
						if username, _, ok := strings.Cut(ar.remoteUser.UserProfile.LoginName, "@"); ok {
							resp["preferred_username"] = username
						}
						resp["picture"] = ar.remoteUser.UserProfile.ProfilePicURL
					}
				case "email":
					if ar.remoteUser.UserProfile != nil {
						resp["email"] = ar.remoteUser.UserProfile.LoginName
					}
				}
			}
		}

		// Add audience if available
		audience := []string{}
		if ar.clientID != "" {
			audience = append(audience, ar.clientID)
		}
		if len(ar.resources) > 0 {
			audience = append(audience, ar.resources...)
		}
		if len(audience) > 0 {
			resp["aud"] = audience
		}

		// Add scope if available
		if len(ar.scopes) > 0 {
			resp["scope"] = strings.Join(ar.scopes, " ")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
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

// oauthErrorResponse represents an OAuth 2.0 error response per RFC 6749 and RFC 7591
type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeJSONError writes an OAuth 2.0 compliant JSON error response
func writeJSONError(w http.ResponseWriter, statusCode int, errorCode, errorDescription string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(oauthErrorResponse{
		Error:            errorCode,
		ErrorDescription: errorDescription,
	})
}

// writeTokenEndpointError writes an RFC 6749 compliant token endpoint error response
// with required headers per section 5.2
func writeTokenEndpointError(w http.ResponseWriter, statusCode int, errorCode, errorDescription string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(oauthErrorResponse{
		Error:            errorCode,
		ErrorDescription: errorDescription,
	})
}

// writeBearerError writes an RFC 6750 compliant Bearer token error response
// with WWW-Authenticate header per section 3.1
func writeBearerError(w http.ResponseWriter, statusCode int, errorCode, errorDescription string) {
	// Build WWW-Authenticate header value
	authHeader := fmt.Sprintf(`Bearer error="%s"`, errorCode)
	if errorDescription != "" {
		authHeader += fmt.Sprintf(`, error_description="%s"`, errorDescription)
	}
	w.Header().Set("WWW-Authenticate", authHeader)
	w.WriteHeader(statusCode)
}

// redirectAuthError redirects to the client's redirect_uri with error parameters
// per RFC 6749 Section 4.1.2.1
func redirectAuthError(w http.ResponseWriter, r *http.Request, redirectURI, errorCode, errorDescription, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// If redirect URI is invalid, return error directly
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	q := u.Query()
	q.Set("error", errorCode)
	if errorDescription != "" {
		q.Set("error_description", errorDescription)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

const (
	oidcJWKSPath      = "/.well-known/jwks.json"
	oidcConfigPath    = "/.well-known/openid-configuration"
	oauthMetadataPath = "/.well-known/oauth-authorization-server"
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
		var sk signingKey
		b, err := os.ReadFile("oidc-key.json")
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
		if err := os.WriteFile("oidc-key.json", b, 0600); err != nil {
			log.Fatalf("Error writing key: %v", err)
		}
		return &sk, nil
	})
}

func (s *idpServer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != oidcJWKSPath {
		writeJSONError(w, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	sk, err := s.oidcPrivateKey()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "internal server error")
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
		writeJSONError(w, http.StatusInternalServerError, "server_error", "internal server error")
	}
}

// openIDProviderMetadata is a partial representation of
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata.
type openIDProviderMetadata struct {
	Issuer                           string              `json:"issuer"`
	AuthorizationEndpoint            string              `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                    string              `json:"token_endpoint,omitempty"`
	UserInfoEndpoint                 string              `json:"userinfo_endpoint,omitempty"`
	IntrospectionEndpoint            string              `json:"introspection_endpoint,omitempty"`
	RegistrationEndpoint             string              `json:"registration_endpoint,omitempty"`
	JWKS_URI                         string              `json:"jwks_uri"`
	ScopesSupported                  views.Slice[string] `json:"scopes_supported"`
	ResponseTypesSupported           views.Slice[string] `json:"response_types_supported"`
	SubjectTypesSupported            views.Slice[string] `json:"subject_types_supported"`
	ClaimsSupported                  views.Slice[string] `json:"claims_supported"`
	IDTokenSigningAlgValuesSupported views.Slice[string] `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported    views.Slice[string] `json:"code_challenge_methods_supported,omitempty"`
	// TODO(maisem): maybe add other fields?
	// Currently we fill out the REQUIRED fields, scopes_supported and claims_supported.
}

// oauthAuthorizationServerMetadata is a representation of
// OAuth 2.0 Authorization Server Metadata as defined in RFC 8414.
// https://datatracker.ietf.org/doc/html/rfc8414
type oauthAuthorizationServerMetadata struct {
	Issuer                             string              `json:"issuer"`
	AuthorizationEndpoint              string              `json:"authorization_endpoint"`
	TokenEndpoint                      string              `json:"token_endpoint"`
	IntrospectionEndpoint              string              `json:"introspection_endpoint,omitempty"`
	RegistrationEndpoint               string              `json:"registration_endpoint,omitempty"`
	JWKS_URI                           string              `json:"jwks_uri"`
	ResponseTypesSupported             views.Slice[string] `json:"response_types_supported"`
	GrantTypesSupported                views.Slice[string] `json:"grant_types_supported"`
	ScopesSupported                    views.Slice[string] `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethodsSupported  views.Slice[string] `json:"token_endpoint_auth_methods_supported"`
	AuthorizationDetailsTypesSupported views.Slice[string] `json:"authorization_details_types_supported,omitempty"`
	ResourceIndicatorsSupported        bool                `json:"resource_indicators_supported,omitempty"`
	CodeChallengeMethodsSupported      views.Slice[string] `json:"code_challenge_methods_supported,omitempty"`
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

	// PreferredUsername is the local part of Email (without '@' and domain).
	PreferredUsername string `json:"preferred_username,omitempty"`
	
	// Picture is the user's profile picture URL.
	Picture string `json:"picture,omitempty"`
}

var (
	openIDSupportedClaims = views.SliceOf([]string{
		// Standard claims, these correspond to fields in jwt.Claims.
		"sub", "aud", "exp", "iat", "iss", "jti", "nbf", "preferred_username", "email", "picture",

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

	// OAuth 2.0 specific metadata constants
	oauthSupportedGrantTypes               = views.SliceOf([]string{"authorization_code", "refresh_token"})
	oauthSupportedTokenEndpointAuthMethods = views.SliceOf([]string{"client_secret_post", "client_secret_basic"})

	// PKCE support (RFC 7636)
	pkceCodeChallengeMethodsSupported = views.SliceOf([]string{"plain", "S256"})
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
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		log.Printf("Error parsing remote addr: %v", err)
		http.Error(w, "tsidp: invalid remote address", http.StatusBadRequest)
		return
	}
	var authorizeEndpoint string
	rpEndpoint := s.serverURL
	if isFunnelRequest(r) {
		authorizeEndpoint = fmt.Sprintf("%s/authorize/funnel", s.serverURL)
	} else if ap.Addr().IsLoopback() {
		rpEndpoint = s.loopbackURL
		authorizeEndpoint = fmt.Sprintf("%s/authorize/localhost", s.serverURL)
	} else if s.lc != nil {
		if who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr); err == nil {
			authorizeEndpoint = fmt.Sprintf("%s/authorize/%d", s.serverURL, who.Node.ID)
		} else {
			log.Printf("Error getting WhoIs: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "tsidp: internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	je := json.NewEncoder(w)
	je.SetIndent("", "  ")
	metadata := openIDProviderMetadata{
		AuthorizationEndpoint:            authorizeEndpoint,
		Issuer:                           rpEndpoint,
		JWKS_URI:                         rpEndpoint + oidcJWKSPath,
		UserInfoEndpoint:                 rpEndpoint + "/userinfo",
		TokenEndpoint:                    rpEndpoint + "/token",
		IntrospectionEndpoint:            rpEndpoint + "/introspect",
		ScopesSupported:                  openIDSupportedScopes,
		ResponseTypesSupported:           openIDSupportedReponseTypes,
		SubjectTypesSupported:            openIDSupportedSubjectTypes,
		ClaimsSupported:                  openIDSupportedClaims,
		IDTokenSigningAlgValuesSupported: openIDSupportedSigningAlgos,
		CodeChallengeMethodsSupported:    pkceCodeChallengeMethodsSupported,
	}

	// Only expose registration endpoint over tailnet, not funnel
	if !isFunnelRequest(r) {
		metadata.RegistrationEndpoint = rpEndpoint + "/register"
	}

	if err := je.Encode(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *idpServer) serveOAuthMetadata(w http.ResponseWriter, r *http.Request) {
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
	if r.URL.Path != oauthMetadataPath {
		http.Error(w, "tsidp: not found", http.StatusNotFound)
		return
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		log.Printf("Error parsing remote addr: %v", err)
		http.Error(w, "tsidp: invalid remote address", http.StatusBadRequest)
		return
	}
	var authorizeEndpoint string
	rpEndpoint := s.serverURL
	if isFunnelRequest(r) {
		authorizeEndpoint = fmt.Sprintf("%s/authorize/funnel", s.serverURL)
	} else if ap.Addr().IsLoopback() {
		rpEndpoint = s.loopbackURL
		authorizeEndpoint = fmt.Sprintf("%s/authorize/localhost", s.serverURL)
	} else if s.lc != nil {
		if who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr); err == nil {
			authorizeEndpoint = fmt.Sprintf("%s/authorize/%d", s.serverURL, who.Node.ID)
		} else {
			log.Printf("Error getting WhoIs: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "tsidp: internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	je := json.NewEncoder(w)
	je.SetIndent("", "  ")
	metadata := oauthAuthorizationServerMetadata{
		Issuer:                             rpEndpoint,
		AuthorizationEndpoint:              authorizeEndpoint,
		TokenEndpoint:                      rpEndpoint + "/token",
		IntrospectionEndpoint:              rpEndpoint + "/introspect",
		JWKS_URI:                           rpEndpoint + oidcJWKSPath,
		ResponseTypesSupported:             openIDSupportedReponseTypes,
		GrantTypesSupported:                oauthSupportedGrantTypes,
		ScopesSupported:                    openIDSupportedScopes,
		TokenEndpointAuthMethodsSupported:  oauthSupportedTokenEndpointAuthMethods,
		ResourceIndicatorsSupported:        true, // RFC 8707 support
		AuthorizationDetailsTypesSupported: views.SliceOf([]string{"resource_indicators"}),
		CodeChallengeMethodsSupported:      pkceCodeChallengeMethodsSupported,
	}

	// Only expose registration endpoint over tailnet, not funnel
	if !isFunnelRequest(r) {
		metadata.RegistrationEndpoint = rpEndpoint + "/register"
	}

	if err := je.Encode(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// funnelClient represents an OAuth 2.0/OIDC client/relying party.
// It can be created manually via the /clients endpoint or dynamically
// via the /register endpoint (RFC 7591).
type funnelClient struct {
	ID                      string    `json:"client_id"`
	Secret                  string    `json:"client_secret,omitempty"`
	Name                    string    `json:"client_name,omitempty"`
	RedirectURIs            []string  `json:"redirect_uris"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string  `json:"grant_types,omitempty"`
	ResponseTypes           []string  `json:"response_types,omitempty"`
	Scope                   string    `json:"scope,omitempty"`
	ClientURI               string    `json:"client_uri,omitempty"`
	LogoURI                 string    `json:"logo_uri,omitempty"`
	Contacts                []string  `json:"contacts,omitempty"`
	ApplicationType         string    `json:"application_type,omitempty"`
	DynamicallyRegistered   bool      `json:"dynamically_registered,omitempty"`
	CreatedAt               time.Time `json:"created_at,omitempty"`
}

// UnmarshalJSON implements custom JSON unmarshaling for backward compatibility.
// It migrates the old singular redirect_uri field to the new redirect_uris array
// and the old name field to client_name.
func (c *funnelClient) UnmarshalJSON(data []byte) error {
	type Alias funnelClient
	aux := &struct {
		RedirectURI string `json:"redirect_uri,omitempty"`
		Name        string `json:"name,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Migrate old redirect_uri to redirect_uris
	if len(c.RedirectURIs) == 0 && aux.RedirectURI != "" {
		c.RedirectURIs = []string{aux.RedirectURI}
	}

	// Migrate old name to client_name
	if c.Name == "" && aux.Name != "" {
		c.Name = aux.Name
	}

	return nil
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
			ID:           c.ID,
			Name:         c.Name,
			Secret:       "",
			RedirectURIs: c.RedirectURIs,
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
		ID:           clientID,
		Secret:       clientSecret,
		Name:         r.FormValue("name"),
		RedirectURIs: []string{redirectURI},
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
			ID:           c.ID,
			Name:         c.Name,
			Secret:       "",
			RedirectURIs: c.RedirectURIs,
		})
	}
	s.mu.Unlock()
	json.NewEncoder(w).Encode(redactedClients)
}

// serveDynamicClientRegistration implements RFC 7591 OAuth 2.0 Dynamic Client Registration
// and OpenID Connect Dynamic Client Registration 1.0.
func (s *idpServer) serveDynamicClientRegistration(w http.ResponseWriter, r *http.Request) {
	// Block funnel requests - dynamic registration is only available over tailnet
	if isFunnelRequest(r) {
		writeJSONError(w, http.StatusForbidden, "access_denied", "dynamic client registration not available over funnel")
		return
	}

	if r.Method != "POST" {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}

	// Parse registration request
	var req struct {
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
		GrantTypes              []string `json:"grant_types,omitempty"`
		ResponseTypes           []string `json:"response_types,omitempty"`
		ClientName              string   `json:"client_name,omitempty"`
		ClientURI               string   `json:"client_uri,omitempty"`
		LogoURI                 string   `json:"logo_uri,omitempty"`
		Scope                   string   `json:"scope,omitempty"`
		Contacts                []string `json:"contacts,omitempty"`
		ApplicationType         string   `json:"application_type,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	// Validate required fields per RFC 7591 and OpenID specs
	if len(req.RedirectURIs) == 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required")
		return
	}

	// Set defaults per specs
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.ApplicationType == "" {
		req.ApplicationType = "web"
	}

	// Generate client credentials
	clientID := rands.HexString(32)
	clientSecret := rands.HexString(64)

	// Create new client
	newClient := funnelClient{
		ID:                      clientID,
		Secret:                  clientSecret,
		Name:                    req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		Scope:                   req.Scope,
		ClientURI:               req.ClientURI,
		LogoURI:                 req.LogoURI,
		Contacts:                req.Contacts,
		ApplicationType:         req.ApplicationType,
		DynamicallyRegistered:   true,
		CreatedAt:               time.Now(),
	}

	// Store the client
	s.mu.Lock()
	mak.Set(&s.funnelClients, clientID, &newClient)
	if err := s.storeFunnelClientsLocked(); err != nil {
		s.mu.Unlock()
		log.Printf("tsidp: error storing client: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	s.mu.Unlock()

	// Return the client registration response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newClient)
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
// pairs for RPs that access the IDP over funnel. s.mu must be held while
// calling this.
func (s *idpServer) storeFunnelClientsLocked() error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(s.funnelClients); err != nil {
		return err
	}
	return os.WriteFile(funnelClientsFile, buf.Bytes(), 0600)
}

// cleanupExpiredTokens removes expired access and refresh tokens from memory.
// This prevents memory leaks from accumulating expired tokens over time.
func (s *idpServer) cleanupExpiredTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Clean up expired access tokens
	for token, ar := range s.accessToken {
		if ar.validTill.Before(now) {
			delete(s.accessToken, token)
		}
	}

	// Clean up expired refresh tokens
	for token, ar := range s.refreshToken {
		if ar.validTill.Before(now) {
			delete(s.refreshToken, token)
		}
	}
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
