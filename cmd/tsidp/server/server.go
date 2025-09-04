// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package server implements the HTTP server and handlers for the tsidp service.
package server

import (
	"context"
	"net/http"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/lazy"
)

// CtxConn is a key to look up a net.Conn stored in an HTTP request's context.
// Migrated from legacy/tsidp.go:58
type CtxConn struct{}

// IDPServer handles OIDC identity provider operations
// Migrated from legacy/tsidp.go:306-323
type IDPServer struct {
	lc          *local.Client
	loopbackURL string
	serverURL   string // "https://foo.bar.ts.net"
	funnel      bool
	localTSMode bool
	enableSTS   bool

	lazyMux        lazy.SyncValue[*http.ServeMux]
	lazySigningKey lazy.SyncValue[*signingKey]
	lazySigner     lazy.SyncValue[jose.Signer]

	mu            sync.Mutex               // guards the fields below
	code          map[string]*AuthRequest  // keyed by random hex
	accessToken   map[string]*AuthRequest  // keyed by random hex
	refreshToken  map[string]*AuthRequest  // keyed by random hex
	funnelClients map[string]*FunnelClient // keyed by client ID
}

// AuthRequest represents an authorization request
// Migrated from legacy/tsidp.go:325-387
type AuthRequest struct {
	// localRP is true if the request is from a relying party running on the
	// same machine as the idp server. It is mutually exclusive with rpNodeID
	// and funnelRP.
	LocalRP bool

	// rpNodeID is the NodeID of the relying party (who requested the auth, such
	// as Proxmox or Synology), not the user node who is being authenticated. It
	// is mutually exclusive with localRP and funnelRP.
	RPNodeID tailcfg.NodeID

	// funnelRP is non-nil if the request is from a relying party outside the
	// tailnet, via Tailscale Funnel. It is mutually exclusive with rpNodeID
	// and localRP.
	FunnelRP *FunnelClient

	// clientID is the "client_id" sent in the authorized request.
	ClientID string

	// nonce presented in the request.
	Nonce string

	// redirectURI is the redirect_uri presented in the request.
	RedirectURI string

	// resources are the resource URIs from RFC 8707 that the client is
	// requesting access to. These are validated at token issuance time.
	Resources []string

	// scopes are the OAuth 2.0 scopes requested by the client.
	// These are validated against supported scopes at authorization time.
	Scopes []string

	// codeChallenge is the PKCE code challenge from RFC 7636.
	// It is a derived value from the code_verifier that the client
	// will send during token exchange.
	CodeChallenge string

	// codeChallengeMethod is the method used to derive codeChallenge
	// from the code_verifier. Valid values are "plain" and "S256".
	// If empty, PKCE is not used for this request.
	CodeChallengeMethod string

	// remoteUser is the user who is being authenticated.
	RemoteUser *apitype.WhoIsResponse

	// validTill is the time until which the token is valid.
	// Authorization codes expire after 5 minutes per OAuth 2.0 best practices (RFC 6749 recommends max 10 minutes).
	ValidTill time.Time

	// jti is the unique identifier for the JWT token (JWT ID).
	// This is used for token introspection to return the jti claim.
	JTI string

	// Token exchange specific fields (RFC 8693)
	IsExchangedToken bool     // Indicates if this token was created via exchange
	OriginalClientID string   // The client that originally authenticated the user
	ExchangedBy      string   // The client that performed the exchange
	Audiences        []string // All intended audiences for the token

	// Delegation support (RFC 8693 act claim)
	ActorInfo *ActorClaim // For delegation scenarios
}

// ActorClaim represents the 'act' claim structure defined in RFC 8693 Section 4.1
// for delegation scenarios in token exchange.
// Migrated from legacy/tsidp.go:391-395
type ActorClaim struct {
	Subject  string      `json:"sub"`
	ClientID string      `json:"client_id,omitempty"`
	Actor    *ActorClaim `json:"act,omitempty"` // Nested for delegation chains
}

// FunnelClient represents an OAuth client accessing the IDP via Funnel
// Migrated from legacy/tsidp.go:2006-2024
type FunnelClient struct {
	ID          string    `json:"id"`
	Secret      string    `json:"secret"`
	Name        string    `json:"name"`
	RedirectURI string    `json:"redirect_uri"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used,omitempty"`
}

// signingKey represents a JWT signing key
// Migrated from legacy/tsidp.go:2336-2339
type signingKey struct {
	Kid uint64
	Key interface{} // *rsa.PrivateKey
}

// New creates a new IDPServer instance
func New(lc *local.Client, funnel, localTSMode, enableSTS bool) *IDPServer {
	return &IDPServer{
		lc:            lc,
		funnel:        funnel,
		localTSMode:   localTSMode,
		enableSTS:     enableSTS,
		code:          make(map[string]*AuthRequest),
		accessToken:   make(map[string]*AuthRequest),
		refreshToken:  make(map[string]*AuthRequest),
		funnelClients: make(map[string]*FunnelClient),
	}
}

// SetServerURL sets the server URL
func (s *IDPServer) SetServerURL(url string) {
	s.serverURL = url
}

// ServerURL returns the server URL
func (s *IDPServer) ServerURL() string {
	return s.serverURL
}

// SetLoopbackURL sets the loopback URL
func (s *IDPServer) SetLoopbackURL(url string) {
	s.loopbackURL = url
}

// SetFunnelClients sets the funnel clients
func (s *IDPServer) SetFunnelClients(clients map[string]*FunnelClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.funnelClients = clients
}

// CleanupExpiredTokens removes expired tokens from memory
// Migrated from legacy/tsidp.go:2280-2299
func (s *IDPServer) CleanupExpiredTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Clean up authorization codes (they should be short-lived)
	for code, ar := range s.code {
		if now.After(ar.ValidTill) {
			delete(s.code, code)
		}
	}

	// Clean up access tokens
	for token, ar := range s.accessToken {
		if now.After(ar.ValidTill) {
			delete(s.accessToken, token)
		}
	}

	// Clean up refresh tokens (if they have an expiry)
	for token, ar := range s.refreshToken {
		if !ar.ValidTill.IsZero() && now.After(ar.ValidTill) {
			delete(s.refreshToken, token)
		}
	}
}

// ServeHTTP implements http.Handler
// Migrated from legacy/tsidp.go:689-692
func (s *IDPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.lazyMux.Get(s.newMux).ServeHTTP(w, r)
}

// newMux creates the HTTP request multiplexer
// This will be expanded with actual handlers
// Migrated from legacy/tsidp.go:674-687
func (s *IDPServer) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	// TODO: Register actual handlers here
	// These will be implemented as we extract more functionality
	// mux.HandleFunc("/authorize", s.authorize)
	// mux.HandleFunc("/.well-known/openid-configuration", s.serveOpenIDConfig)
	// mux.HandleFunc("/.well-known/oauth-authorization-server", s.serveOAuthMetadata)
	// mux.HandleFunc("/token", s.serveToken)
	// mux.HandleFunc("/introspect", s.serveIntrospect)
	// mux.HandleFunc("/jwks", s.serveJWKS)
	// mux.HandleFunc("/userinfo", s.serveUserInfo)
	// mux.HandleFunc("/clients/", s.serveClients)
	// mux.HandleFunc("/register", s.serveDynamicClientRegistration)
	return mux
}

// ServeOnLocalTailscaled starts a serve session using an already-running tailscaled
// Migrated from legacy/tsidp.go:244-304
func ServeOnLocalTailscaled(ctx context.Context, lc *local.Client, st *ipnstate.Status, dstPort uint16, shouldFunnel bool) (cleanup func(), watcherChan chan error, err error) {
	// TODO: Implement this function by extracting from legacy/tsidp.go:244-304
	// This function handles serving on local tailscaled
	return func() {}, make(chan error), nil
}
