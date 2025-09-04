// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"

	"gopkg.in/square/go-jose.v2"
	"tailscale.com/ipn"
	"tailscale.com/types/views"
)

// openIDProviderMetadata is a partial representation of OpenID Provider Metadata.
// Migrated from legacy/tsidp.go:1754-1771
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
	GrantTypesSupported              views.Slice[string] `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported    views.Slice[string] `json:"code_challenge_methods_supported,omitempty"`
}

// oauthAuthorizationServerMetadata is a representation of
// OAuth 2.0 Authorization Server Metadata as defined in RFC 8414.
// Migrated from legacy/tsidp.go:1773-1790
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

// Supported OpenID/OAuth metadata constants
// Migrated from legacy/tsidp.go:1816-1845
var (
	openIDSupportedClaims = views.SliceOf([]string{
		// Standard claims, these correspond to fields in jwt.Claims.
		"sub", "aud", "exp", "iat", "iss", "jti", "nbf", "preferred_username", "email", "picture", "azp",

		// Tailscale claims
		"key", "addresses", "nid", "node", "tailnet", "tags", "user", "uid",
	})

	// As defined in the OpenID spec this should be "openid".
	openIDSupportedScopes = views.SliceOf([]string{"openid", "email", "profile"})

	// We only support getting the id_token.
	openIDSupportedReponseTypes = views.SliceOf([]string{"id_token", "code"})

	// The type of the "sub" field in the JWT, which means it is globally unique identifier.
	openIDSupportedSubjectTypes = views.SliceOf([]string{"public"})

	// The algo used for signing. The OpenID spec says "The algorithm RS256 MUST be included."
	openIDSupportedSigningAlgos = views.SliceOf([]string{string(jose.RS256)})

	// OAuth 2.0 specific metadata constants
	oauthSupportedGrantTypes               = views.SliceOf([]string{"authorization_code", "refresh_token"})
	oauthSupportedTokenEndpointAuthMethods = views.SliceOf([]string{"client_secret_post", "client_secret_basic"})

	// PKCE support (RFC 7636)
	pkceCodeChallengeMethodsSupported = views.SliceOf([]string{"plain", "S256"})
)

// serveOpenIDConfig serves the OpenID Connect discovery endpoint
// Migrated from legacy/tsidp.go:1847-1923
func (s *IDPServer) serveOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Method", "GET, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")

	// early return for pre-flight OPTIONS requests.
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path != "/.well-known/openid-configuration" {
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
		JWKS_URI:                         rpEndpoint + "/.well-known/jwks.json",
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

	// Add grant types supported
	grantTypes := []string{"authorization_code", "refresh_token"}
	if s.enableSTS {
		grantTypes = append(grantTypes, "urn:ietf:params:oauth:grant-type:token-exchange")
	}
	metadata.GrantTypesSupported = views.SliceOf(grantTypes)

	// Only expose registration endpoint over tailnet, not funnel
	if !isFunnelRequest(r) {
		metadata.RegistrationEndpoint = rpEndpoint + "/register"
	}

	if err := je.Encode(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// serveOAuthMetadata serves the OAuth 2.0 Authorization Server metadata endpoint
// Migrated from legacy/tsidp.go:1925-2001
func (s *IDPServer) serveOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Method", "GET, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")

	// early return for pre-flight OPTIONS requests.
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path != "/.well-known/oauth-authorization-server" {
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

	// Build grant types list
	grantTypes := []string{"authorization_code", "refresh_token"}
	if s.enableSTS {
		grantTypes = append(grantTypes, "urn:ietf:params:oauth:grant-type:token-exchange")
	}

	metadata := oauthAuthorizationServerMetadata{
		Issuer:                             rpEndpoint,
		AuthorizationEndpoint:              authorizeEndpoint,
		TokenEndpoint:                      rpEndpoint + "/token",
		IntrospectionEndpoint:              rpEndpoint + "/introspect",
		JWKS_URI:                           rpEndpoint + "/.well-known/jwks.json",
		ResponseTypesSupported:             openIDSupportedReponseTypes,
		GrantTypesSupported:                views.SliceOf(grantTypes),
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

// serveJWKS serves the JSON Web Key Set endpoint
// Migrated from legacy/tsidp.go:1723-1750
func (s *IDPServer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.well-known/jwks.json" {
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
				Key:       sk.Key.Public(),
				Algorithm: string(jose.RS256),
				Use:       "sig",
				KeyID:     fmt.Sprint(sk.Kid),
			},
		},
	}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "internal server error")
	}
}

// Helper functions

// isFunnelRequest checks if the request is coming through Tailscale Funnel
// Migrated from legacy/tsidp.go:2392-2410
func isFunnelRequest(r *http.Request) bool {
	// If we're funneling through the local tailscaled, it will set this HTTP header
	if r.Header.Get("Tailscale-Funnel-Request") != "" {
		return true
	}

	// If the funneled connection is from tsnet, then the net.Conn will be of type ipn.FunnelConn
	netConn := r.Context().Value(CtxConn{})
	// if the conn is wrapped inside TLS, unwrap it
	if tlsConn, ok := netConn.(*tls.Conn); ok {
		netConn = tlsConn.NetConn()
	}
	if _, ok := netConn.(*ipn.FunnelConn); ok {
		return true
	}
	return false
}

// writeJSONError writes a JSON error response
// Migrated from legacy/tsidp.go:1619-1626
func writeJSONError(w http.ResponseWriter, statusCode int, errorCode, errorDescription string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(oauthErrorResponse{
		Error:            errorCode,
		ErrorDescription: errorDescription,
	})
}

// oauthErrorResponse represents an OAuth 2.0 error response
// Migrated from legacy/tsidp.go:1613-1617
type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}
