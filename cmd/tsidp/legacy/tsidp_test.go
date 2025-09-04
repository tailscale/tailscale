// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestBackwardCompatibility(t *testing.T) {
	tests := []struct {
		name       string
		jsonData   string
		expectURIs []string
		expectName string
	}{
		{
			name: "old format with redirect_uri and name",
			jsonData: `{
				"client_id": "test-client",
				"client_secret": "test-secret",
				"name": "Test Client",
				"redirect_uri": "https://example.com/callback"
			}`,
			expectURIs: []string{"https://example.com/callback"},
			expectName: "Test Client",
		},
		{
			name: "new format with redirect_uris and client_name",
			jsonData: `{
				"client_id": "test-client",
				"client_secret": "test-secret",
				"client_name": "Test Client",
				"redirect_uris": ["https://example.com/callback", "https://example.com/callback2"]
			}`,
			expectURIs: []string{"https://example.com/callback", "https://example.com/callback2"},
			expectName: "Test Client",
		},
		{
			name: "both redirect fields present (redirect_uris takes precedence)",
			jsonData: `{
				"client_id": "test-client",
				"client_secret": "test-secret",
				"client_name": "Test Client",
				"redirect_uri": "https://old.example.com/callback",
				"redirect_uris": ["https://new.example.com/callback"]
			}`,
			expectURIs: []string{"https://new.example.com/callback"},
			expectName: "Test Client",
		},
		{
			name: "both name fields present (client_name takes precedence)",
			jsonData: `{
				"client_id": "test-client",
				"client_secret": "test-secret",
				"name": "Old Name",
				"client_name": "New Name",
				"redirect_uris": ["https://example.com/callback"]
			}`,
			expectURIs: []string{"https://example.com/callback"},
			expectName: "New Name",
		},
		{
			name: "mixed old and new fields",
			jsonData: `{
				"client_id": "test-client",
				"client_secret": "test-secret",
				"name": "Test Client",
				"redirect_uris": ["https://example.com/callback"]
			}`,
			expectURIs: []string{"https://example.com/callback"},
			expectName: "Test Client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var client funnelClient
			if err := json.Unmarshal([]byte(tt.jsonData), &client); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if !reflect.DeepEqual(client.RedirectURIs, tt.expectURIs) {
				t.Errorf("expected redirect_uris %v, got %v", tt.expectURIs, client.RedirectURIs)
			}

			if client.Name != tt.expectName {
				t.Errorf("expected name %q, got %q", tt.expectName, client.Name)
			}
		})
	}
}

func TestServeDynamicClientRegistration(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		body          string
		isFunnel      bool
		expectStatus  int
		checkResponse func(t *testing.T, body []byte)
	}{
		{
			name:   "POST request - valid registration",
			method: "POST",
			body: `{
				"redirect_uris": ["https://example.com/callback"],
				"client_name": "Test Dynamic Client",
				"grant_types": ["authorization_code"],
				"response_types": ["code"]
			}`,
			expectStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, body []byte) {
				var resp funnelClient
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}

				if resp.ID == "" {
					t.Error("expected client_id to be set")
				}
				if resp.Secret == "" {
					t.Error("expected client_secret to be set")
				}
				if resp.Name != "Test Dynamic Client" {
					t.Errorf("expected client_name to be 'Test Dynamic Client', got %s", resp.Name)
				}
				if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "https://example.com/callback" {
					t.Errorf("expected redirect_uris to be ['https://example.com/callback'], got %v", resp.RedirectURIs)
				}
				if !resp.DynamicallyRegistered {
					t.Error("expected dynamically_registered to be true")
				}
				if resp.TokenEndpointAuthMethod != "client_secret_basic" {
					t.Errorf("expected default token_endpoint_auth_method to be 'client_secret_basic', got %s", resp.TokenEndpointAuthMethod)
				}
			},
		},
		{
			name:   "POST request - minimal registration",
			method: "POST",
			body: `{
				"redirect_uris": ["https://example.com/callback"]
			}`,
			expectStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, body []byte) {
				var resp funnelClient
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}

				// Check defaults were applied
				if resp.TokenEndpointAuthMethod != "client_secret_basic" {
					t.Errorf("expected default token_endpoint_auth_method, got %s", resp.TokenEndpointAuthMethod)
				}
				if !reflect.DeepEqual(resp.GrantTypes, []string{"authorization_code"}) {
					t.Errorf("expected default grant_types, got %v", resp.GrantTypes)
				}
				if !reflect.DeepEqual(resp.ResponseTypes, []string{"code"}) {
					t.Errorf("expected default response_types, got %v", resp.ResponseTypes)
				}
				if resp.ApplicationType != "web" {
					t.Errorf("expected default application_type to be 'web', got %s", resp.ApplicationType)
				}
			},
		},
		{
			name:         "POST request - blocked over funnel",
			method:       "POST",
			body:         `{"redirect_uris": ["https://example.com/callback"]}`,
			isFunnel:     true,
			expectStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "access_denied" {
					t.Errorf("expected error code 'access_denied', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "not available over funnel") {
					t.Errorf("expected error description about funnel, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "POST request - missing redirect_uris",
			method:       "POST",
			body:         `{"client_name": "Test Client"}`,
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_client_metadata" {
					t.Errorf("expected error code 'invalid_client_metadata', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "redirect_uris is required") {
					t.Errorf("expected error description about redirect_uris, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "POST request - empty redirect_uris",
			method:       "POST",
			body:         `{"redirect_uris": []}`,
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_client_metadata" {
					t.Errorf("expected error code 'invalid_client_metadata', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "redirect_uris is required") {
					t.Errorf("expected error description about redirect_uris, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "POST request - invalid JSON",
			method:       "POST",
			body:         `{invalid json}`,
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_request" {
					t.Errorf("expected error code 'invalid_request', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "invalid request body") {
					t.Errorf("expected error description about invalid request body, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "GET request - method not allowed",
			method:       "GET",
			expectStatus: http.StatusMethodNotAllowed,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_request" {
					t.Errorf("expected error code 'invalid_request', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "method not allowed") {
					t.Errorf("expected error description about method not allowed, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:   "POST request - multiple redirect URIs",
			method: "POST",
			body: `{
				"redirect_uris": ["https://example.com/callback", "https://example.com/oauth", "https://example.com/auth"],
				"client_name": "Multi-Redirect Client"
			}`,
			expectStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, body []byte) {
				var resp funnelClient
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}

				if len(resp.RedirectURIs) != 3 {
					t.Errorf("expected 3 redirect_uris, got %d", len(resp.RedirectURIs))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL:     "https://idp.test.ts.net",
				funnelClients: make(map[string]*funnelClient),
			}

			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}

			req := httptest.NewRequest(tt.method, "/register", body)
			if tt.isFunnel {
				req.Header.Set("Tailscale-Funnel-Request", "true")
			}

			rr := httptest.NewRecorder()
			s.serveDynamicClientRegistration(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rr.Code)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, rr.Body.Bytes())
			}
		})
	}
}

func TestRedirectURIValidation(t *testing.T) {
	// Test the redirect URI validation logic directly
	tests := []struct {
		name        string
		clientURIs  []string
		requestURI  string
		expectValid bool
	}{
		{
			name:        "valid single URI",
			clientURIs:  []string{"https://example.com/callback"},
			requestURI:  "https://example.com/callback",
			expectValid: true,
		},
		{
			name:        "valid multiple URIs - first",
			clientURIs:  []string{"https://example.com/callback1", "https://example.com/callback2"},
			requestURI:  "https://example.com/callback1",
			expectValid: true,
		},
		{
			name:        "valid multiple URIs - second",
			clientURIs:  []string{"https://example.com/callback1", "https://example.com/callback2"},
			requestURI:  "https://example.com/callback2",
			expectValid: true,
		},
		{
			name:        "invalid URI",
			clientURIs:  []string{"https://example.com/callback"},
			requestURI:  "https://evil.com/callback",
			expectValid: false,
		},
		{
			name:        "empty client URIs",
			clientURIs:  []string{},
			requestURI:  "https://example.com/callback",
			expectValid: false,
		},
		{
			name:        "case sensitive mismatch",
			clientURIs:  []string{"https://example.com/callback"},
			requestURI:  "https://example.com/CALLBACK",
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the validation logic directly
			validRedirect := false
			for _, uri := range tt.clientURIs {
				if tt.requestURI == uri {
					validRedirect = true
					break
				}
			}

			if validRedirect != tt.expectValid {
				t.Errorf("expected valid=%v, got %v", tt.expectValid, validRedirect)
			}
		})
	}
}

func TestMetadataEndpoints(t *testing.T) {
	tests := []struct {
		name         string
		endpoint     string
		isFunnel     bool
		expectRegURL bool // Should registration_endpoint be present
	}{
		{
			name:         "OpenID metadata - tailnet",
			endpoint:     "/.well-known/openid-configuration",
			isFunnel:     false,
			expectRegURL: true,
		},
		{
			name:         "OpenID metadata - funnel",
			endpoint:     "/.well-known/openid-configuration",
			isFunnel:     true,
			expectRegURL: false,
		},
		{
			name:         "OAuth metadata - tailnet",
			endpoint:     "/.well-known/oauth-authorization-server",
			isFunnel:     false,
			expectRegURL: true,
		},
		{
			name:         "OAuth metadata - funnel",
			endpoint:     "/.well-known/oauth-authorization-server",
			isFunnel:     true,
			expectRegURL: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL:   "https://idp.test.ts.net",
				loopbackURL: "http://localhost:8080",
			}

			req := httptest.NewRequest("GET", tt.endpoint, nil)
			req.RemoteAddr = "127.0.0.1:12345"
			if tt.isFunnel {
				req.Header.Set("Tailscale-Funnel-Request", "true")
			}

			rr := httptest.NewRecorder()

			if strings.Contains(tt.endpoint, "openid") {
				s.serveOpenIDConfig(rr, req)
			} else {
				s.serveOAuthMetadata(rr, req)
			}

			if rr.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rr.Code)
			}

			var metadata map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &metadata); err != nil {
				t.Fatalf("failed to unmarshal metadata: %v", err)
			}

			if tt.expectRegURL {
				if _, ok := metadata["registration_endpoint"]; !ok {
					t.Error("expected registration_endpoint in metadata")
				}
			} else {
				if _, ok := metadata["registration_endpoint"]; ok {
					t.Error("unexpected registration_endpoint in metadata")
				}
			}
		})
	}
}

func TestRefreshTokenFlow(t *testing.T) {
	tests := []struct {
		name          string
		grantType     string
		refreshToken  string
		clientID      string
		clientSecret  string
		expectStatus  int
		checkResponse func(t *testing.T, body []byte)
	}{
		{
			name:         "valid refresh token grant",
			grantType:    "refresh_token",
			refreshToken: "valid-refresh-token",
			clientID:     "test-client",
			clientSecret: "test-secret",
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var resp oidcTokenResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp.AccessToken == "" {
					t.Error("expected access token")
				}
				if resp.RefreshToken == "" {
					t.Error("expected new refresh token")
				}
				if resp.IDToken == "" {
					t.Error("expected ID token")
				}
				if resp.TokenType != "Bearer" {
					t.Errorf("expected token type Bearer, got %s", resp.TokenType)
				}
				if resp.ExpiresIn != 300 {
					t.Errorf("expected expires_in 300, got %d", resp.ExpiresIn)
				}
			},
		},
		{
			name:         "missing refresh token",
			grantType:    "refresh_token",
			refreshToken: "",
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_request" {
					t.Errorf("expected error code 'invalid_request', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "refresh_token is required") {
					t.Errorf("expected error description about refresh_token, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "invalid refresh token",
			grantType:    "refresh_token",
			refreshToken: "invalid-token",
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_grant" {
					t.Errorf("expected error code 'invalid_grant', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "invalid refresh token") {
					t.Errorf("expected error description about invalid refresh token, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "expired refresh token",
			grantType:    "refresh_token",
			refreshToken: "expired-token",
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_grant" {
					t.Errorf("expected error code 'invalid_grant', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "invalid refresh token") {
					t.Errorf("expected error description about invalid refresh token, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "wrong client credentials",
			grantType:    "refresh_token",
			refreshToken: "valid-refresh-token",
			clientID:     "wrong-client",
			clientSecret: "wrong-secret",
			expectStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_client" {
					t.Errorf("expected error code 'invalid_client', got: %v", errResp["error"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL:     "https://idp.test.ts.net",
				refreshToken:  make(map[string]*authRequest),
				funnelClients: make(map[string]*funnelClient),
			}

			// Set up test data
			if tt.refreshToken == "valid-refresh-token" {
				s.refreshToken[tt.refreshToken] = &authRequest{
					funnelRP: &funnelClient{
						ID:     "test-client",
						Secret: "test-secret",
					},
					clientID:  "test-client",
					scopes:    []string{"openid", "email"}, // Add scopes to refresh token
					validTill: time.Now().Add(time.Hour),
					remoteUser: &apitype.WhoIsResponse{
						Node: &tailcfg.Node{
							ID:        1,
							Name:      "node1.example.ts.net",
							User:      tailcfg.UserID(1),
							Key:       key.NodePublic{},
							Addresses: []netip.Prefix{},
						},
						UserProfile: &tailcfg.UserProfile{
							LoginName:     "user@example.com",
							DisplayName:   "Test User",
							ProfilePicURL: "https://example.com/pic.jpg",
						},
					},
				}
				s.funnelClients["test-client"] = &funnelClient{
					ID:     "test-client",
					Secret: "test-secret",
				}
			} else if tt.refreshToken == "expired-token" {
				s.refreshToken[tt.refreshToken] = &authRequest{
					funnelRP: &funnelClient{
						ID:     "test-client",
						Secret: "test-secret",
					},
					clientID:  "test-client",
					validTill: time.Now().Add(-time.Hour), // expired
				}
			}

			// Create request
			form := url.Values{}
			form.Set("grant_type", tt.grantType)
			if tt.refreshToken != "" {
				form.Set("refresh_token", tt.refreshToken)
			}
			if tt.clientID != "" {
				form.Set("client_id", tt.clientID)
			}
			if tt.clientSecret != "" {
				form.Set("client_secret", tt.clientSecret)
			}

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.serveToken(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rr.Code)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, rr.Body.Bytes())
			}
		})
	}
}

func TestTokenEndpointUnsupportedGrantType(t *testing.T) {
	tests := []struct {
		name         string
		grantType    string
		expectStatus int
	}{
		{
			name:         "password grant type",
			grantType:    "password",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "client_credentials grant type",
			grantType:    "client_credentials",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "implicit grant type",
			grantType:    "implicit",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "unknown grant type",
			grantType:    "unknown_grant",
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL: "https://idp.test.ts.net",
			}

			form := url.Values{
				"grant_type": {tt.grantType},
			}

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.serveToken(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rr.Code)
			}

			// Check JSON error response per RFC 6749
			var errResp map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("expected JSON error response, got: %s", rr.Body.String())
			}
			if errResp["error"] != "unsupported_grant_type" {
				t.Errorf("expected error code 'unsupported_grant_type', got: %v", errResp["error"])
			}

			// Check required headers per RFC 6749 Section 5.2
			if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
				t.Errorf("expected Content-Type application/json, got: %s", ct)
			}
			if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("expected Cache-Control no-store, got: %s", cc)
			}
			if pragma := rr.Header().Get("Pragma"); pragma != "no-cache" {
				t.Errorf("expected Pragma no-cache, got: %s", pragma)
			}
		})
	}
}

func TestOAuthMetadataRefreshTokenSupport(t *testing.T) {
	s := &idpServer{
		serverURL:   "https://idp.test.ts.net",
		loopbackURL: "http://localhost:8080",
	}

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	s.serveOAuthMetadata(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var metadata oauthAuthorizationServerMetadata
	if err := json.Unmarshal(rr.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	// Check that refresh_token is in grant_types_supported
	found := false
	for _, gt := range metadata.GrantTypesSupported.AsSlice() {
		if gt == "refresh_token" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected refresh_token in grant_types_supported")
	}
}

func TestTokenExpiration(t *testing.T) {
	tests := []struct {
		name         string
		tokenAge     time.Duration
		expectStatus int
		expectError  string
	}{
		{
			name:         "valid access token",
			tokenAge:     -1 * time.Minute, // 1 minute old (still valid)
			expectStatus: http.StatusOK,
		},
		{
			name:         "expired access token",
			tokenAge:     10 * time.Minute,        // 10 minutes old (expired)
			expectStatus: http.StatusUnauthorized, // 401 per RFC 6750
			expectError:  "token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL:   "https://idp.test.ts.net",
				accessToken: make(map[string]*authRequest),
			}

			// Create a test token
			testToken := "test-access-token"
			s.accessToken[testToken] = &authRequest{
				validTill: time.Now().Add(-tt.tokenAge),
				remoteUser: &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						ID:   1,
						Name: "node1.example.ts.net",
						User: tailcfg.UserID(1),
					},
					UserProfile: &tailcfg.UserProfile{
						LoginName:   "user@example.com",
						DisplayName: "Test User",
					},
				},
			}

			req := httptest.NewRequest("GET", "/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+testToken)

			rr := httptest.NewRecorder()
			s.serveUserInfo(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rr.Code)
			}

			if tt.expectError != "" {
				// Check for WWW-Authenticate header as per RFC 6750
				authHeader := rr.Header().Get("WWW-Authenticate")
				if authHeader == "" {
					t.Error("expected WWW-Authenticate header for Bearer token error")
				}
				if !strings.Contains(authHeader, `error="invalid_token"`) {
					t.Errorf("expected WWW-Authenticate header with invalid_token error, got: %s", authHeader)
				}
				if !strings.Contains(authHeader, tt.expectError) {
					t.Errorf("expected error description containing %q in WWW-Authenticate header, got: %s", tt.expectError, authHeader)
				}
				// Verify token was deleted
				if _, exists := s.accessToken[testToken]; exists {
					t.Error("expected expired token to be deleted")
				}
			}
		})
	}
}

func TestCleanupExpiredTokens(t *testing.T) {
	s := &idpServer{
		accessToken:  make(map[string]*authRequest),
		refreshToken: make(map[string]*authRequest),
	}

	now := time.Now()

	// Add various tokens with different expiration times
	s.accessToken["valid-access"] = &authRequest{validTill: now.Add(1 * time.Minute)}
	s.accessToken["expired-access-1"] = &authRequest{validTill: now.Add(-1 * time.Minute)}
	s.accessToken["expired-access-2"] = &authRequest{validTill: now.Add(-10 * time.Minute)}

	s.refreshToken["valid-refresh"] = &authRequest{validTill: now.Add(24 * time.Hour)}
	s.refreshToken["expired-refresh-1"] = &authRequest{validTill: now.Add(-1 * time.Hour)}
	s.refreshToken["expired-refresh-2"] = &authRequest{validTill: now.Add(-24 * time.Hour)}

	// Run cleanup
	s.cleanupExpiredTokens()

	// Check that only valid tokens remain
	if len(s.accessToken) != 1 {
		t.Errorf("expected 1 valid access token, got %d", len(s.accessToken))
	}
	if _, exists := s.accessToken["valid-access"]; !exists {
		t.Error("valid access token was incorrectly deleted")
	}

	if len(s.refreshToken) != 1 {
		t.Errorf("expected 1 valid refresh token, got %d", len(s.refreshToken))
	}
	if _, exists := s.refreshToken["valid-refresh"]; !exists {
		t.Error("valid refresh token was incorrectly deleted")
	}
}

func TestResourceIndicators(t *testing.T) {
	tests := []struct {
		name               string
		authorizationQuery string
		tokenFormData      url.Values
		capMapRules        []stsCapRule
		expectStatus       int
		checkResponse      func(t *testing.T, body []byte)
	}{
		{
			name:               "authorization with single resource",
			authorizationQuery: "client_id=test-client&redirect_uri=https://example.com/callback&resource=https://api.example.com",
			tokenFormData: url.Values{
				"grant_type":   {"authorization_code"},
				"redirect_uri": {"https://example.com/callback"},
			},
			capMapRules: []stsCapRule{
				{
					Users:     []string{"*"},
					Resources: []string{"https://api.example.com"},
				},
			},
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var resp oidcTokenResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				// Decode JWT to check audience
				token, err := jwt.ParseSigned(resp.IDToken)
				if err != nil {
					t.Fatalf("failed to parse JWT: %v", err)
				}
				var claims map[string]interface{}
				if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
					t.Fatalf("failed to get claims: %v", err)
				}
				aud, ok := claims["aud"].([]interface{})
				if !ok {
					t.Fatalf("expected aud to be an array, got %T", claims["aud"])
				}
				if len(aud) != 2 || aud[0] != "test-client" || aud[1] != "https://api.example.com" {
					t.Errorf("expected audience [test-client, https://api.example.com], got %v", aud)
				}
			},
		},
		{
			name:               "authorization with multiple resources",
			authorizationQuery: "client_id=test-client&redirect_uri=https://example.com/callback&resource=https://api1.example.com&resource=https://api2.example.com",
			tokenFormData: url.Values{
				"grant_type":   {"authorization_code"},
				"redirect_uri": {"https://example.com/callback"},
			},
			capMapRules: []stsCapRule{
				{
					Users:     []string{"*"},
					Resources: []string{"*"}, // Allow all resources
				},
			},
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var resp oidcTokenResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				// Decode JWT to check audience
				token, err := jwt.ParseSigned(resp.IDToken)
				if err != nil {
					t.Fatalf("failed to parse JWT: %v", err)
				}
				var claims map[string]interface{}
				if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
					t.Fatalf("failed to get claims: %v", err)
				}
				aud, ok := claims["aud"].([]interface{})
				if !ok {
					t.Fatalf("expected aud to be an array, got %T", claims["aud"])
				}
				if len(aud) != 3 {
					t.Errorf("expected 3 audience values, got %d", len(aud))
				}
			},
		},
		{
			name:               "token request with resource parameter",
			authorizationQuery: "client_id=test-client&redirect_uri=https://example.com/callback",
			tokenFormData: url.Values{
				"grant_type":   {"authorization_code"},
				"redirect_uri": {"https://example.com/callback"},
				"resource":     {"https://api.example.com"},
			},
			capMapRules: []stsCapRule{
				{
					Users:     []string{"user@example.com"},
					Resources: []string{"https://api.example.com"},
				},
			},
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var resp oidcTokenResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp.AccessToken == "" {
					t.Error("expected access token")
				}
			},
		},
		{
			name:               "unauthorized resource request",
			authorizationQuery: "client_id=test-client&redirect_uri=https://example.com/callback",
			tokenFormData: url.Values{
				"grant_type":   {"authorization_code"},
				"redirect_uri": {"https://example.com/callback"},
				"resource":     {"https://unauthorized.example.com"},
			},
			capMapRules: []stsCapRule{
				{
					Users:     []string{"user@example.com"},
					Resources: []string{"https://api.example.com"},
				},
			},
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL:     "https://idp.test.ts.net",
				code:          make(map[string]*authRequest),
				accessToken:   make(map[string]*authRequest),
				refreshToken:  make(map[string]*authRequest),
				funnelClients: make(map[string]*funnelClient),
			}

			// Parse authorization query
			authQuery, _ := url.ParseQuery(tt.authorizationQuery)

			// Create mock authRequest
			code := "test-code"
			ar := &authRequest{
				funnelRP: &funnelClient{
					ID:           "test-client",
					Secret:       "test-secret",
					RedirectURIs: []string{"https://example.com/callback"},
				},
				clientID:    authQuery.Get("client_id"),
				redirectURI: authQuery.Get("redirect_uri"),
				resources:   authQuery["resource"],
				remoteUser: &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						ID:   1,
						Name: "node1.example.ts.net",
						User: tailcfg.UserID(1),
						Key:  key.NodePublic{},
						Addresses: []netip.Prefix{
							netip.MustParsePrefix("100.64.0.1/32"),
						},
					},
					UserProfile: &tailcfg.UserProfile{
						LoginName:   "user@example.com",
						DisplayName: "Test User",
					},
					CapMap: tailcfg.PeerCapMap{
						"test-tailscale.com/idp/sts/openly-allow": marshalCapRules(tt.capMapRules),
					},
				},
				validTill: time.Now().Add(5 * time.Minute),
			}

			s.funnelClients["test-client"] = ar.funnelRP
			s.code[code] = ar

			// Add code to form data
			tt.tokenFormData.Set("code", code)
			tt.tokenFormData.Set("client_id", "test-client")
			tt.tokenFormData.Set("client_secret", "test-secret")

			req := httptest.NewRequest("POST", "/token", strings.NewReader(tt.tokenFormData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.serveToken(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectStatus, rr.Code, rr.Body.String())
			}

			if tt.checkResponse != nil && rr.Code == http.StatusOK {
				tt.checkResponse(t, rr.Body.Bytes())
			}
		})
	}
}

// marshalCapRules is a helper to convert stsCapRule slice to JSON for testing
func marshalCapRules(rules []stsCapRule) []tailcfg.RawMessage {
	// UnmarshalCapJSON expects each rule to be a separate RawMessage
	var msgs []tailcfg.RawMessage
	for _, rule := range rules {
		data, _ := json.Marshal(rule)
		msgs = append(msgs, tailcfg.RawMessage(data))
	}
	return msgs
}

func TestRefreshTokenWithResources(t *testing.T) {
	tests := []struct {
		name              string
		originalResources []string
		refreshResources  []string
		capMapRules       []stsCapRule
		expectStatus      int
		expectError       string
	}{
		{
			name:              "refresh with resource downscoping",
			originalResources: []string{"https://api1.example.com", "https://api2.example.com"},
			refreshResources:  []string{"https://api1.example.com"},
			capMapRules: []stsCapRule{
				{
					Users:     []string{"*"},
					Resources: []string{"*"},
				},
			},
			expectStatus: http.StatusOK,
		},
		{
			name:              "refresh with resource not in original grant",
			originalResources: []string{"https://api1.example.com"},
			refreshResources:  []string{"https://api2.example.com"},
			capMapRules: []stsCapRule{
				{
					Users:     []string{"*"},
					Resources: []string{"*"},
				},
			},
			expectStatus: http.StatusBadRequest,
			expectError:  "requested resource not in original grant",
		},
		{
			name:              "refresh without resource parameter",
			originalResources: []string{"https://api1.example.com"},
			refreshResources:  nil,
			capMapRules: []stsCapRule{
				{
					Users:     []string{"*"},
					Resources: []string{"*"},
				},
			},
			expectStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL:     "https://idp.test.ts.net",
				refreshToken:  make(map[string]*authRequest),
				funnelClients: make(map[string]*funnelClient),
			}

			// Create refresh token
			rt := "test-refresh-token"
			ar := &authRequest{
				funnelRP: &funnelClient{
					ID:     "test-client",
					Secret: "test-secret",
				},
				clientID:  "test-client",
				resources: tt.originalResources,
				validTill: time.Now().Add(time.Hour),
				remoteUser: &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						ID:   1,
						Name: "node1.example.ts.net",
						User: tailcfg.UserID(1),
						Key:  key.NodePublic{},
					},
					UserProfile: &tailcfg.UserProfile{
						LoginName:   "user@example.com",
						DisplayName: "Test User",
					},
					CapMap: tailcfg.PeerCapMap{
						"test-tailscale.com/idp/sts/openly-allow": marshalCapRules(tt.capMapRules),
					},
				},
			}
			s.refreshToken[rt] = ar
			s.funnelClients["test-client"] = ar.funnelRP

			// Create request
			form := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {rt},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			}
			for _, res := range tt.refreshResources {
				form.Add("resource", res)
			}

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.serveToken(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectStatus, rr.Code, rr.Body.String())
			}

			if tt.expectError != "" && !strings.Contains(rr.Body.String(), tt.expectError) {
				t.Errorf("expected error containing %q, got %q", tt.expectError, rr.Body.String())
			}
		})
	}
}

func TestIntrospectTokenExpiration(t *testing.T) {
	s := &idpServer{
		serverURL:     "https://idp.test.ts.net",
		accessToken:   make(map[string]*authRequest),
		funnelClients: make(map[string]*funnelClient),
	}

	// Create an expired token
	expiredToken := "expired-token"
	s.accessToken[expiredToken] = &authRequest{
		validTill: time.Now().Add(-10 * time.Minute), // expired
		funnelRP: &funnelClient{
			ID:     "test-client",
			Secret: "test-secret",
		},
		clientID: "test-client",
	}

	// Set up the funnel client
	s.funnelClients["test-client"] = &funnelClient{
		ID:     "test-client",
		Secret: "test-secret",
	}

	form := url.Values{}
	form.Set("token", expiredToken)
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	s.serveIntrospect(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Check response shows token as inactive
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if active, ok := resp["active"].(bool); !ok || active {
		t.Error("expected active: false for expired token")
	}

	// Verify token was deleted
	if _, exists := s.accessToken[expiredToken]; exists {
		t.Error("expected expired token to be deleted from introspection")
	}
}

func TestIntrospectWithResources(t *testing.T) {
	s := &idpServer{
		serverURL:     "https://idp.test.ts.net",
		accessToken:   make(map[string]*authRequest),
		funnelClients: make(map[string]*funnelClient),
	}

	// Create a token with resources
	activeToken := "active-token-with-resources"
	s.accessToken[activeToken] = &authRequest{
		validTill: time.Now().Add(10 * time.Minute), // not expired
		funnelRP: &funnelClient{
			ID:     "test-client",
			Secret: "test-secret",
		},
		clientID:  "test-client",
		resources: []string{"https://api1.example.com", "https://api2.example.com"},
		scopes:    []string{"openid", "email"}, // Add scopes for testing
		jti:       "test-jti-12345",            // Add JTI for testing new claim
		remoteUser: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				User: 12345,
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "user@example.com",
			},
		},
	}

	// Set up the funnel client
	s.funnelClients["test-client"] = &funnelClient{
		ID:     "test-client",
		Secret: "test-secret",
	}

	form := url.Values{}
	form.Set("token", activeToken)
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	s.serveIntrospect(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Check response shows token as active with resources in audience
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if active, ok := resp["active"].(bool); !ok || !active {
		t.Error("expected active: true for valid token")
	}

	// Check token_type is present and set to Bearer
	if tokenType, ok := resp["token_type"].(string); !ok || tokenType != "Bearer" {
		t.Errorf("expected token_type to be 'Bearer', got: %v", resp["token_type"])
	}

	// Check audience includes client_id and resources
	aud, ok := resp["aud"].([]interface{})
	if !ok {
		t.Fatalf("expected aud to be an array, got %T", resp["aud"])
	}

	expectedAud := []string{"test-client", "https://api1.example.com", "https://api2.example.com"}
	if len(aud) != len(expectedAud) {
		t.Errorf("expected %d audience values, got %d", len(expectedAud), len(aud))
	}

	// Convert to string slice for comparison
	audStrings := make([]string, len(aud))
	for i, v := range aud {
		audStrings[i], ok = v.(string)
		if !ok {
			t.Fatalf("expected audience value to be string, got %T", v)
		}
	}

	// Check all expected values are present
	for _, expected := range expectedAud {
		found := false
		for _, actual := range audStrings {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected audience to contain %q", expected)
		}
	}

	// Check scope is present in introspection response
	if scope, ok := resp["scope"].(string); !ok {
		t.Error("expected scope in introspection response")
	} else if scope != "openid email" {
		t.Errorf("expected scope to be 'openid email', got %q", scope)
	}
}

func TestIntrospectionRFC7662Compliance(t *testing.T) {
	s := &idpServer{
		serverURL:     "https://idp.test.ts.net",
		loopbackURL:   "http://localhost:8080",
		accessToken:   make(map[string]*authRequest),
		funnelClients: make(map[string]*funnelClient),
	}

	// Create a token with all fields populated
	activeToken := "test-token-rfc-compliance"
	now := time.Now()
	s.accessToken[activeToken] = &authRequest{
		validTill: now.Add(10 * time.Minute),
		funnelRP: &funnelClient{
			ID:     "test-client",
			Secret: "test-secret",
		},
		clientID:  "test-client",
		resources: []string{"https://api.example.com"},
		scopes:    []string{"openid", "profile", "email"},
		jti:       "unique-jwt-id-12345",
		remoteUser: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				User: 12345,
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName:     "user@example.com",
				DisplayName:   "Test User",
				ProfilePicURL: "https://example.com/pic.jpg",
			},
		},
	}

	// Set up the funnel client
	s.funnelClients["test-client"] = &funnelClient{
		ID:     "test-client",
		Secret: "test-secret",
	}

	form := url.Values{}
	form.Set("token", activeToken)
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	s.serveIntrospect(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Check all RFC 7662 required and recommended claims
	requiredClaims := map[string]bool{
		"active":             true,
		"client_id":          true,
		"exp":                true,
		"iat":                true,
		"nbf":                true, // NEW
		"sub":                true,
		"aud":                true,
		"iss":                true, // NEW
		"jti":                true, // NEW
		"username":           true, // NEW
		"token_type":         true,
		"scope":              true,
		"email":              true, // from scope
		"preferred_username": true, // from scope
		"picture":            true, // from scope
	}

	for claim, required := range requiredClaims {
		if _, ok := resp[claim]; !ok && required {
			t.Errorf("missing required claim: %s", claim)
		}
	}

	// Verify specific claim values
	if username, ok := resp["username"].(string); !ok || username != "user@example.com" {
		t.Errorf("expected username to be 'user@example.com', got: %v", resp["username"])
	}

	if iss, ok := resp["iss"].(string); !ok || iss != s.serverURL {
		t.Errorf("expected iss to be '%s', got: %v", s.serverURL, resp["iss"])
	}

	if jti, ok := resp["jti"].(string); !ok || jti != "unique-jwt-id-12345" {
		t.Errorf("expected jti to be 'unique-jwt-id-12345', got: %v", resp["jti"])
	}

	// Check that nbf is set and equals iat
	if nbf, ok := resp["nbf"].(float64); ok {
		if iat, ok := resp["iat"].(float64); ok {
			if nbf != iat {
				t.Errorf("expected nbf to equal iat, got nbf=%v, iat=%v", nbf, iat)
			}
		}
	} else {
		t.Error("nbf claim missing or wrong type")
	}
}

func TestRefreshTokenScopePreservation(t *testing.T) {
	s := &idpServer{
		serverURL:     "https://idp.test.ts.net",
		refreshToken:  make(map[string]*authRequest),
		funnelClients: make(map[string]*funnelClient),
	}

	// Create refresh token with specific scopes
	rt := "test-refresh-token-scopes"
	originalScopes := []string{"openid", "profile"}
	s.refreshToken[rt] = &authRequest{
		funnelRP: &funnelClient{
			ID:     "test-client",
			Secret: "test-secret",
		},
		clientID:  "test-client",
		scopes:    originalScopes,
		validTill: time.Now().Add(time.Hour),
		remoteUser: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				ID:   1,
				Name: "node1.example.ts.net",
				User: tailcfg.UserID(1),
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName:   "user@example.com",
				DisplayName: "Test User",
			},
		},
	}
	s.funnelClients["test-client"] = &funnelClient{
		ID:     "test-client",
		Secret: "test-secret",
	}

	// Issue new tokens using refresh token
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	s.serveToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Parse response to get new access token
	var tokenResp oidcTokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("failed to unmarshal token response: %v", err)
	}

	// Verify the new access token has the same scopes
	if newAR, ok := s.accessToken[tokenResp.AccessToken]; ok {
		if len(newAR.scopes) != len(originalScopes) {
			t.Errorf("new access token has %d scopes, expected %d", len(newAR.scopes), len(originalScopes))
		}
		for i, scope := range newAR.scopes {
			if i < len(originalScopes) && scope != originalScopes[i] {
				t.Errorf("scope[%d] = %q, expected %q", i, scope, originalScopes[i])
			}
		}
	} else {
		t.Error("new access token not found in server state")
	}

	// Verify the new refresh token also has the same scopes
	if newRT, ok := s.refreshToken[tokenResp.RefreshToken]; ok {
		if len(newRT.scopes) != len(originalScopes) {
			t.Errorf("new refresh token has %d scopes, expected %d", len(newRT.scopes), len(originalScopes))
		}
	} else {
		t.Error("new refresh token not found in server state")
	}
}

func TestAZPClaimWithMultipleAudiences(t *testing.T) {
	tests := []struct {
		name              string
		resources         []string
		expectAZP         bool
		expectedAudiences int
	}{
		{
			name:              "single audience - no azp",
			resources:         []string{},
			expectAZP:         false,
			expectedAudiences: 1, // just client_id
		},
		{
			name:              "multiple audiences - azp required",
			resources:         []string{"https://api1.example.com", "https://api2.example.com"},
			expectAZP:         true,
			expectedAudiences: 3, // client_id + 2 resources
		},
		{
			name:              "single resource - azp required",
			resources:         []string{"https://api.example.com"},
			expectAZP:         true,
			expectedAudiences: 2, // client_id + 1 resource
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL:     "https://idp.test.ts.net",
				code:          make(map[string]*authRequest),
				accessToken:   make(map[string]*authRequest),
				refreshToken:  make(map[string]*authRequest),
				funnelClients: make(map[string]*funnelClient),
			}

			// Set up funnel client
			s.funnelClients["test-client"] = &funnelClient{
				ID:           "test-client",
				Secret:       "test-secret",
				RedirectURIs: []string{"https://example.com/callback"},
			}

			// Create auth request
			code := "test-code"
			ar := &authRequest{
				funnelRP:    s.funnelClients["test-client"],
				clientID:    "test-client",
				redirectURI: "https://example.com/callback",
				resources:   tt.resources,
				scopes:      []string{"openid"},
				remoteUser: &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						ID:   1,
						Name: "node1.example.ts.net",
						User: tailcfg.UserID(1),
					},
					UserProfile: &tailcfg.UserProfile{
						LoginName: "user@example.com",
					},
				},
				validTill: time.Now().Add(5 * time.Minute),
			}
			s.code[code] = ar

			// Exchange code for token
			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {"https://example.com/callback"},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			}

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.serveToken(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
			}

			var tokenResp oidcTokenResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &tokenResp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			// Parse the ID token
			token, err := jwt.ParseSigned(tokenResp.IDToken)
			if err != nil {
				t.Fatalf("failed to parse JWT: %v", err)
			}

			var claims map[string]interface{}
			if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
				t.Fatalf("failed to get claims: %v", err)
			}

			// Check audience
			aud, ok := claims["aud"]
			if !ok {
				t.Fatal("aud claim not found")
			}

			// The JWT library always serializes audience as an array
			audArray, isArray := aud.([]interface{})
			if !isArray {
				t.Errorf("expected audience to be array, got %T", aud)
			}

			if len(audArray) != tt.expectedAudiences {
				t.Errorf("expected %d audiences, got %d", tt.expectedAudiences, len(audArray))
			}

			// Check azp claim
			azp, hasAZP := claims["azp"]
			if tt.expectAZP && !hasAZP {
				t.Error("expected azp claim for multiple audiences, but not found")
			}
			if !tt.expectAZP && hasAZP {
				t.Error("unexpected azp claim for single audience")
			}
			if hasAZP {
				azpStr, ok := azp.(string)
				if !ok {
					t.Errorf("azp claim should be string, got %T", azp)
				}
				if azpStr != "test-client" {
					t.Errorf("expected azp to be 'test-client', got %s", azpStr)
				}
			}
		})
	}
}

func TestPKCE(t *testing.T) {
	tests := []struct {
		name             string
		authQuery        string
		codeVerifier     string
		expectAuthError  bool
		expectTokenError bool
		checkResponse    func(t *testing.T, body []byte)
	}{
		{
			name:         "valid PKCE with S256 method",
			authQuery:    "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
			codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			// code_challenge = BASE64URL(SHA256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
			// = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
		},
		{
			name:         "valid PKCE with plain method",
			authQuery:    "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=plain",
			codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		{
			name:         "PKCE with default plain method",
			authQuery:    "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		{
			name:             "missing code_verifier",
			authQuery:        "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
			codeVerifier:     "",
			expectTokenError: true,
		},
		{
			name:             "invalid code_verifier",
			authQuery:        "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
			codeVerifier:     "wrong-verifier-that-does-not-match-the-challenge",
			expectTokenError: true,
		},
		{
			name:            "unsupported code_challenge_method",
			authQuery:       "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=test&code_challenge_method=invalid",
			expectAuthError: true,
		},
		{
			name:             "code_verifier too short",
			authQuery:        "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=short&code_challenge_method=plain",
			codeVerifier:     "short", // less than 43 characters
			expectTokenError: true,
		},
		{
			name:             "code_verifier too long",
			authQuery:        "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=" + strings.Repeat("a", 129) + "&code_challenge_method=plain",
			codeVerifier:     strings.Repeat("a", 129), // more than 128 characters
			expectTokenError: true,
		},
		{
			name:             "code_verifier with invalid characters",
			authQuery:        "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX!&code_challenge_method=plain",
			codeVerifier:     "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX!", // contains '!' which is invalid
			expectTokenError: true,
		},
		{
			name:         "no PKCE parameters - backward compatibility",
			authQuery:    "client_id=test-client&redirect_uri=https://example.com/callback",
			codeVerifier: "", // no code_verifier sent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL:     "https://idp.test.ts.net",
				code:          make(map[string]*authRequest),
				accessToken:   make(map[string]*authRequest),
				refreshToken:  make(map[string]*authRequest),
				funnelClients: make(map[string]*funnelClient),
			}

			// Set up funnel client
			s.funnelClients["test-client"] = &funnelClient{
				ID:           "test-client",
				Secret:       "test-secret",
				RedirectURIs: []string{"https://example.com/callback"},
			}

			// Parse authorization query
			authValues, _ := url.ParseQuery(tt.authQuery)

			// Create mock authRequest based on authorization
			code := "test-code"
			ar := &authRequest{
				funnelRP:    s.funnelClients["test-client"],
				clientID:    authValues.Get("client_id"),
				redirectURI: authValues.Get("redirect_uri"),
				remoteUser: &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						ID:   1,
						Name: "node1.example.ts.net",
						User: tailcfg.UserID(1),
					},
					UserProfile: &tailcfg.UserProfile{
						LoginName:   "user@example.com",
						DisplayName: "Test User",
					},
				},
				validTill: time.Now().Add(5 * time.Minute),
				scopes:    []string{"openid"},
			}

			// Handle PKCE parameters from authorization
			if codeChallenge := authValues.Get("code_challenge"); codeChallenge != "" {
				ar.codeChallenge = codeChallenge
				ar.codeChallengeMethod = authValues.Get("code_challenge_method")
				if ar.codeChallengeMethod == "" {
					ar.codeChallengeMethod = "plain"
				}
			}

			// Check for auth errors first (unsupported method)
			if tt.expectAuthError {
				if ar.codeChallengeMethod != "" && ar.codeChallengeMethod != "plain" && ar.codeChallengeMethod != "S256" {
					// Expected error - unsupported method
					return
				}
			}

			s.code[code] = ar

			// Now test token exchange
			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {ar.redirectURI},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			}
			if tt.codeVerifier != "" {
				form.Set("code_verifier", tt.codeVerifier)
			}

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.serveToken(rr, req)

			if tt.expectTokenError {
				if rr.Code == http.StatusOK {
					t.Errorf("expected token error, got status 200")
				}
			} else {
				if rr.Code != http.StatusOK {
					t.Errorf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
				}
			}

			if tt.checkResponse != nil && rr.Code == http.StatusOK {
				tt.checkResponse(t, rr.Body.Bytes())
			}
		})
	}
}

func TestPKCEMetadata(t *testing.T) {
	s := &idpServer{
		serverURL:   "https://idp.test.ts.net",
		loopbackURL: "http://localhost:8080",
	}

	tests := []struct {
		name     string
		endpoint string
		checkFn  func(t *testing.T, metadata map[string]interface{})
	}{
		{
			name:     "OpenID Connect metadata",
			endpoint: "/.well-known/openid-configuration",
			checkFn: func(t *testing.T, metadata map[string]interface{}) {
				methods, ok := metadata["code_challenge_methods_supported"].([]interface{})
				if !ok {
					t.Fatal("code_challenge_methods_supported not found or wrong type")
				}
				if len(methods) != 2 {
					t.Errorf("expected 2 methods, got %d", len(methods))
				}
				expectedMethods := map[string]bool{"plain": true, "S256": true}
				for _, m := range methods {
					method, ok := m.(string)
					if !ok {
						t.Errorf("method is not a string: %T", m)
						continue
					}
					if !expectedMethods[method] {
						t.Errorf("unexpected method: %s", method)
					}
					delete(expectedMethods, method)
				}
				if len(expectedMethods) > 0 {
					t.Errorf("missing methods: %v", expectedMethods)
				}
			},
		},
		{
			name:     "OAuth 2.0 metadata",
			endpoint: "/.well-known/oauth-authorization-server",
			checkFn: func(t *testing.T, metadata map[string]interface{}) {
				methods, ok := metadata["code_challenge_methods_supported"].([]interface{})
				if !ok {
					t.Fatal("code_challenge_methods_supported not found or wrong type")
				}
				if len(methods) != 2 {
					t.Errorf("expected 2 methods, got %d", len(methods))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.endpoint, nil)
			req.RemoteAddr = "127.0.0.1:12345"

			rr := httptest.NewRecorder()

			if strings.Contains(tt.endpoint, "openid") {
				s.serveOpenIDConfig(rr, req)
			} else {
				s.serveOAuthMetadata(rr, req)
			}

			if rr.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d", rr.Code)
			}

			var metadata map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &metadata); err != nil {
				t.Fatalf("failed to unmarshal metadata: %v", err)
			}

			tt.checkFn(t, metadata)
		})
	}
}

func TestPKCEWithRefreshToken(t *testing.T) {
	s := &idpServer{
		serverURL:     "https://idp.test.ts.net",
		code:          make(map[string]*authRequest),
		accessToken:   make(map[string]*authRequest),
		refreshToken:  make(map[string]*authRequest),
		funnelClients: make(map[string]*funnelClient),
	}

	// Set up funnel client
	s.funnelClients["test-client"] = &funnelClient{
		ID:           "test-client",
		Secret:       "test-secret",
		RedirectURIs: []string{"https://example.com/callback"},
	}

	// Step 1: Initial authorization with PKCE
	code := "test-code"
	ar := &authRequest{
		funnelRP:            s.funnelClients["test-client"],
		clientID:            "test-client",
		redirectURI:         "https://example.com/callback",
		codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		codeChallengeMethod: "S256",
		scopes:              []string{"openid", "offline_access"},
		remoteUser: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				ID:        1,
				Name:      "node1.example.ts.net",
				User:      tailcfg.UserID(1),
				Key:       key.NodePublic{},
				Addresses: []netip.Prefix{},
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName:   "user@example.com",
				DisplayName: "Test User",
			},
		},
		validTill: time.Now().Add(5 * time.Minute),
	}
	s.code[code] = ar

	// Step 2: Exchange code for tokens with code_verifier
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	s.serveToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("initial token request failed: %d: %s", rr.Code, rr.Body.String())
	}

	var tokenResp oidcTokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("failed to unmarshal token response: %v", err)
	}

	if tokenResp.RefreshToken == "" {
		t.Fatal("expected refresh token in response")
	}

	// Step 3: Use refresh token (should work without code_verifier)
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenResp.RefreshToken},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}

	refreshReq := httptest.NewRequest("POST", "/token", strings.NewReader(refreshForm.Encode()))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	refreshRR := httptest.NewRecorder()
	s.serveToken(refreshRR, refreshReq)

	if refreshRR.Code != http.StatusOK {
		t.Errorf("refresh token request failed: %d: %s", refreshRR.Code, refreshRR.Body.String())
	}

	var refreshResp oidcTokenResponse
	if err := json.Unmarshal(refreshRR.Body.Bytes(), &refreshResp); err != nil {
		t.Fatalf("failed to unmarshal refresh response: %v", err)
	}

	if refreshResp.AccessToken == "" {
		t.Error("expected new access token from refresh")
	}
	if refreshResp.RefreshToken == "" {
		t.Error("expected new refresh token from refresh")
	}
}

func TestScopeHandling(t *testing.T) {
	tests := []struct {
		name            string
		authQuery       string
		expectedScopes  []string
		expectAuthError bool
	}{
		{
			name:           "single valid scope",
			authQuery:      "client_id=test-client&redirect_uri=https://example.com/callback&scope=openid",
			expectedScopes: []string{"openid"},
		},
		{
			name:           "multiple valid scopes",
			authQuery:      "client_id=test-client&redirect_uri=https://example.com/callback&scope=openid email profile",
			expectedScopes: []string{"openid", "email", "profile"},
		},
		{
			name:           "no scope defaults to openid",
			authQuery:      "client_id=test-client&redirect_uri=https://example.com/callback",
			expectedScopes: []string{"openid"},
		},
		{
			name:            "invalid scope",
			authQuery:       "client_id=test-client&redirect_uri=https://example.com/callback&scope=openid invalid_scope",
			expectAuthError: true,
		},
		{
			name:           "extra spaces in scope",
			authQuery:      "client_id=test-client&redirect_uri=https://example.com/callback&scope=openid    email   profile",
			expectedScopes: []string{"openid", "email", "profile"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL:     "https://idp.test.ts.net",
				code:          make(map[string]*authRequest),
				accessToken:   make(map[string]*authRequest),
				funnelClients: make(map[string]*funnelClient),
			}

			// Set up funnel client
			s.funnelClients["test-client"] = &funnelClient{
				ID:           "test-client",
				Secret:       "test-secret",
				RedirectURIs: []string{"https://example.com/callback"},
			}

			// Parse query
			authValues, _ := url.ParseQuery(tt.authQuery)

			// Create mock authRequest
			code := "test-code"
			ar := &authRequest{
				funnelRP:    s.funnelClients["test-client"],
				clientID:    authValues.Get("client_id"),
				redirectURI: authValues.Get("redirect_uri"),
				remoteUser: &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						ID:   1,
						Name: "node1.example.ts.net",
						User: tailcfg.UserID(1),
					},
					UserProfile: &tailcfg.UserProfile{
						LoginName:   "user@example.com",
						DisplayName: "Test User",
					},
				},
				validTill: time.Now().Add(5 * time.Minute),
			}

			// Parse and validate scopes
			if scopeParam := authValues.Get("scope"); scopeParam != "" {
				ar.scopes = strings.Fields(scopeParam)
			}
			validatedScopes, err := s.validateScopes(ar.scopes)

			if tt.expectAuthError {
				if err == nil {
					t.Error("expected scope validation error")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected scope validation error: %v", err)
				return
			}

			ar.scopes = validatedScopes
			s.code[code] = ar

			// Verify scopes match expected
			if len(ar.scopes) != len(tt.expectedScopes) {
				t.Errorf("expected %d scopes, got %d", len(tt.expectedScopes), len(ar.scopes))
			}
			for i, scope := range ar.scopes {
				if i < len(tt.expectedScopes) && scope != tt.expectedScopes[i] {
					t.Errorf("expected scope[%d] = %q, got %q", i, tt.expectedScopes[i], scope)
				}
			}

			// Test token endpoint preserves scopes
			if !tt.expectAuthError {
				form := url.Values{
					"grant_type":    {"authorization_code"},
					"code":          {code},
					"redirect_uri":  {ar.redirectURI},
					"client_id":     {"test-client"},
					"client_secret": {"test-secret"},
				}

				req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				rr := httptest.NewRecorder()
				s.serveToken(rr, req)

				if rr.Code != http.StatusOK {
					t.Errorf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
				}

				// Verify the issued access token has the correct scopes
				var tokenResp oidcTokenResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &tokenResp); err != nil {
					t.Fatalf("failed to unmarshal token response: %v", err)
				}

				if tokenAR, ok := s.accessToken[tokenResp.AccessToken]; ok {
					if len(tokenAR.scopes) != len(tt.expectedScopes) {
						t.Errorf("access token has %d scopes, expected %d", len(tokenAR.scopes), len(tt.expectedScopes))
					}
				} else {
					t.Error("access token not found in server state")
				}
			}
		})
	}
}
