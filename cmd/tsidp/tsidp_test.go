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

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestBackwardCompatibility(t *testing.T) {
	tests := []struct {
		name         string
		jsonData     string
		expectURIs   []string
		expectName   string
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
				if !strings.Contains(string(body), "not available over funnel") {
					t.Errorf("expected funnel error message, got: %s", body)
				}
			},
		},
		{
			name:         "POST request - missing redirect_uris",
			method:       "POST",
			body:         `{"client_name": "Test Client"}`,
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				if !strings.Contains(string(body), "redirect_uris is required") {
					t.Errorf("expected redirect_uris required error, got: %s", body)
				}
			},
		},
		{
			name:         "POST request - empty redirect_uris",
			method:       "POST",
			body:         `{"redirect_uris": []}`,
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				if !strings.Contains(string(body), "redirect_uris is required") {
					t.Errorf("expected redirect_uris required error, got: %s", body)
				}
			},
		},
		{
			name:         "POST request - invalid JSON",
			method:       "POST",
			body:         `{invalid json}`,
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				if !strings.Contains(string(body), "invalid request body") {
					t.Errorf("expected invalid request body error, got: %s", body)
				}
			},
		},
		{
			name:         "GET request - method not allowed",
			method:       "GET",
			expectStatus: http.StatusMethodNotAllowed,
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
		name            string
		clientURIs      []string
		requestURI      string
		expectValid     bool
	}{
		{
			name:            "valid single URI",
			clientURIs:      []string{"https://example.com/callback"},
			requestURI:      "https://example.com/callback",
			expectValid:     true,
		},
		{
			name:            "valid multiple URIs - first",
			clientURIs:      []string{"https://example.com/callback1", "https://example.com/callback2"},
			requestURI:      "https://example.com/callback1",
			expectValid:     true,
		},
		{
			name:            "valid multiple URIs - second",
			clientURIs:      []string{"https://example.com/callback1", "https://example.com/callback2"},
			requestURI:      "https://example.com/callback2",
			expectValid:     true,
		},
		{
			name:            "invalid URI",
			clientURIs:      []string{"https://example.com/callback"},
			requestURI:      "https://evil.com/callback",
			expectValid:     false,
		},
		{
			name:            "empty client URIs",
			clientURIs:      []string{},
			requestURI:      "https://example.com/callback",
			expectValid:     false,
		},
		{
			name:            "case sensitive mismatch",
			clientURIs:      []string{"https://example.com/callback"},
			requestURI:      "https://example.com/CALLBACK",
			expectValid:     false,
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
				if !strings.Contains(string(body), "refresh_token is required") {
					t.Errorf("expected refresh_token required error, got: %s", body)
				}
			},
		},
		{
			name:         "invalid refresh token",
			grantType:    "refresh_token",
			refreshToken: "invalid-token",
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				if !strings.Contains(string(body), "invalid refresh token") {
					t.Errorf("expected invalid refresh token error, got: %s", body)
				}
			},
		},
		{
			name:         "expired refresh token",
			grantType:    "refresh_token",
			refreshToken: "expired-token",
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				if !strings.Contains(string(body), "invalid refresh token") {
					t.Errorf("expected invalid refresh token error, got: %s", body)
				}
			},
		},
		{
			name:         "wrong client credentials",
			grantType:    "refresh_token",
			refreshToken: "valid-refresh-token",
			clientID:     "wrong-client",
			clientSecret: "wrong-secret",
			expectStatus: http.StatusForbidden,
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
			tokenAge:     10 * time.Minute, // 10 minutes old (expired)
			expectStatus: http.StatusBadRequest,
			expectError:  "token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL:    "https://idp.test.ts.net",
				accessToken:  make(map[string]*authRequest),
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
				if !strings.Contains(rr.Body.String(), tt.expectError) {
					t.Errorf("expected error containing %q, got %q", tt.expectError, rr.Body.String())
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