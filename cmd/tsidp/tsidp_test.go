// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
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