// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// normalizeMap recursively sorts []any values in a map[string]any
func normalizeMap(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	normalized := make(map[string]any, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case []any:
			sorted := make([]string, len(val))
			for i, item := range val {
				sorted[i] = fmt.Sprintf("%v", item) // convert everything to string for sorting
			}
			sort.Strings(sorted)

			// convert back to []any
			sortedIface := make([]any, len(sorted))
			for i, s := range sorted {
				sortedIface[i] = s
			}
			normalized[k] = sortedIface

		default:
			normalized[k] = v
		}
	}
	return normalized
}

func mustMarshalJSON(t *testing.T, v any) tailcfg.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return tailcfg.RawMessage(b)
}

var privateKey *rsa.PrivateKey = nil

func oidcTestingSigner(t *testing.T) jose.Signer {
	t.Helper()
	privKey := mustGeneratePrivateKey(t)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	return sig
}

func oidcTestingPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	privKey := mustGeneratePrivateKey(t)
	return &privKey.PublicKey
}

func mustGeneratePrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	if privateKey != nil {
		return privateKey
	}

	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	return privateKey
}

func TestFlattenExtraClaims(t *testing.T) {
	log.SetOutput(io.Discard) // suppress log output during tests

	tests := []struct {
		name     string
		input    []capRule
		expected map[string]any
	}{
		{
			name: "empty extra claims",
			input: []capRule{
				{ExtraClaims: map[string]any{}},
			},
			expected: map[string]any{},
		},
		{
			name: "string and number values",
			input: []capRule{
				{
					ExtraClaims: map[string]any{
						"featureA": "read",
						"featureB": 42,
					},
				},
			},
			expected: map[string]any{
				"featureA": "read",
				"featureB": "42",
			},
		},
		{
			name: "slice of strings and ints",
			input: []capRule{
				{
					ExtraClaims: map[string]any{
						"roles": []any{"admin", "user", 1},
					},
				},
			},
			expected: map[string]any{
				"roles": []any{"admin", "user", "1"},
			},
		},
		{
			name: "duplicate values deduplicated (slice input)",
			input: []capRule{
				{
					ExtraClaims: map[string]any{
						"foo": []string{"bar", "baz"},
					},
				},
				{
					ExtraClaims: map[string]any{
						"foo": []any{"bar", "qux"},
					},
				},
			},
			expected: map[string]any{
				"foo": []any{"bar", "baz", "qux"},
			},
		},
		{
			name: "ignore unsupported map type, keep valid scalar",
			input: []capRule{
				{
					ExtraClaims: map[string]any{
						"invalid": map[string]any{"bad": "yes"},
						"valid":   "ok",
					},
				},
			},
			expected: map[string]any{
				"valid": "ok",
			},
		},
		{
			name: "scalar first, slice second",
			input: []capRule{
				{ExtraClaims: map[string]any{"foo": "bar"}},
				{ExtraClaims: map[string]any{"foo": []any{"baz"}}},
			},
			expected: map[string]any{
				"foo": []any{"bar", "baz"}, // since first was scalar, second being a slice forces slice output
			},
		},
		{
			name: "conflicting scalar and unsupported map",
			input: []capRule{
				{ExtraClaims: map[string]any{"foo": "bar"}},
				{ExtraClaims: map[string]any{"foo": map[string]any{"bad": "entry"}}},
			},
			expected: map[string]any{
				"foo": "bar", // map should be ignored
			},
		},
		{
			name: "multiple slices with overlap",
			input: []capRule{
				{ExtraClaims: map[string]any{"roles": []any{"admin", "user"}}},
				{ExtraClaims: map[string]any{"roles": []any{"admin", "guest"}}},
			},
			expected: map[string]any{
				"roles": []any{"admin", "user", "guest"},
			},
		},
		{
			name: "slice with unsupported values",
			input: []capRule{
				{ExtraClaims: map[string]any{
					"mixed": []any{"ok", 42, map[string]string{"oops": "fail"}},
				}},
			},
			expected: map[string]any{
				"mixed": []any{"ok", "42"}, // map is ignored
			},
		},
		{
			name: "duplicate scalar value",
			input: []capRule{
				{ExtraClaims: map[string]any{"env": "prod"}},
				{ExtraClaims: map[string]any{"env": "prod"}},
			},
			expected: map[string]any{
				"env": "prod", // not converted to slice
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := flattenExtraClaims(tt.input)

			gotNormalized := normalizeMap(t, got)
			expectedNormalized := normalizeMap(t, tt.expected)

			if !reflect.DeepEqual(gotNormalized, expectedNormalized) {
				t.Errorf("mismatch\nGot:\n%s\nWant:\n%s", gotNormalized, expectedNormalized)
			}
		})
	}
}

func TestExtraClaims(t *testing.T) {
	tests := []struct {
		name        string
		claim       tailscaleClaims
		extraClaims []capRule
		expected    map[string]any
		expectError bool
	}{
		{
			name: "extra claim",
			claim: tailscaleClaims{
				Claims:    jwt.Claims{},
				Nonce:     "foobar",
				Key:       key.NodePublic{},
				Addresses: views.Slice[netip.Prefix]{},
				NodeID:    0,
				NodeName:  "test-node",
				Tailnet:   "test.ts.net",
				Email:     "test@example.com",
				UserID:    0,
				UserName:  "test",
			},
			extraClaims: []capRule{
				{
					ExtraClaims: map[string]any{
						"foo": []string{"bar"},
					},
				},
			},
			expected: map[string]any{
				"nonce":     "foobar",
				"key":       "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
				"addresses": nil,
				"nid":       float64(0),
				"node":      "test-node",
				"tailnet":   "test.ts.net",
				"email":     "test@example.com",
				"username":  "test",
				"foo":       []any{"bar"},
			},
		},
		{
			name: "duplicate claim distinct values",
			claim: tailscaleClaims{
				Claims:    jwt.Claims{},
				Nonce:     "foobar",
				Key:       key.NodePublic{},
				Addresses: views.Slice[netip.Prefix]{},
				NodeID:    0,
				NodeName:  "test-node",
				Tailnet:   "test.ts.net",
				Email:     "test@example.com",
				UserID:    0,
				UserName:  "test",
			},
			extraClaims: []capRule{
				{
					ExtraClaims: map[string]any{
						"foo": []string{"bar"},
					},
				},
				{
					ExtraClaims: map[string]any{
						"foo": []string{"foobar"},
					},
				},
			},
			expected: map[string]any{
				"nonce":     "foobar",
				"key":       "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
				"addresses": nil,
				"nid":       float64(0),
				"node":      "test-node",
				"tailnet":   "test.ts.net",
				"email":     "test@example.com",
				"username":  "test",
				"foo":       []any{"foobar", "bar"},
			},
		},
		{
			name: "multiple extra claims",
			claim: tailscaleClaims{
				Claims:    jwt.Claims{},
				Nonce:     "foobar",
				Key:       key.NodePublic{},
				Addresses: views.Slice[netip.Prefix]{},
				NodeID:    0,
				NodeName:  "test-node",
				Tailnet:   "test.ts.net",
				Email:     "test@example.com",
				UserID:    0,
				UserName:  "test",
			},
			extraClaims: []capRule{
				{
					ExtraClaims: map[string]any{
						"foo": []string{"bar"},
					},
				},
				{
					ExtraClaims: map[string]any{
						"bar": []string{"foo"},
					},
				},
			},
			expected: map[string]any{
				"nonce":     "foobar",
				"key":       "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
				"addresses": nil,
				"nid":       float64(0),
				"node":      "test-node",
				"tailnet":   "test.ts.net",
				"email":     "test@example.com",
				"username":  "test",
				"foo":       []any{"bar"},
				"bar":       []any{"foo"},
			},
		},
		{
			name: "overwrite claim",
			claim: tailscaleClaims{
				Claims:    jwt.Claims{},
				Nonce:     "foobar",
				Key:       key.NodePublic{},
				Addresses: views.Slice[netip.Prefix]{},
				NodeID:    0,
				NodeName:  "test-node",
				Tailnet:   "test.ts.net",
				Email:     "test@example.com",
				UserID:    0,
				UserName:  "test",
			},
			extraClaims: []capRule{
				{
					ExtraClaims: map[string]any{
						"username": "foobar",
					},
				},
			},
			expected: map[string]any{
				"nonce":     "foobar",
				"key":       "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
				"addresses": nil,
				"nid":       float64(0),
				"node":      "test-node",
				"tailnet":   "test.ts.net",
				"email":     "test@example.com",
				"username":  "foobar",
			},
			expectError: true,
		},
		{
			name: "empty extra claims",
			claim: tailscaleClaims{
				Claims:    jwt.Claims{},
				Nonce:     "foobar",
				Key:       key.NodePublic{},
				Addresses: views.Slice[netip.Prefix]{},
				NodeID:    0,
				NodeName:  "test-node",
				Tailnet:   "test.ts.net",
				Email:     "test@example.com",
				UserID:    0,
				UserName:  "test",
			},
			extraClaims: []capRule{{ExtraClaims: map[string]any{}}},
			expected: map[string]any{
				"nonce":     "foobar",
				"key":       "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
				"addresses": nil,
				"nid":       float64(0),
				"node":      "test-node",
				"tailnet":   "test.ts.net",
				"email":     "test@example.com",
				"username":  "test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := withExtraClaims(tt.claim, tt.extraClaims)
			if err != nil && !tt.expectError {
				t.Fatalf("claim.withExtraClaims() unexpected error = %v", err)
			} else if err == nil && tt.expectError {
				t.Fatalf("expected error, got nil")
			} else if err != nil && tt.expectError {
				return // just as expected
			}

			// Marshal to JSON then unmarshal back to map[string]any
			gotClaims, err := json.Marshal(claims)
			if err != nil {
				t.Errorf("json.Marshal(claims) error = %v", err)
			}

			var gotClaimsMap map[string]any
			if err := json.Unmarshal(gotClaims, &gotClaimsMap); err != nil {
				t.Fatalf("json.Unmarshal(gotClaims) error = %v", err)
			}

			gotNormalized := normalizeMap(t, gotClaimsMap)
			expectedNormalized := normalizeMap(t, tt.expected)

			if !reflect.DeepEqual(gotNormalized, expectedNormalized) {
				t.Errorf("claims mismatch:\n got: %#v\nwant: %#v", gotNormalized, expectedNormalized)
			}
		})
	}
}

func TestServeToken(t *testing.T) {
	tests := []struct {
		name        string
		caps        tailcfg.PeerCapMap
		method      string
		grantType   string
		code        string
		omitCode    bool
		redirectURI string
		remoteAddr  string
		expectError bool
		expected    map[string]any
	}{
		{
			name:        "GET not allowed",
			method:      "GET",
			grantType:   "authorization_code",
			expectError: true,
		},
		{
			name:        "unsupported grant type",
			method:      "POST",
			grantType:   "pkcs",
			expectError: true,
		},
		{
			name:        "invalid code",
			method:      "POST",
			grantType:   "authorization_code",
			code:        "invalid-code",
			expectError: true,
		},
		{
			name:        "omit code from form",
			method:      "POST",
			grantType:   "authorization_code",
			omitCode:    true,
			expectError: true,
		},
		{
			name:        "invalid redirect uri",
			method:      "POST",
			grantType:   "authorization_code",
			code:        "valid-code",
			redirectURI: "https://invalid.example.com/callback",
			remoteAddr:  "127.0.0.1:12345",
			expectError: true,
		},
		{
			name:        "invalid remoteAddr",
			method:      "POST",
			grantType:   "authorization_code",
			redirectURI: "https://rp.example.com/callback",
			code:        "valid-code",
			remoteAddr:  "192.168.0.1:12345",
			expectError: true,
		},
		{
			name:        "extra claim included",
			method:      "POST",
			grantType:   "authorization_code",
			redirectURI: "https://rp.example.com/callback",
			code:        "valid-code",
			remoteAddr:  "127.0.0.1:12345",
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: true,
						ExtraClaims: map[string]any{
							"foo": "bar",
						},
					}),
				},
			},
			expected: map[string]any{
				"foo": "bar",
			},
		},
		{
			name:        "attempt to overwrite protected claim",
			method:      "POST",
			grantType:   "authorization_code",
			redirectURI: "https://rp.example.com/callback",
			code:        "valid-code",
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: true,
						ExtraClaims: map[string]any{
							"sub": "should-not-overwrite",
						},
					}),
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()

			// Fake user/node
			profile := &tailcfg.UserProfile{
				LoginName:     "alice@example.com",
				DisplayName:   "Alice Example",
				ProfilePicURL: "https://example.com/alice.jpg",
			}
			node := &tailcfg.Node{
				ID:       123,
				Name:     "test-node.test.ts.net.",
				User:     456,
				Key:      key.NodePublic{},
				Cap:      1,
				DiscoKey: key.DiscoPublic{},
			}

			remoteUser := &apitype.WhoIsResponse{
				Node:        node,
				UserProfile: profile,
				CapMap:      tt.caps,
			}

			s := &idpServer{
				code: map[string]*authRequest{
					"valid-code": {
						clientID:    "client-id",
						nonce:       "nonce123",
						redirectURI: "https://rp.example.com/callback",
						validTill:   now.Add(5 * time.Minute),
						remoteUser:  remoteUser,
						localRP:     true,
					},
				},
			}
			// Inject a working signer
			s.lazySigner.Set(oidcTestingSigner(t))

			form := url.Values{}
			form.Set("grant_type", tt.grantType)
			form.Set("redirect_uri", tt.redirectURI)
			if !tt.omitCode {
				form.Set("code", tt.code)
			}

			req := httptest.NewRequest(tt.method, "/token", strings.NewReader(form.Encode()))
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			s.serveToken(rr, req)

			if tt.expectError {
				if rr.Code == http.StatusOK {
					t.Fatalf("expected error, got 200 OK: %s", rr.Body.String())
				}
				return
			}

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
			}

			var resp struct {
				IDToken string `json:"id_token"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			tok, err := jwt.ParseSigned(resp.IDToken)
			if err != nil {
				t.Fatalf("failed to parse ID token: %v", err)
			}

			out := make(map[string]any)
			if err := tok.Claims(oidcTestingPublicKey(t), &out); err != nil {
				t.Fatalf("failed to extract claims: %v", err)
			}

			for k, want := range tt.expected {
				got, ok := out[k]
				if !ok {
					t.Errorf("missing expected claim %q", k)
					continue
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("claim %q: got %v, want %v", k, got, want)
				}
			}
		})
	}
}

func TestServeIntrospect(t *testing.T) {
	now := time.Now()
	validToken := "valid-access-token"
	expiredToken := "expired-access-token"

	// Create test user and node
	profile := &tailcfg.UserProfile{
		LoginName:     "alice@example.com",
		DisplayName:   "Alice Example",
		ProfilePicURL: "https://example.com/alice.jpg",
	}
	node := &tailcfg.Node{
		ID:       123,
		Name:     "test-node.test.ts.net.",
		User:     456,
		Key:      key.NodePublic{},
		Cap:      1,
		DiscoKey: key.DiscoPublic{},
	}
	remoteUser := &apitype.WhoIsResponse{
		Node:        node,
		UserProfile: profile,
	}

	// Create funnel client for testing
	funnelClient := &funnelClient{
		ID:          "funnel-client-id",
		Secret:      "funnel-client-secret",
		Name:        "Test Funnel Client",
		RedirectURI: "https://funnel.example.com/callback",
	}

	tests := []struct {
		name           string
		method         string
		token          string
		omitToken      bool
		clientID       string
		clientSecret   string
		useBasicAuth   bool
		remoteAddr     string
		authRequest    *authRequest
		expectStatus   int
		expectActive   bool
		expectedFields map[string]any
	}{
		{
			name:         "GET not allowed",
			method:       "GET",
			token:        validToken,
			expectStatus: http.StatusMethodNotAllowed,
		},
		{
			name:         "missing token parameter",
			method:       "POST",
			omitToken:    true,
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "invalid token returns inactive",
			method:       "POST",
			token:        "invalid-token",
			expectStatus: http.StatusOK,
			expectActive: false,
		},
		{
			name:         "expired token returns inactive",
			method:       "POST",
			token:        expiredToken,
			expectStatus: http.StatusOK,
			expectActive: false,
		},
		{
			name:       "valid token with local RP authentication",
			method:     "POST",
			token:      validToken,
			remoteAddr: "127.0.0.1:12345",
			authRequest: &authRequest{
				localRP:    true,
				clientID:   "local-client",
				remoteUser: remoteUser,
				validTill:  now.Add(5 * time.Minute),
			},
			expectStatus: http.StatusOK,
			expectActive: true,
			expectedFields: map[string]any{
				"client_id": "local-client",
				"sub":       "456",
				"username":  "alice@example.com",
				"aud":       "local-client",
			},
		},
		{
			name:         "valid token with funnel RP authentication - correct credentials",
			method:       "POST",
			token:        validToken,
			clientID:     "funnel-client-id",
			clientSecret: "funnel-client-secret",
			authRequest: &authRequest{
				funnelRP:   funnelClient,
				clientID:   "funnel-client-id",
				remoteUser: remoteUser,
				validTill:  now.Add(5 * time.Minute),
			},
			expectStatus: http.StatusOK,
			expectActive: true,
			expectedFields: map[string]any{
				"client_id": "funnel-client-id",
				"sub":       "456",
				"username":  "alice@example.com",
				"aud":       "funnel-client-id",
			},
		},
		{
			name:         "valid token with funnel RP authentication - basic auth",
			method:       "POST",
			token:        validToken,
			clientID:     "funnel-client-id",
			clientSecret: "funnel-client-secret",
			useBasicAuth: true,
			authRequest: &authRequest{
				funnelRP:   funnelClient,
				clientID:   "funnel-client-id",
				remoteUser: remoteUser,
				validTill:  now.Add(5 * time.Minute),
			},
			expectStatus: http.StatusOK,
			expectActive: true,
		},
		{
			name:         "valid token with funnel RP authentication - wrong credentials",
			method:       "POST",
			token:        validToken,
			clientID:     "wrong-client-id",
			clientSecret: "wrong-secret",
			authRequest: &authRequest{
				funnelRP:   funnelClient,
				clientID:   "funnel-client-id",
				remoteUser: remoteUser,
				validTill:  now.Add(5 * time.Minute),
			},
			expectStatus: http.StatusOK,
			expectActive: false, // Returns inactive for unauthorized clients
		},
		{
			name:       "valid token with node RP authentication - unauthorized node",
			method:     "POST",
			token:      validToken,
			remoteAddr: "100.64.1.2:12345", // Different node
			authRequest: &authRequest{
				rpNodeID:   789, // Different node ID
				clientID:   "node-client",
				remoteUser: remoteUser,
				validTill:  now.Add(5 * time.Minute),
			},
			expectStatus: http.StatusOK,
			expectActive: false, // Returns inactive for unauthorized nodes
		},
		{
			name:       "valid token from non-loopback for local RP",
			method:     "POST",
			token:      validToken,
			remoteAddr: "192.168.1.100:12345", // Non-loopback
			authRequest: &authRequest{
				localRP:    true,
				clientID:   "local-client",
				remoteUser: remoteUser,
				validTill:  now.Add(5 * time.Minute),
			},
			expectStatus: http.StatusOK,
			expectActive: false, // Returns inactive for unauthorized access
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with test tokens
			s := &idpServer{
				accessToken: map[string]*authRequest{},
			}

			// Add valid token if test uses it
			if tt.authRequest != nil && tt.token == validToken {
				s.accessToken[validToken] = tt.authRequest
			}

			// Add expired token
			s.accessToken[expiredToken] = &authRequest{
				localRP:    true,
				clientID:   "expired-client",
				remoteUser: remoteUser,
				validTill:  now.Add(-1 * time.Hour), // Expired
			}

			// Create request
			form := url.Values{}
			if !tt.omitToken {
				form.Set("token", tt.token)
			}
			if !tt.useBasicAuth && tt.clientID != "" {
				form.Set("client_id", tt.clientID)
				form.Set("client_secret", tt.clientSecret)
			}

			req := httptest.NewRequest(tt.method, "/introspect", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			if tt.useBasicAuth && tt.clientID != "" {
				req.SetBasicAuth(tt.clientID, tt.clientSecret)
			}

			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			} else {
				req.RemoteAddr = "127.0.0.1:12345" // Default to loopback
			}

			rr := httptest.NewRecorder()

			// Call the handler
			s.serveIntrospect(rr, req)

			// Check status code
			if rr.Code != tt.expectStatus {
				t.Fatalf("expected status %d, got %d: %s", tt.expectStatus, rr.Code, rr.Body.String())
			}

			// If we expect an error status, no need to check response body
			if tt.expectStatus != http.StatusOK {
				return
			}

			// Parse response
			var resp map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			// Check active field
			active, ok := resp["active"].(bool)
			if !ok {
				t.Fatal("response missing 'active' field or wrong type")
			}
			if active != tt.expectActive {
				t.Errorf("expected active=%v, got %v", tt.expectActive, active)
			}

			// Check expected fields if token is active
			if tt.expectActive && tt.expectedFields != nil {
				for field, expected := range tt.expectedFields {
					got, ok := resp[field]
					if !ok {
						t.Errorf("missing expected field %q", field)
						continue
					}
					if got != expected {
						t.Errorf("field %q: expected %v, got %v", field, expected, got)
					}
				}

				// Check standard fields that should always be present for active tokens
				if _, ok := resp["exp"]; !ok {
					t.Error("missing 'exp' field for active token")
				}
				if _, ok := resp["iat"]; !ok {
					t.Error("missing 'iat' field for active token")
				}
			}
		})
	}
}

func TestExtraUserInfo(t *testing.T) {
	tests := []struct {
		name           string
		caps           tailcfg.PeerCapMap
		tokenValidTill time.Time
		expected       map[string]any
		expectError    bool
	}{
		{
			name:           "extra claim",
			tokenValidTill: time.Now().Add(1 * time.Minute),
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: true,
						ExtraClaims: map[string]any{
							"foo": []string{"bar"},
						},
					}),
				},
			},
			expected: map[string]any{
				"foo": []any{"bar"},
			},
		},
		{
			name:           "duplicate claim distinct values",
			tokenValidTill: time.Now().Add(1 * time.Minute),
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: true,
						ExtraClaims: map[string]any{
							"foo": []string{"bar", "foobar"},
						},
					}),
				},
			},
			expected: map[string]any{
				"foo": []any{"bar", "foobar"},
			},
		},
		{
			name:           "multiple extra claims",
			tokenValidTill: time.Now().Add(1 * time.Minute),
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: true,
						ExtraClaims: map[string]any{
							"foo": "bar",
							"bar": "foo",
						},
					}),
				},
			},
			expected: map[string]any{
				"foo": "bar",
				"bar": "foo",
			},
		},
		{
			name:           "empty extra claims",
			caps:           tailcfg.PeerCapMap{},
			tokenValidTill: time.Now().Add(1 * time.Minute),
			expected:       map[string]any{},
		},
		{
			name:           "attempt to overwrite protected claim",
			tokenValidTill: time.Now().Add(1 * time.Minute),
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: true,
						ExtraClaims: map[string]any{
							"sub": "should-not-overwrite",
							"foo": "ok",
						},
					}),
				},
			},
			expectError: true,
		},
		{
			name:           "extra claim omitted",
			tokenValidTill: time.Now().Add(1 * time.Minute),
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: false,
						ExtraClaims: map[string]any{
							"foo": "ok",
						},
					}),
				},
			},
			expected: map[string]any{},
		},
		{
			name:           "expired token",
			caps:           tailcfg.PeerCapMap{},
			tokenValidTill: time.Now().Add(-1 * time.Minute),
			expected:       map[string]any{},
			expectError:    true,
		},
	}
	token := "valid-token"

	// Create a fake tailscale Node
	node := &tailcfg.Node{
		ID:   123,
		Name: "test-node.test.ts.net.",
		User: 456,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Construct the remote user
			profile := tailcfg.UserProfile{
				LoginName:     "alice@example.com",
				DisplayName:   "Alice Example",
				ProfilePicURL: "https://example.com/alice.jpg",
			}

			remoteUser := &apitype.WhoIsResponse{
				Node:        node,
				UserProfile: &profile,
				CapMap:      tt.caps,
			}

			// Insert a valid token into the idpServer
			s := &idpServer{
				accessToken: map[string]*authRequest{
					token: {
						validTill:  tt.tokenValidTill,
						remoteUser: remoteUser,
					},
				},
			}

			// Construct request
			req := httptest.NewRequest("GET", "/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()

			// Call the method under test
			s.serveUserInfo(rr, req)

			if tt.expectError {
				if rr.Code == http.StatusOK {
					t.Fatalf("expected error, got %d: %s", rr.Code, rr.Body.String())
				}
				return
			}

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
			}

			var resp map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse JSON response: %v", err)
			}

			// Construct expected
			tt.expected["sub"] = remoteUser.Node.User.String()
			tt.expected["name"] = profile.DisplayName
			tt.expected["email"] = profile.LoginName
			tt.expected["picture"] = profile.ProfilePicURL
			tt.expected["username"], _, _ = strings.Cut(profile.LoginName, "@")

			gotNormalized := normalizeMap(t, resp)
			expectedNormalized := normalizeMap(t, tt.expected)

			if !reflect.DeepEqual(gotNormalized, expectedNormalized) {
				t.Errorf("UserInfo mismatch:\n got: %#v\nwant: %#v", gotNormalized, expectedNormalized)
			}
		})
	}
}

func TestFunnelClientsPersistence(t *testing.T) {
	testClients := map[string]*funnelClient{
		"test-client-1": {
			ID:          "test-client-1",
			Secret:      "test-secret-1",
			Name:        "Test Client 1",
			RedirectURI: "https://example.com/callback",
		},
		"test-client-2": {
			ID:          "test-client-2",
			Secret:      "test-secret-2",
			Name:        "Test Client 2",
			RedirectURI: "https://example2.com/callback",
		},
	}

	testData, err := json.Marshal(testClients)
	if err != nil {
		t.Fatalf("failed to marshal test data: %v", err)
	}

	tmpFile := t.TempDir() + "/oidc-funnel-clients.json"
	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	t.Run("step1_load_from_existing_file", func(t *testing.T) {
		srv := &idpServer{}

		// Simulate the funnel clients loading logic from main()
		srv.funnelClients = make(map[string]*funnelClient)
		f, err := os.Open(tmpFile)
		if err == nil {
			if err := json.NewDecoder(f).Decode(&srv.funnelClients); err != nil {
				t.Fatalf("could not parse %s: %v", tmpFile, err)
			}
			f.Close()
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("could not open %s: %v", tmpFile, err)
		}

		// Verify clients were loaded correctly
		if len(srv.funnelClients) != 2 {
			t.Errorf("expected 2 clients, got %d", len(srv.funnelClients))
		}

		client1, ok := srv.funnelClients["test-client-1"]
		if !ok {
			t.Error("expected test-client-1 to be loaded")
		} else {
			if client1.Name != "Test Client 1" {
				t.Errorf("expected client name 'Test Client 1', got '%s'", client1.Name)
			}
			if client1.Secret != "test-secret-1" {
				t.Errorf("expected client secret 'test-secret-1', got '%s'", client1.Secret)
			}
		}
	})

	t.Run("step2_initialize_empty_when_no_file", func(t *testing.T) {
		nonExistentFile := t.TempDir() + "/non-existent.json"

		srv := &idpServer{}

		// Simulate the funnel clients loading logic from main()
		srv.funnelClients = make(map[string]*funnelClient)
		f, err := os.Open(nonExistentFile)
		if err == nil {
			if err := json.NewDecoder(f).Decode(&srv.funnelClients); err != nil {
				t.Fatalf("could not parse %s: %v", nonExistentFile, err)
			}
			f.Close()
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("could not open %s: %v", nonExistentFile, err)
		}

		// Verify map is initialized but empty
		if srv.funnelClients == nil {
			t.Error("expected funnelClients map to be initialized")
		}
		if len(srv.funnelClients) != 0 {
			t.Errorf("expected empty map, got %d clients", len(srv.funnelClients))
		}
	})

	t.Run("step3_persist_and_reload_clients", func(t *testing.T) {
		tmpFile2 := t.TempDir() + "/test-persistence.json"

		// Create initial server with one client
		srv1 := &idpServer{
			funnelClients: make(map[string]*funnelClient),
		}
		srv1.funnelClients["new-client"] = &funnelClient{
			ID:          "new-client",
			Secret:      "new-secret",
			Name:        "New Client",
			RedirectURI: "https://new.example.com/callback",
		}

		// Save clients to file (simulating saveFunnelClients)
		data, err := json.Marshal(srv1.funnelClients)
		if err != nil {
			t.Fatalf("failed to marshal clients: %v", err)
		}
		if err := os.WriteFile(tmpFile2, data, 0600); err != nil {
			t.Fatalf("failed to write clients file: %v", err)
		}

		// Create new server instance and load clients
		srv2 := &idpServer{}
		srv2.funnelClients = make(map[string]*funnelClient)
		f, err := os.Open(tmpFile2)
		if err == nil {
			if err := json.NewDecoder(f).Decode(&srv2.funnelClients); err != nil {
				t.Fatalf("could not parse %s: %v", tmpFile2, err)
			}
			f.Close()
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("could not open %s: %v", tmpFile2, err)
		}

		// Verify the client was persisted correctly
		loadedClient, ok := srv2.funnelClients["new-client"]
		if !ok {
			t.Error("expected new-client to be loaded after persistence")
		} else {
			if loadedClient.Name != "New Client" {
				t.Errorf("expected client name 'New Client', got '%s'", loadedClient.Name)
			}
			if loadedClient.Secret != "new-secret" {
				t.Errorf("expected client secret 'new-secret', got '%s'", loadedClient.Secret)
			}
		}
	})
}

func TestServeOpenIDConfig(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		path          string
		remoteAddr    string
		isFunnel      bool
		expectStatus  int
		checkResponse func(t *testing.T, body []byte)
	}{
		{
			name:         "OPTIONS request - CORS preflight",
			method:       "OPTIONS",
			path:         "/.well-known/openid-configuration",
			remoteAddr:   "100.64.1.2:12345",
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				if len(body) != 0 {
					t.Errorf("expected empty body for OPTIONS request, got: %s", body)
				}
			},
		},
		{
			name:         "GET request - localhost",
			method:       "GET",
			path:         "/.well-known/openid-configuration",
			remoteAddr:   "127.0.0.1:12345",
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var metadata map[string]any
				if err := json.Unmarshal(body, &metadata); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}

				// Check required OpenID fields
				requiredFields := []string{
					"issuer",
					"authorization_endpoint",
					"token_endpoint",
					"userinfo_endpoint",
					"jwks_uri",
					"response_types_supported",
					"subject_types_supported",
					"id_token_signing_alg_values_supported",
				}
				for _, field := range requiredFields {
					if _, ok := metadata[field]; !ok {
						t.Errorf("missing required field: %s", field)
					}
				}

				// Check that authorization endpoint contains localhost
				authEndpoint, ok := metadata["authorization_endpoint"].(string)
				if !ok || !strings.Contains(authEndpoint, "/authorize/localhost") {
					t.Errorf("expected localhost authorization endpoint, got: %v", metadata["authorization_endpoint"])
				}

				// Check issuer for localhost
				issuer, ok := metadata["issuer"].(string)
				if !ok || !strings.HasPrefix(issuer, "http://localhost") {
					t.Errorf("expected localhost issuer, got: %v", metadata["issuer"])
				}

				// Check introspection endpoint
				introspectionEndpoint, ok := metadata["introspection_endpoint"].(string)
				if !ok || !strings.HasSuffix(introspectionEndpoint, "/introspect") {
					t.Errorf("expected introspection endpoint ending with /introspect, got: %v", metadata["introspection_endpoint"])
				}

				// Check response types
				responseTypes, ok := metadata["response_types_supported"].([]any)
				if !ok || len(responseTypes) == 0 {
					t.Errorf("invalid response_types_supported: %v", metadata["response_types_supported"])
				}

				// Check subject types
				subjectTypes, ok := metadata["subject_types_supported"].([]any)
				if !ok || len(subjectTypes) == 0 {
					t.Errorf("invalid subject_types_supported: %v", metadata["subject_types_supported"])
				}
			},
		},
		{
			name:         "GET request - funnel",
			method:       "GET",
			path:         "/.well-known/openid-configuration",
			remoteAddr:   "100.64.1.2:12345",
			isFunnel:     true,
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var metadata map[string]any
				if err := json.Unmarshal(body, &metadata); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}

				// Check that authorization endpoint contains funnel
				authEndpoint, ok := metadata["authorization_endpoint"].(string)
				if !ok || !strings.Contains(authEndpoint, "/authorize/funnel") {
					t.Errorf("expected funnel authorization endpoint, got: %v", metadata["authorization_endpoint"])
				}

				// Check issuer
				issuer, ok := metadata["issuer"].(string)
				if !ok || !strings.HasPrefix(issuer, "https://") {
					t.Errorf("invalid issuer: %v", metadata["issuer"])
				}
			},
		},
		{
			name:         "GET request - wrong path",
			method:       "GET",
			path:         "/.well-known/wrong-path",
			remoteAddr:   "100.64.1.2:12345",
			expectStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, body []byte) {
				if !strings.Contains(string(body), "not found") {
					t.Errorf("expected not found error, got: %s", body)
				}
			},
		},
		{
			name:         "GET request - invalid remote address",
			method:       "GET",
			path:         "/.well-known/openid-configuration",
			remoteAddr:   "invalid-address",
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				if !strings.Contains(string(body), "invalid remote address") {
					t.Errorf("expected invalid remote address error, got: %s", body)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL:   "https://idp.test.ts.net",
				loopbackURL: "http://localhost:8080",
			}

			// Only set lc to nil - this will trigger the localhost/error path
			// when the server can't determine the node ID
			s.lc = nil

			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.RemoteAddr = tt.remoteAddr

			if tt.isFunnel {
				req.Header.Set("Tailscale-Funnel-Request", "true")
			}

			rr := httptest.NewRecorder()

			s.serveOpenIDConfig(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rr.Code)
			}

			// Check CORS headers
			if h := rr.Header().Get("Access-Control-Allow-Origin"); h != "*" {
				t.Errorf("expected CORS origin *, got %s", h)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, rr.Body.Bytes())
			}
		})
	}
}

func TestServeOAuthMetadata(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		path          string
		remoteAddr    string
		isFunnel      bool
		expectStatus  int
		checkResponse func(t *testing.T, body []byte)
	}{
		{
			name:         "OPTIONS request - CORS preflight",
			method:       "OPTIONS",
			path:         "/.well-known/oauth-authorization-server",
			remoteAddr:   "100.64.1.2:12345",
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				if len(body) != 0 {
					t.Errorf("expected empty body for OPTIONS request, got: %s", body)
				}
			},
		},
		{
			name:         "GET request - localhost",
			method:       "GET",
			path:         "/.well-known/oauth-authorization-server",
			remoteAddr:   "127.0.0.1:12345",
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var metadata map[string]any
				if err := json.Unmarshal(body, &metadata); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}

				// Check required fields
				requiredFields := []string{
					"issuer",
					"authorization_endpoint",
					"token_endpoint",
					"introspection_endpoint",
					"response_types_supported",
					"grant_types_supported",
					"token_endpoint_auth_methods_supported",
				}
				for _, field := range requiredFields {
					if _, ok := metadata[field]; !ok {
						t.Errorf("missing required field: %s", field)
					}
				}

				// Check that authorization endpoint contains localhost
				authEndpoint, ok := metadata["authorization_endpoint"].(string)
				if !ok || !strings.Contains(authEndpoint, "/authorize/localhost") {
					t.Errorf("expected localhost authorization endpoint, got: %v", metadata["authorization_endpoint"])
				}

				// Check issuer for localhost
				issuer, ok := metadata["issuer"].(string)
				if !ok || !strings.HasPrefix(issuer, "http://localhost") {
					t.Errorf("expected localhost issuer, got: %v", metadata["issuer"])
				}

				// Check response types
				responseTypes, ok := metadata["response_types_supported"].([]any)
				if !ok || len(responseTypes) == 0 {
					t.Errorf("invalid response_types_supported: %v", metadata["response_types_supported"])
				}

				// Check grant types
				grantTypes, ok := metadata["grant_types_supported"].([]any)
				if !ok || len(grantTypes) != 1 || grantTypes[0] != "authorization_code" {
					t.Errorf("invalid grant_types_supported: %v", metadata["grant_types_supported"])
				}

				// Check token endpoint auth methods
				authMethods, ok := metadata["token_endpoint_auth_methods_supported"].([]any)
				if !ok || len(authMethods) != 2 {
					t.Errorf("invalid token_endpoint_auth_methods_supported: %v", metadata["token_endpoint_auth_methods_supported"])
				}
			},
		},
		{
			name:         "GET request - funnel",
			method:       "GET",
			path:         "/.well-known/oauth-authorization-server",
			remoteAddr:   "100.64.1.2:12345",
			isFunnel:     true,
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var metadata map[string]any
				if err := json.Unmarshal(body, &metadata); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}

				// Check that authorization endpoint contains funnel
				authEndpoint, ok := metadata["authorization_endpoint"].(string)
				if !ok || !strings.Contains(authEndpoint, "/authorize/funnel") {
					t.Errorf("expected funnel authorization endpoint, got: %v", metadata["authorization_endpoint"])
				}

				// Check issuer
				issuer, ok := metadata["issuer"].(string)
				if !ok || !strings.HasPrefix(issuer, "https://") {
					t.Errorf("invalid issuer: %v", metadata["issuer"])
				}
			},
		},
		{
			name:         "GET request - wrong path",
			method:       "GET",
			path:         "/.well-known/wrong-path",
			remoteAddr:   "100.64.1.2:12345",
			expectStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, body []byte) {
				if !strings.Contains(string(body), "not found") {
					t.Errorf("expected not found error, got: %s", body)
				}
			},
		},
		{
			name:         "GET request - invalid remote address",
			method:       "GET",
			path:         "/.well-known/oauth-authorization-server",
			remoteAddr:   "invalid-address",
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				if !strings.Contains(string(body), "invalid remote address") {
					t.Errorf("expected invalid remote address error, got: %s", body)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpServer{
				serverURL:   "https://idp.test.ts.net",
				loopbackURL: "http://localhost:8080",
			}

			// Only set lc to nil - this will trigger the localhost/error path
			// when the server can't determine the node ID
			s.lc = nil

			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.RemoteAddr = tt.remoteAddr

			if tt.isFunnel {
				req.Header.Set("Tailscale-Funnel-Request", "true")
			}

			rr := httptest.NewRecorder()

			s.serveOAuthMetadata(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rr.Code)
			}

			// Check CORS headers
			if h := rr.Header().Get("Access-Control-Allow-Origin"); h != "*" {
				t.Errorf("expected CORS origin *, got %s", h)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, rr.Body.Bytes())
			}
		})
	}
}
