// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package main tests for tsidp focus on OAuth security boundaries and
// correct implementation of the OpenID Connect identity provider.
//
// Test Strategy:
// - Tests are intentionally granular to provide clear failure signals when
//   security-critical logic breaks
// - OAuth flow tests cover both strict mode (registered clients only) and
//   legacy mode (local funnel clients) to ensure proper access controls
// - Helper functions like normalizeMap ensure deterministic comparisons
//   despite JSON marshaling order variations
// - The privateKey global is reused across tests for performance (RSA key
//   generation is expensive)

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
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
	"tailscale.com/types/views"
)

// normalizeMap recursively sorts []any values in a map[string]any to ensure
// deterministic test comparisons. This is necessary because JSON marshaling
// doesn't guarantee array order, and we need stable comparisons when testing
// claim merging and flattening logic.
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

// privateKey is a shared RSA private key used across tests. It's lazily
// initialized on first use to avoid the expensive key generation cost
// for every test. Protected by privateKeyMu for thread safety.
var (
	privateKey   *rsa.PrivateKey
	privateKeyMu sync.Mutex
)

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
	privateKeyMu.Lock()
	defer privateKeyMu.Unlock()

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
				"foo": []any{"bar", "baz"}, // converts to slice when any rule provides a slice
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
		strictMode  bool
		expectError bool
		expected    map[string]any
	}{
		{
			name:        "GET not allowed",
			method:      "GET",
			grantType:   "authorization_code",
			strictMode:  false,
			expectError: true,
		},
		{
			name:        "unsupported grant type",
			method:      "POST",
			grantType:   "pkcs",
			strictMode:  false,
			expectError: true,
		},
		{
			name:        "invalid code",
			method:      "POST",
			grantType:   "authorization_code",
			code:        "invalid-code",
			strictMode:  false,
			expectError: true,
		},
		{
			name:        "omit code from form",
			method:      "POST",
			grantType:   "authorization_code",
			omitCode:    true,
			strictMode:  false,
			expectError: true,
		},
		{
			name:        "invalid redirect uri",
			method:      "POST",
			grantType:   "authorization_code",
			code:        "valid-code",
			redirectURI: "https://invalid.example.com/callback",
			remoteAddr:  "127.0.0.1:12345",
			strictMode:  false,
			expectError: true,
		},
		{
			name:        "invalid remoteAddr",
			method:      "POST",
			grantType:   "authorization_code",
			redirectURI: "https://rp.example.com/callback",
			code:        "valid-code",
			remoteAddr:  "192.168.0.1:12345",
			strictMode:  false,
			expectError: true,
		},
		{
			name:        "extra claim included (non-strict)",
			method:      "POST",
			grantType:   "authorization_code",
			redirectURI: "https://rp.example.com/callback",
			code:        "valid-code",
			remoteAddr:  "127.0.0.1:12345",
			strictMode:  false,
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
			name:        "attempt to overwrite protected claim (non-strict)",
			method:      "POST",
			grantType:   "authorization_code",
			redirectURI: "https://rp.example.com/callback",
			code:        "valid-code",
			strictMode:  false,
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

			// Use setupTestServer helper
			s := setupTestServer(t, tt.strictMode)

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

			// Setup auth request with appropriate configuration for strict mode
			var funnelClientPtr *funnelClient
			if tt.strictMode {
				funnelClientPtr = &funnelClient{
					ID:          "client-id",
					Secret:      "test-secret",
					Name:        "Test Client",
					RedirectURI: "https://rp.example.com/callback",
				}
				s.funnelClients["client-id"] = funnelClientPtr
			}

			s.code["valid-code"] = &authRequest{
				clientID:    "client-id",
				nonce:       "nonce123",
				redirectURI: "https://rp.example.com/callback",
				validTill:   now.Add(5 * time.Minute),
				remoteUser:  remoteUser,
				localRP:     !tt.strictMode,
				funnelRP:    funnelClientPtr,
			}

			form := url.Values{}
			form.Set("grant_type", tt.grantType)
			form.Set("redirect_uri", tt.redirectURI)
			if !tt.omitCode {
				form.Set("code", tt.code)
			}
			// Add client credentials for strict mode
			if tt.strictMode {
				form.Set("client_id", "client-id")
				form.Set("client_secret", "test-secret")
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
				allowInsecureRegistration: true, // Default to allowing insecure registration for backward compatibility
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

	t.Run("load_from_existing_file", func(t *testing.T) {
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

	t.Run("initialize_empty_when_no_file", func(t *testing.T) {
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

	t.Run("persist_and_reload_clients", func(t *testing.T) {
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

	t.Run("strict_mode_file_handling", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Test strict mode uses oauth-clients.json
		srv1 := setupTestServer(t, true)
		srv1.rootPath = tmpDir
		srv1.funnelClients["oauth-client"] = &funnelClient{
			ID:          "oauth-client",
			Secret:      "oauth-secret",
			Name:        "OAuth Client",
			RedirectURI: "https://oauth.example.com/callback",
		}

		// Test storeFunnelClientsLocked in strict mode
		srv1.mu.Lock()
		err := srv1.storeFunnelClientsLocked()
		srv1.mu.Unlock()

		if err != nil {
			t.Fatalf("failed to store clients in strict mode: %v", err)
		}

		// Verify oauth-clients.json was created
		oauthPath := tmpDir + "/" + oauthClientsFile
		if _, err := os.Stat(oauthPath); err != nil {
			t.Errorf("expected oauth-clients.json to be created: %v", err)
		}

		// Verify oidc-funnel-clients.json was NOT created
		funnelPath := tmpDir + "/" + funnelClientsFile
		if _, err := os.Stat(funnelPath); !os.IsNotExist(err) {
			t.Error("expected oidc-funnel-clients.json NOT to be created in strict mode")
		}
	})

	t.Run("non_strict_mode_file_handling", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Test non-strict mode uses oidc-funnel-clients.json
		srv1 := setupTestServer(t, false)
		srv1.rootPath = tmpDir
		srv1.funnelClients["funnel-client"] = &funnelClient{
			ID:          "funnel-client",
			Secret:      "funnel-secret",
			Name:        "Funnel Client",
			RedirectURI: "https://funnel.example.com/callback",
		}

		// Test storeFunnelClientsLocked in non-strict mode
		srv1.mu.Lock()
		err := srv1.storeFunnelClientsLocked()
		srv1.mu.Unlock()

		if err != nil {
			t.Fatalf("failed to store clients in non-strict mode: %v", err)
		}

		// Verify oidc-funnel-clients.json was created
		funnelPath := tmpDir + "/" + funnelClientsFile
		if _, err := os.Stat(funnelPath); err != nil {
			t.Errorf("expected oidc-funnel-clients.json to be created: %v", err)
		}

		// Verify oauth-clients.json was NOT created
		oauthPath := tmpDir + "/" + oauthClientsFile
		if _, err := os.Stat(oauthPath); !os.IsNotExist(err) {
			t.Error("expected oauth-clients.json NOT to be created in non-strict mode")
		}
	})
}

// Test helper functions for strict OAuth mode testing
func setupTestServer(t *testing.T, strictMode bool) *idpServer {
	return setupTestServerWithClient(t, strictMode, nil)
}

// setupTestServerWithClient creates a test server with an optional LocalClient.
// If lc is nil, the server will have no LocalClient (original behavior).
// If lc is provided, it will be used for WhoIs calls during testing.
func setupTestServerWithClient(t *testing.T, strictMode bool, lc *local.Client) *idpServer {
	t.Helper()

	srv := &idpServer{
		allowInsecureRegistration: !strictMode,
		code:                      make(map[string]*authRequest),
		accessToken:               make(map[string]*authRequest),
		funnelClients:             make(map[string]*funnelClient),
		serverURL:                 "https://test.ts.net",
		rootPath:                  t.TempDir(),
		lc:                        lc,
	}

	// Add a test client for funnel/strict mode testing
	srv.funnelClients["test-client"] = &funnelClient{
		ID:          "test-client",
		Secret:      "test-secret",
		Name:        "Test Client",
		RedirectURI: "https://rp.example.com/callback",
	}

	// Inject a working signer for token tests
	srv.lazySigner.Set(oidcTestingSigner(t))

	return srv
}

func TestGetAllowInsecureRegistration(t *testing.T) {
	tests := []struct {
		name                            string
		flagSet                         bool
		flagValue                       bool
		expectAllowInsecureRegistration bool
	}{
		{
			name:                            "flag explicitly set to false - insecure registration disabled (strict mode)",
			flagSet:                         true,
			flagValue:                       false,
			expectAllowInsecureRegistration: false,
		},
		{
			name:                            "flag explicitly set to true - insecure registration enabled",
			flagSet:                         true,
			flagValue:                       true,
			expectAllowInsecureRegistration: true,
		},
		{
			name:                            "flag unset - insecure registration enabled (default for backward compatibility)",
			flagSet:                         false,
			flagValue:                       false, // not used when unset
			expectAllowInsecureRegistration: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original state
			originalFlag := flagAllowInsecureRegistration
			defer func() {
				flagAllowInsecureRegistration = originalFlag
			}()

			// Set up test state by creating a new BoolFlag and setting values
			var b opt.Bool
			flagAllowInsecureRegistration = opt.BoolFlag{Bool: &b}
			if tt.flagSet {
				flagAllowInsecureRegistration.Bool.Set(tt.flagValue)
			}
			// Note: when tt.flagSet is false, the Bool remains unset (which is what we want)

			got := getAllowInsecureRegistration()
			if got != tt.expectAllowInsecureRegistration {
				t.Errorf("getAllowInsecureRegistration() = %v, want %v", got, tt.expectAllowInsecureRegistration)
			}
		})
	}
}

// TestMigrateOAuthClients verifies the migration from legacy funnel clients
// to OAuth clients. This migration is necessary when transitioning from
// non-strict to strict OAuth mode. The migration logic should:
// - Copy clients from oidc-funnel-clients.json to oauth-clients.json
// - Rename the old file to mark it as deprecated
// - Handle cases where files already exist or are missing
func TestMigrateOAuthClients(t *testing.T) {
	tests := []struct {
		name                string
		setupOldFile        bool
		setupNewFile        bool
		oldFileContent      map[string]*funnelClient
		newFileContent      map[string]*funnelClient
		expectError         bool
		expectNewFileExists bool
		expectOldRenamed    bool
	}{
		{
			name:         "migrate from old file to new file",
			setupOldFile: true,
			oldFileContent: map[string]*funnelClient{
				"old-client": {
					ID:          "old-client",
					Secret:      "old-secret",
					Name:        "Old Client",
					RedirectURI: "https://old.example.com/callback",
				},
			},
			expectNewFileExists: true,
			expectOldRenamed:    true,
		},
		{
			name:         "new file already exists - no migration",
			setupNewFile: true,
			newFileContent: map[string]*funnelClient{
				"existing-client": {
					ID:          "existing-client",
					Secret:      "existing-secret",
					Name:        "Existing Client",
					RedirectURI: "https://existing.example.com/callback",
				},
			},
			expectNewFileExists: true,
			expectOldRenamed:    false,
		},
		{
			name:                "neither file exists - create empty new file",
			expectNewFileExists: true,
			expectOldRenamed:    false,
		},
		{
			name:         "both files exist - prefer new file",
			setupOldFile: true,
			setupNewFile: true,
			oldFileContent: map[string]*funnelClient{
				"old-client": {
					ID:          "old-client",
					Secret:      "old-secret",
					Name:        "Old Client",
					RedirectURI: "https://old.example.com/callback",
				},
			},
			newFileContent: map[string]*funnelClient{
				"new-client": {
					ID:          "new-client",
					Secret:      "new-secret",
					Name:        "New Client",
					RedirectURI: "https://new.example.com/callback",
				},
			},
			expectNewFileExists: true,
			expectOldRenamed:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootPath := t.TempDir()

			// Setup old file if needed
			if tt.setupOldFile {
				oldData, err := json.Marshal(tt.oldFileContent)
				if err != nil {
					t.Fatalf("failed to marshal old file content: %v", err)
				}
				oldPath := rootPath + "/" + funnelClientsFile
				if err := os.WriteFile(oldPath, oldData, 0600); err != nil {
					t.Fatalf("failed to create old file: %v", err)
				}
			}

			// Setup new file if needed
			if tt.setupNewFile {
				newData, err := json.Marshal(tt.newFileContent)
				if err != nil {
					t.Fatalf("failed to marshal new file content: %v", err)
				}
				newPath := rootPath + "/" + oauthClientsFile
				if err := os.WriteFile(newPath, newData, 0600); err != nil {
					t.Fatalf("failed to create new file: %v", err)
				}
			}

			// Call migrateOAuthClients
			resultPath, err := migrateOAuthClients(rootPath)

			if tt.expectError && err == nil {
				t.Fatalf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.expectError {
				return
			}

			// Verify result path points to oauth-clients.json
			expectedPath := filepath.Join(rootPath, oauthClientsFile)
			if resultPath != expectedPath {
				t.Errorf("expected result path %s, got %s", expectedPath, resultPath)
			}

			// Verify new file exists if expected
			if tt.expectNewFileExists {
				if _, err := os.Stat(resultPath); err != nil {
					t.Errorf("expected new file to exist at %s: %v", resultPath, err)
				}

				// Verify content
				data, err := os.ReadFile(resultPath)
				if err != nil {
					t.Fatalf("failed to read new file: %v", err)
				}

				var clients map[string]*funnelClient
				if err := json.Unmarshal(data, &clients); err != nil {
					t.Fatalf("failed to unmarshal new file: %v", err)
				}

				// Determine expected content
				var expectedContent map[string]*funnelClient
				if tt.setupNewFile {
					expectedContent = tt.newFileContent
				} else if tt.setupOldFile {
					expectedContent = tt.oldFileContent
				} else {
					expectedContent = make(map[string]*funnelClient)
				}

				if len(clients) != len(expectedContent) {
					t.Errorf("expected %d clients, got %d", len(expectedContent), len(clients))
				}

				for id, expectedClient := range expectedContent {
					actualClient, ok := clients[id]
					if !ok {
						t.Errorf("expected client %s not found", id)
						continue
					}
					if actualClient.ID != expectedClient.ID ||
						actualClient.Secret != expectedClient.Secret ||
						actualClient.Name != expectedClient.Name ||
						actualClient.RedirectURI != expectedClient.RedirectURI {
						t.Errorf("client %s mismatch: got %+v, want %+v", id, actualClient, expectedClient)
					}
				}
			}

			// Verify old file renamed if expected
			if tt.expectOldRenamed {
				deprecatedPath := rootPath + "/" + deprecatedFunnelClientsFile
				if _, err := os.Stat(deprecatedPath); err != nil {
					t.Errorf("expected old file to be renamed to %s: %v", deprecatedPath, err)
				}

				// Verify original old file is gone
				oldPath := rootPath + "/" + funnelClientsFile
				if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
					t.Errorf("expected old file %s to be removed", oldPath)
				}
			}
		})
	}
}

// TestGetConfigFilePath verifies backward compatibility for config file location.
// The function must check current directory first (legacy deployments) before
// falling back to rootPath (new installations) to prevent breaking existing
// tsidp deployments that have config files in unexpected locations.
func TestGetConfigFilePath(t *testing.T) {
	tests := []struct {
		name         string
		fileName     string
		createInCwd  bool
		createInRoot bool
		expectInCwd  bool
		expectError  bool
	}{
		{
			name:        "file exists in current directory - use current directory",
			fileName:    "test-config.json",
			createInCwd: true,
			expectInCwd: true,
		},
		{
			name:        "file does not exist - use root path",
			fileName:    "test-config.json",
			createInCwd: false,
			expectInCwd: false,
		},
		{
			name:         "file exists in both - prefer current directory",
			fileName:     "test-config.json",
			createInCwd:  true,
			createInRoot: true,
			expectInCwd:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directories
			rootPath := t.TempDir()
			originalWd, err := os.Getwd()
			if err != nil {
				t.Fatalf("failed to get working directory: %v", err)
			}

			// Create a temporary working directory
			tmpWd := t.TempDir()
			if err := os.Chdir(tmpWd); err != nil {
				t.Fatalf("failed to change to temp directory: %v", err)
			}
			defer func() {
				os.Chdir(originalWd)
			}()

			// Setup files as needed
			if tt.createInCwd {
				if err := os.WriteFile(tt.fileName, []byte("{}"), 0600); err != nil {
					t.Fatalf("failed to create file in cwd: %v", err)
				}
			}
			if tt.createInRoot {
				rootFilePath := filepath.Join(rootPath, tt.fileName)
				if err := os.WriteFile(rootFilePath, []byte("{}"), 0600); err != nil {
					t.Fatalf("failed to create file in root: %v", err)
				}
			}

			// Call getConfigFilePath
			resultPath, err := getConfigFilePath(rootPath, tt.fileName)

			if tt.expectError && err == nil {
				t.Fatalf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.expectError {
				return
			}

			// Verify result
			if tt.expectInCwd {
				if resultPath != tt.fileName {
					t.Errorf("expected path %s, got %s", tt.fileName, resultPath)
				}
			} else {
				expectedPath := filepath.Join(rootPath, tt.fileName)
				if resultPath != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, resultPath)
				}
			}
		})
	}
}

// TestAuthorizeStrictMode verifies OAuth authorization endpoint security and validation logic.
// Tests both the security boundary (funnel rejection) and the business logic (strict mode validation).
func TestAuthorizeStrictMode(t *testing.T) {
	tests := []struct {
		name           string
		strictMode     bool
		clientID       string
		redirectURI    string
		state          string
		nonce          string
		setupClient    bool
		clientRedirect string
		useFunnel      bool // whether to simulate funnel request
		mockWhoIsError bool // whether to make WhoIs return an error
		expectError    bool
		expectCode     int
		expectRedirect bool
	}{
		// Security boundary test: funnel rejection
		{
			name:           "funnel requests are always rejected for security",
			strictMode:     true,
			clientID:       "test-client",
			redirectURI:    "https://rp.example.com/callback",
			state:          "random-state",
			nonce:          "random-nonce",
			setupClient:    true,
			clientRedirect: "https://rp.example.com/callback",
			useFunnel:      true,
			expectError:    true,
			expectCode:     http.StatusUnauthorized,
		},

		// Strict mode parameter validation tests (non-funnel)
		{
			name:        "strict mode - missing client_id",
			strictMode:  true,
			clientID:    "",
			redirectURI: "https://rp.example.com/callback",
			useFunnel:   false,
			expectError: true,
			expectCode:  http.StatusBadRequest,
		},
		{
			name:        "strict mode - missing redirect_uri",
			strictMode:  true,
			clientID:    "test-client",
			redirectURI: "",
			useFunnel:   false,
			expectError: true,
			expectCode:  http.StatusBadRequest,
		},

		// Strict mode client validation tests (non-funnel)
		{
			name:        "strict mode - invalid client_id",
			strictMode:  true,
			clientID:    "invalid-client",
			redirectURI: "https://rp.example.com/callback",
			setupClient: false,
			useFunnel:   false,
			expectError: true,
			expectCode:  http.StatusBadRequest,
		},
		{
			name:           "strict mode - redirect_uri mismatch",
			strictMode:     true,
			clientID:       "test-client",
			redirectURI:    "https://wrong.example.com/callback",
			setupClient:    true,
			clientRedirect: "https://rp.example.com/callback",
			useFunnel:      false,
			expectError:    true,
			expectCode:     http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := setupTestServer(t, tt.strictMode)

			// For non-funnel tests, we'll test the parameter validation logic
			// without needing to mock WhoIs, since the validation happens before WhoIs calls

			// Setup client if needed
			if tt.setupClient {
				srv.funnelClients["test-client"] = &funnelClient{
					ID:          "test-client",
					Secret:      "test-secret",
					Name:        "Test Client",
					RedirectURI: tt.clientRedirect,
				}
			} else if !tt.strictMode {
				// For non-strict mode tests that don't need a specific client setup
				// but might reference one, clear the default client
				delete(srv.funnelClients, "test-client")
			}

			// Create request
			reqURL := "/authorize"
			if !tt.strictMode {
				// In non-strict mode, use the node-specific endpoint
				reqURL = "/authorize/123"
			}

			query := url.Values{}
			if tt.clientID != "" {
				query.Set("client_id", tt.clientID)
			}
			if tt.redirectURI != "" {
				query.Set("redirect_uri", tt.redirectURI)
			}
			if tt.state != "" {
				query.Set("state", tt.state)
			}
			if tt.nonce != "" {
				query.Set("nonce", tt.nonce)
			}

			reqURL += "?" + query.Encode()
			req := httptest.NewRequest("GET", reqURL, nil)
			req.RemoteAddr = "127.0.0.1:12345"

			// Set funnel header only when explicitly testing funnel behavior
			if tt.useFunnel {
				req.Header.Set("Tailscale-Funnel-Request", "true")
			}

			rr := httptest.NewRecorder()
			srv.authorize(rr, req)

			if tt.expectError {
				if rr.Code != tt.expectCode {
					t.Errorf("expected status code %d, got %d: %s", tt.expectCode, rr.Code, rr.Body.String())
				}
			} else if tt.expectRedirect {
				if rr.Code != http.StatusFound {
					t.Errorf("expected redirect (302), got %d: %s", rr.Code, rr.Body.String())
				}

				location := rr.Header().Get("Location")
				if location == "" {
					t.Error("expected Location header in redirect response")
				} else {
					// Parse the redirect URL to verify it contains a code
					redirectURL, err := url.Parse(location)
					if err != nil {
						t.Errorf("failed to parse redirect URL: %v", err)
					} else {
						code := redirectURL.Query().Get("code")
						if code == "" {
							t.Error("expected 'code' parameter in redirect URL")
						}

						// Verify state is preserved if provided
						if tt.state != "" {
							returnedState := redirectURL.Query().Get("state")
							if returnedState != tt.state {
								t.Errorf("expected state '%s', got '%s'", tt.state, returnedState)
							}
						}

						// Verify the auth request was stored
						srv.mu.Lock()
						ar, ok := srv.code[code]
						srv.mu.Unlock()

						if !ok {
							t.Error("expected authorization request to be stored")
						} else {
							if ar.clientID != tt.clientID {
								t.Errorf("expected clientID '%s', got '%s'", tt.clientID, ar.clientID)
							}
							if ar.redirectURI != tt.redirectURI {
								t.Errorf("expected redirectURI '%s', got '%s'", tt.redirectURI, ar.redirectURI)
							}
							if ar.nonce != tt.nonce {
								t.Errorf("expected nonce '%s', got '%s'", tt.nonce, ar.nonce)
							}
						}
					}
				}
			} else {
				t.Errorf("unexpected test case: not expecting error or redirect")
			}
		})
	}
}

// TestServeTokenWithClientValidation verifies OAuth token endpoint security in both strict and non-strict modes.
// In strict mode, the token endpoint must:
// - Require and validate client credentials (client_id + client_secret)
// - Only accept tokens from registered funnel clients
// - Validate that redirect_uri matches the registered client
// - Support both form-based and HTTP Basic authentication for client credentials
func TestServeTokenWithClientValidation(t *testing.T) {
	tests := []struct {
		name                string
		strictMode          bool
		method              string
		grantType           string
		code                string
		clientID            string
		clientSecret        string
		redirectURI         string
		useBasicAuth        bool
		setupAuthRequest    bool
		authRequestClient   string
		authRequestRedirect string
		expectError         bool
		expectCode          int
		expectIDToken       bool
	}{
		{
			name:                "strict mode - valid token exchange with form credentials",
			strictMode:          true,
			method:              "POST",
			grantType:           "authorization_code",
			code:                "valid-code",
			clientID:            "test-client",
			clientSecret:        "test-secret",
			redirectURI:         "https://rp.example.com/callback",
			setupAuthRequest:    true,
			authRequestClient:   "test-client",
			authRequestRedirect: "https://rp.example.com/callback",
			expectIDToken:       true,
		},
		{
			name:                "strict mode - valid token exchange with basic auth",
			strictMode:          true,
			method:              "POST",
			grantType:           "authorization_code",
			code:                "valid-code",
			redirectURI:         "https://rp.example.com/callback",
			useBasicAuth:        true,
			clientID:            "test-client",
			clientSecret:        "test-secret",
			setupAuthRequest:    true,
			authRequestClient:   "test-client",
			authRequestRedirect: "https://rp.example.com/callback",
			expectIDToken:       true,
		},
		{
			name:                "strict mode - missing client credentials",
			strictMode:          true,
			method:              "POST",
			grantType:           "authorization_code",
			code:                "valid-code",
			redirectURI:         "https://rp.example.com/callback",
			setupAuthRequest:    true,
			authRequestClient:   "test-client",
			authRequestRedirect: "https://rp.example.com/callback",
			expectError:         true,
			expectCode:          http.StatusUnauthorized,
		},
		{
			name:              "strict mode - client_id mismatch",
			strictMode:        true,
			method:            "POST",
			grantType:         "authorization_code",
			code:              "valid-code",
			clientID:          "wrong-client",
			clientSecret:      "test-secret",
			redirectURI:       "https://rp.example.com/callback",
			setupAuthRequest:  true,
			authRequestClient: "test-client",
			expectError:       true,
			expectCode:        http.StatusBadRequest,
		},
		{
			name:                "strict mode - invalid client secret",
			strictMode:          true,
			method:              "POST",
			grantType:           "authorization_code",
			code:                "valid-code",
			clientID:            "test-client",
			clientSecret:        "wrong-secret",
			redirectURI:         "https://rp.example.com/callback",
			setupAuthRequest:    true,
			authRequestClient:   "test-client",
			authRequestRedirect: "https://rp.example.com/callback",
			expectError:         true,
			expectCode:          http.StatusUnauthorized,
		},
		{
			name:                "strict mode - redirect_uri mismatch",
			strictMode:          true,
			method:              "POST",
			grantType:           "authorization_code",
			code:                "valid-code",
			clientID:            "test-client",
			clientSecret:        "test-secret",
			redirectURI:         "https://wrong.example.com/callback",
			setupAuthRequest:    true,
			authRequestClient:   "test-client",
			authRequestRedirect: "https://rp.example.com/callback",
			expectError:         true,
			expectCode:          http.StatusBadRequest,
		},
		{
			name:                "non-strict mode - no client validation required",
			strictMode:          false,
			method:              "POST",
			grantType:           "authorization_code",
			code:                "valid-code",
			redirectURI:         "https://rp.example.com/callback",
			setupAuthRequest:    true,
			authRequestRedirect: "https://rp.example.com/callback",
			expectIDToken:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := setupTestServer(t, tt.strictMode)

			// Setup authorization request if needed
			if tt.setupAuthRequest {
				now := time.Now()
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
					CapMap:      tailcfg.PeerCapMap{},
				}

				var funnelClientPtr *funnelClient
				if tt.strictMode && tt.authRequestClient != "" {
					funnelClientPtr = &funnelClient{
						ID:          tt.authRequestClient,
						Secret:      "test-secret",
						Name:        "Test Client",
						RedirectURI: tt.authRequestRedirect,
					}
					srv.funnelClients[tt.authRequestClient] = funnelClientPtr
				}

				srv.code["valid-code"] = &authRequest{
					clientID:    tt.authRequestClient,
					nonce:       "nonce123",
					redirectURI: tt.authRequestRedirect,
					validTill:   now.Add(5 * time.Minute),
					remoteUser:  remoteUser,
					localRP:     !tt.strictMode,
					funnelRP:    funnelClientPtr,
				}
			}

			// Create form data
			form := url.Values{}
			form.Set("grant_type", tt.grantType)
			form.Set("code", tt.code)
			form.Set("redirect_uri", tt.redirectURI)

			if !tt.useBasicAuth {
				if tt.clientID != "" {
					form.Set("client_id", tt.clientID)
				}
				if tt.clientSecret != "" {
					form.Set("client_secret", tt.clientSecret)
				}
			}

			req := httptest.NewRequest(tt.method, "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = "127.0.0.1:12345"

			if tt.useBasicAuth && tt.clientID != "" && tt.clientSecret != "" {
				req.SetBasicAuth(tt.clientID, tt.clientSecret)
			}

			rr := httptest.NewRecorder()
			srv.serveToken(rr, req)

			if tt.expectError {
				if rr.Code != tt.expectCode {
					t.Errorf("expected status code %d, got %d: %s", tt.expectCode, rr.Code, rr.Body.String())
				}
			} else if tt.expectIDToken {
				if rr.Code != http.StatusOK {
					t.Errorf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
				}

				var resp struct {
					IDToken     string `json:"id_token"`
					AccessToken string `json:"access_token"`
					TokenType   string `json:"token_type"`
					ExpiresIn   int    `json:"expires_in"`
				}

				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}

				if resp.IDToken == "" {
					t.Error("expected id_token in response")
				}
				if resp.AccessToken == "" {
					t.Error("expected access_token in response")
				}
				if resp.TokenType != "Bearer" {
					t.Errorf("expected token_type 'Bearer', got '%s'", resp.TokenType)
				}
				if resp.ExpiresIn != 300 {
					t.Errorf("expected expires_in 300, got %d", resp.ExpiresIn)
				}

				// Verify access token was stored
				srv.mu.Lock()
				_, ok := srv.accessToken[resp.AccessToken]
				srv.mu.Unlock()

				if !ok {
					t.Error("expected access token to be stored")
				}

				// Verify authorization code was consumed
				srv.mu.Lock()
				_, ok = srv.code[tt.code]
				srv.mu.Unlock()

				if ok {
					t.Error("expected authorization code to be consumed")
				}
			}
		})
	}
}

// TestServeUserInfoWithClientValidation verifies UserInfo endpoint security in both strict and non-strict modes.
// In strict mode, the UserInfo endpoint must:
// - Validate that access tokens are associated with registered clients
// - Reject tokens for clients that have been deleted/unregistered
// - Enforce token expiration properly
// - Return appropriate user claims based on client capabilities
func TestServeUserInfoWithClientValidation(t *testing.T) {
	tests := []struct {
		name           string
		strictMode     bool
		setupToken     bool
		setupClient    bool
		clientID       string
		token          string
		tokenValidTill time.Time
		expectError    bool
		expectCode     int
		expectUserInfo bool
	}{
		{
			name:           "strict mode - valid token with existing client",
			strictMode:     true,
			setupToken:     true,
			setupClient:    true,
			clientID:       "test-client",
			token:          "valid-token",
			tokenValidTill: time.Now().Add(5 * time.Minute),
			expectUserInfo: true,
		},
		{
			name:           "strict mode - valid token but client no longer exists",
			strictMode:     true,
			setupToken:     true,
			setupClient:    false,
			clientID:       "deleted-client",
			token:          "valid-token",
			tokenValidTill: time.Now().Add(5 * time.Minute),
			expectError:    true,
			expectCode:     http.StatusUnauthorized,
		},
		{
			name:           "strict mode - expired token",
			strictMode:     true,
			setupToken:     true,
			setupClient:    true,
			clientID:       "test-client",
			token:          "expired-token",
			tokenValidTill: time.Now().Add(-5 * time.Minute),
			expectError:    true,
			expectCode:     http.StatusBadRequest,
		},
		{
			name:        "strict mode - invalid token",
			strictMode:  true,
			setupToken:  false,
			token:       "invalid-token",
			expectError: true,
			expectCode:  http.StatusBadRequest,
		},
		{
			name:           "strict mode - token without client association",
			strictMode:     true,
			setupToken:     true,
			setupClient:    false,
			clientID:       "",
			token:          "valid-token",
			tokenValidTill: time.Now().Add(5 * time.Minute),
			expectError:    true,
			expectCode:     http.StatusBadRequest,
		},
		{
			name:           "non-strict mode - no client validation required",
			strictMode:     false,
			setupToken:     true,
			setupClient:    false,
			clientID:       "",
			token:          "valid-token",
			tokenValidTill: time.Now().Add(5 * time.Minute),
			expectUserInfo: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := setupTestServer(t, tt.strictMode)

			// Setup client if needed
			if tt.setupClient {
				srv.funnelClients[tt.clientID] = &funnelClient{
					ID:          tt.clientID,
					Secret:      "test-secret",
					Name:        "Test Client",
					RedirectURI: "https://rp.example.com/callback",
				}
			}

			// Setup token if needed
			if tt.setupToken {
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
					CapMap:      tailcfg.PeerCapMap{},
				}

				srv.accessToken[tt.token] = &authRequest{
					clientID:   tt.clientID,
					validTill:  tt.tokenValidTill,
					remoteUser: remoteUser,
				}
			}

			// Create request
			req := httptest.NewRequest("GET", "/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			req.RemoteAddr = "127.0.0.1:12345"

			rr := httptest.NewRecorder()
			srv.serveUserInfo(rr, req)

			if tt.expectError {
				if rr.Code != tt.expectCode {
					t.Errorf("expected status code %d, got %d: %s", tt.expectCode, rr.Code, rr.Body.String())
				}
			} else if tt.expectUserInfo {
				if rr.Code != http.StatusOK {
					t.Errorf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
				}

				var resp map[string]any
				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to parse JSON response: %v", err)
				}

				// Check required fields
				expectedFields := []string{"sub", "name", "email", "picture", "username"}
				for _, field := range expectedFields {
					if _, ok := resp[field]; !ok {
						t.Errorf("expected field '%s' in user info response", field)
					}
				}

				// Verify specific values
				if resp["name"] != "Alice Example" {
					t.Errorf("expected name 'Alice Example', got '%v'", resp["name"])
				}
				if resp["email"] != "alice@example.com" {
					t.Errorf("expected email 'alice@example.com', got '%v'", resp["email"])
				}
				if resp["username"] != "alice" {
					t.Errorf("expected username 'alice', got '%v'", resp["username"])
				}
			}
		})
	}
}
