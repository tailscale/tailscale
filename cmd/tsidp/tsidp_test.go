// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"testing"
	"time"
)

// normalizeMap recursively sorts []interface{} values in a map[string]interface{}
func normalizeMap(t *testing.T, m map[string]interface{}) map[string]interface{} {
	t.Helper()
	normalized := make(map[string]interface{}, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case []interface{}:
			sorted := make([]string, len(val))
			for i, item := range val {
				sorted[i] = fmt.Sprintf("%v", item) // convert everything to string for sorting
			}
			sort.Strings(sorted)

			// convert back to []interface{}
			sortedIface := make([]interface{}, len(sorted))
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
		expected map[string]interface{}
	}{
		{
			name: "empty extra claims",
			input: []capRule{
				{ExtraClaims: map[string]interface{}{}},
			},
			expected: map[string]interface{}{},
		},
		{
			name: "string and number values",
			input: []capRule{
				{
					ExtraClaims: map[string]interface{}{
						"featureA": "read",
						"featureB": 42,
					},
				},
			},
			expected: map[string]interface{}{
				"featureA": "read",
				"featureB": "42",
			},
		},
		{
			name: "slice of strings and ints",
			input: []capRule{
				{
					ExtraClaims: map[string]interface{}{
						"roles": []interface{}{"admin", "user", 1},
					},
				},
			},
			expected: map[string]interface{}{
				"roles": []interface{}{"admin", "user", "1"},
			},
		},
		{
			name: "duplicate values deduplicated (slice input)",
			input: []capRule{
				{
					ExtraClaims: map[string]interface{}{
						"foo": []string{"bar", "baz"},
					},
				},
				{
					ExtraClaims: map[string]interface{}{
						"foo": []interface{}{"bar", "qux"},
					},
				},
			},
			expected: map[string]interface{}{
				"foo": []interface{}{"bar", "baz", "qux"},
			},
		},
		{
			name: "ignore unsupported map type, keep valid scalar",
			input: []capRule{
				{
					ExtraClaims: map[string]interface{}{
						"invalid": map[string]interface{}{"bad": "yes"},
						"valid":   "ok",
					},
				},
			},
			expected: map[string]interface{}{
				"valid": "ok",
			},
		},
		{
			name: "scalar first, slice second",
			input: []capRule{
				{ExtraClaims: map[string]interface{}{"foo": "bar"}},
				{ExtraClaims: map[string]interface{}{"foo": []interface{}{"baz"}}},
			},
			expected: map[string]interface{}{
				"foo": []interface{}{"bar", "baz"}, // since first was scalar, second being a slice forces slice output
			},
		},
		{
			name: "conflicting scalar and unsupported map",
			input: []capRule{
				{ExtraClaims: map[string]interface{}{"foo": "bar"}},
				{ExtraClaims: map[string]interface{}{"foo": map[string]interface{}{"bad": "entry"}}},
			},
			expected: map[string]interface{}{
				"foo": "bar", // map should be ignored
			},
		},
		{
			name: "multiple slices with overlap",
			input: []capRule{
				{ExtraClaims: map[string]interface{}{"roles": []interface{}{"admin", "user"}}},
				{ExtraClaims: map[string]interface{}{"roles": []interface{}{"admin", "guest"}}},
			},
			expected: map[string]interface{}{
				"roles": []interface{}{"admin", "user", "guest"},
			},
		},
		{
			name: "slice with unsupported values",
			input: []capRule{
				{ExtraClaims: map[string]interface{}{
					"mixed": []interface{}{"ok", 42, map[string]string{"oops": "fail"}},
				}},
			},
			expected: map[string]interface{}{
				"mixed": []interface{}{"ok", "42"}, // map is ignored
			},
		},
		{
			name: "duplicate scalar value",
			input: []capRule{
				{ExtraClaims: map[string]interface{}{"env": "prod"}},
				{ExtraClaims: map[string]interface{}{"env": "prod"}},
			},
			expected: map[string]interface{}{
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
		expected    map[string]interface{}
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
					ExtraClaims: map[string]interface{}{
						"foo": []string{"bar"},
					},
				},
			},
			expected: map[string]interface{}{
				"nonce":     "foobar",
				"key":       "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
				"addresses": nil,
				"nid":       float64(0),
				"node":      "test-node",
				"tailnet":   "test.ts.net",
				"email":     "test@example.com",
				"username":  "test",
				"foo":       []interface{}{"bar"},
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
					ExtraClaims: map[string]interface{}{
						"foo": []string{"bar"},
					},
				},
				{
					ExtraClaims: map[string]interface{}{
						"foo": []string{"foobar"},
					},
				},
			},
			expected: map[string]interface{}{
				"nonce":     "foobar",
				"key":       "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
				"addresses": nil,
				"nid":       float64(0),
				"node":      "test-node",
				"tailnet":   "test.ts.net",
				"email":     "test@example.com",
				"username":  "test",
				"foo":       []interface{}{"foobar", "bar"},
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
					ExtraClaims: map[string]interface{}{
						"foo": []string{"bar"},
					},
				},
				{
					ExtraClaims: map[string]interface{}{
						"bar": []string{"foo"},
					},
				},
			},
			expected: map[string]interface{}{
				"nonce":     "foobar",
				"key":       "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
				"addresses": nil,
				"nid":       float64(0),
				"node":      "test-node",
				"tailnet":   "test.ts.net",
				"email":     "test@example.com",
				"username":  "test",
				"foo":       []interface{}{"bar"},
				"bar":       []interface{}{"foo"},
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
					ExtraClaims: map[string]interface{}{
						"username": "foobar",
					},
				},
			},
			expected: map[string]interface{}{
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
			extraClaims: []capRule{{ExtraClaims: map[string]interface{}{}}},
			expected: map[string]interface{}{
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

			// Marshal to JSON then unmarshal back to map[string]interface{}
			gotClaims, err := json.Marshal(claims)
			if err != nil {
				t.Errorf("json.Marshal(claims) error = %v", err)
			}

			var gotClaimsMap map[string]interface{}
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
		expected    map[string]interface{}
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
						ExtraClaims: map[string]interface{}{
							"foo": "bar",
						},
					}),
				},
			},
			expected: map[string]interface{}{
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
						ExtraClaims: map[string]interface{}{
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

			out := make(map[string]interface{})
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
		expected       map[string]interface{}
		expectError    bool
	}{
		{
			name:           "extra claim",
			tokenValidTill: time.Now().Add(1 * time.Minute),
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: true,
						ExtraClaims: map[string]interface{}{
							"foo": []string{"bar"},
						},
					}),
				},
			},
			expected: map[string]interface{}{
				"foo": []interface{}{"bar"},
			},
		},
		{
			name:           "duplicate claim distinct values",
			tokenValidTill: time.Now().Add(1 * time.Minute),
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: true,
						ExtraClaims: map[string]interface{}{
							"foo": []string{"bar", "foobar"},
						},
					}),
				},
			},
			expected: map[string]interface{}{
				"foo": []interface{}{"bar", "foobar"},
			},
		},
		{
			name:           "multiple extra claims",
			tokenValidTill: time.Now().Add(1 * time.Minute),
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: true,
						ExtraClaims: map[string]interface{}{
							"foo": "bar",
							"bar": "foo",
						},
					}),
				},
			},
			expected: map[string]interface{}{
				"foo": "bar",
				"bar": "foo",
			},
		},
		{
			name:           "empty extra claims",
			caps:           tailcfg.PeerCapMap{},
			tokenValidTill: time.Now().Add(1 * time.Minute),
			expected:       map[string]interface{}{},
		},
		{
			name:           "attempt to overwrite protected claim",
			tokenValidTill: time.Now().Add(1 * time.Minute),
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: true,
						ExtraClaims: map[string]interface{}{
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
						ExtraClaims: map[string]interface{}{
							"foo": "ok",
						},
					}),
				},
			},
			expected: map[string]interface{}{},
		},
		{
			name:           "expired token",
			caps:           tailcfg.PeerCapMap{},
			tokenValidTill: time.Now().Add(-1 * time.Minute),
			expected:       map[string]interface{}{},
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

			var resp map[string]interface{}
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
