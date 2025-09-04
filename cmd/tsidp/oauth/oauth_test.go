// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package oauth

import (
	"testing"
)

// TestValidateCodeVerifier tests PKCE code verifier validation
// Migrated from legacy/tsidp_test.go PKCE-related tests
func TestValidateCodeVerifier(t *testing.T) {
	tests := []struct {
		name      string
		verifier  string
		challenge string
		method    string
		wantErr   bool
	}{
		{
			name:      "plain method - matching",
			verifier:  "test-verifier",
			challenge: "test-verifier",
			method:    "plain",
			wantErr:   false,
		},
		{
			name:      "plain method - not matching",
			verifier:  "test-verifier",
			challenge: "different-challenge",
			method:    "plain",
			wantErr:   true,
		},
		{
			name:      "S256 method - matching",
			verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			method:    "S256",
			wantErr:   false,
		},
		{
			name:      "S256 method - not matching",
			verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge: "wrong-challenge",
			method:    "S256",
			wantErr:   true,
		},
		{
			name:      "no PKCE",
			verifier:  "",
			challenge: "",
			method:    "",
			wantErr:   false,
		},
		{
			name:      "unsupported method",
			verifier:  "test",
			challenge: "test",
			method:    "unsupported",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCodeVerifier(tt.verifier, tt.challenge, tt.method)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCodeVerifier() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestGenerateCodeChallenge tests PKCE code challenge generation
func TestGenerateCodeChallenge(t *testing.T) {
	tests := []struct {
		name          string
		verifier      string
		method        string
		wantChallenge string
		wantErr       bool
	}{
		{
			name:          "plain method",
			verifier:      "test-verifier",
			method:        "plain",
			wantChallenge: "test-verifier",
			wantErr:       false,
		},
		{
			name:          "S256 method",
			verifier:      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			method:        "S256",
			wantChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			wantErr:       false,
		},
		{
			name:     "unsupported method",
			verifier: "test",
			method:   "unsupported",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateCodeChallenge(tt.verifier, tt.method)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCodeChallenge() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.wantChallenge {
				t.Errorf("GenerateCodeChallenge() = %v, want %v", got, tt.wantChallenge)
			}
		})
	}
}

// TestValidateScopes tests scope validation
// Migrated from legacy/tsidp_test.go scope-related tests
func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name         string
		scopes       []string
		enableSTS    bool
		wantScopes   []string
		wantErr      bool
	}{
		{
			name:       "default to openid",
			scopes:     []string{},
			enableSTS:  false,
			wantScopes: []string{"openid"},
			wantErr:    false,
		},
		{
			name:       "valid basic scopes",
			scopes:     []string{"openid", "profile", "email"},
			enableSTS:  false,
			wantScopes: []string{"openid", "profile", "email"},
			wantErr:    false,
		},
		{
			name:       "resource scope",
			scopes:     []string{"openid", "resource:https://api.example.com"},
			enableSTS:  false,
			wantScopes: []string{"openid", "resource:https://api.example.com"},
			wantErr:    false,
		},
		{
			name:       "STS scopes disabled",
			scopes:     []string{"openid", "urn:x-oath:params:oauth:token-type:access_token"},
			enableSTS:  false,
			wantScopes: nil,
			wantErr:    true,
		},
		{
			name:       "STS scopes enabled",
			scopes:     []string{"openid", "urn:x-oath:params:oauth:token-type:access_token"},
			enableSTS:  true,
			wantScopes: []string{"openid", "urn:x-oath:params:oauth:token-type:access_token"},
			wantErr:    false,
		},
		{
			name:       "invalid scope",
			scopes:     []string{"openid", "invalid_scope"},
			enableSTS:  false,
			wantScopes: nil,
			wantErr:    true,
		},
		{
			name:       "duplicate scopes",
			scopes:     []string{"openid", "profile", "openid"},
			enableSTS:  false,
			wantScopes: []string{"openid", "profile"},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateScopes(tt.scopes, tt.enableSTS)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScopes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.wantScopes) {
					t.Errorf("ValidateScopes() = %v, want %v", got, tt.wantScopes)
					return
				}
				for i, scope := range got {
					if scope != tt.wantScopes[i] {
						t.Errorf("ValidateScopes() scope[%d] = %v, want %v", i, scope, tt.wantScopes[i])
					}
				}
			}
		})
	}
}