// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package identityfederation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveAuthKey(t *testing.T) {
	tests := []struct {
		name        string
		clientID    string
		idToken     string
		tags        []string
		wantAuthKey string
		wantErr     string
	}{
		{
			name:        "success",
			clientID:    "client-123",
			idToken:     "token",
			tags:        []string{"tag:test"},
			wantAuthKey: "tskey-auth-xyz",
			wantErr:     "",
		},
		{
			name:        "missing client id short-circuits without error",
			clientID:    "",
			idToken:     "token",
			tags:        []string{"tag:test"},
			wantAuthKey: "",
			wantErr:     "",
		},
		{
			name:     "missing id token",
			clientID: "client-123",
			idToken:  "",
			tags:     []string{"tag:test"},
			wantErr:  "federated identity authkeys require --id-token",
		},
		{
			name:     "missing tags",
			clientID: "client-123",
			idToken:  "token",
			tags:     []string{},
			wantErr:  "federated identity authkeys require --advertise-tags",
		},
		{
			name:     "invalid client id attributes",
			clientID: "client-123?invalid=value",
			idToken:  "token",
			tags:     []string{"tag:test"},
			wantErr:  `failed to parse optional config attributes: unknown optional config attribute "invalid"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := mockedControlServer(t)
			defer srv.Close()

			authKey, err := resolveAuthKey(context.Background(), srv.URL, tt.clientID, tt.idToken, tt.tags)
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("resolveAuthKey() error = nil, want %q", tt.wantErr)
					return
				}
				if err.Error() != tt.wantErr {
					t.Errorf("resolveAuthKey() error = %q, want %q", err.Error(), tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("resolveAuthKey() unexpected error = %v", err)
			}
			if authKey != tt.wantAuthKey {
				t.Errorf("resolveAuthKey() = %q, want %q", authKey, tt.wantAuthKey)
			}
		})
	}
}

func TestParseOptionalAttributes(t *testing.T) {
	tests := []struct {
		name          string
		clientID      string
		wantClientID  string
		wantEphemeral bool
		wantPreauth   bool
		wantErr       string
	}{
		{
			name:          "default values",
			clientID:      "client-123",
			wantClientID:  "client-123",
			wantEphemeral: true,
			wantPreauth:   false,
			wantErr:       "",
		},
		{
			name:          "custom values",
			clientID:      "client-123?ephemeral=false&preauthorized=true",
			wantClientID:  "client-123",
			wantEphemeral: false,
			wantPreauth:   true,
			wantErr:       "",
		},
		{
			name:          "unknown attribute",
			clientID:      "client-123?unknown=value",
			wantClientID:  "",
			wantEphemeral: false,
			wantPreauth:   false,
			wantErr:       `unknown optional config attribute "unknown"`,
		},
		{
			name:          "invalid value",
			clientID:      "client-123?ephemeral=invalid",
			wantClientID:  "",
			wantEphemeral: false,
			wantPreauth:   false,
			wantErr:       `strconv.ParseBool: parsing "invalid": invalid syntax`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strippedID, ephemeral, preauth, err := parseOptionalAttributes(tt.clientID)
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("parseOptionalAttributes() error = nil, want %q", tt.wantErr)
					return
				}
				if err.Error() != tt.wantErr {
					t.Errorf("parseOptionalAttributes() error = %q, want %q", err.Error(), tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("parseOptionalAttributes() error = %v, want nil", err)
					return
				}
			}
			if strippedID != tt.wantClientID {
				t.Errorf("parseOptionalAttributes() strippedID = %v, want %v", strippedID, tt.wantClientID)
			}
			if ephemeral != tt.wantEphemeral {
				t.Errorf("parseOptionalAttributes() ephemeral = %v, want %v", ephemeral, tt.wantEphemeral)
			}
			if preauth != tt.wantPreauth {
				t.Errorf("parseOptionalAttributes() preauth = %v, want %v", preauth, tt.wantPreauth)
			}
		})
	}
}

func mockedControlServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth/token-exchange"):
			// OAuth2 library sends the token exchange request
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"access-123","token_type":"Bearer","expires_in":3600}`))
		case strings.Contains(r.URL.Path, "/api/v2/tailnet") && strings.Contains(r.URL.Path, "/keys"):
			// Tailscale client creates the authkey
			w.Write([]byte(`{"key":"tskey-auth-xyz","created":"2024-01-01T00:00:00Z"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}
