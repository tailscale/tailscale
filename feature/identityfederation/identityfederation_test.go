// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package identityfederation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"tailscale.com/internal/client/tailscale"
)

func TestResolveAuthKey(t *testing.T) {
	tests := []struct {
		name        string
		clientID    string
		idToken     string
		audience    string
		tags        []string
		wantAuthKey string
		wantErr     string
	}{
		{
			name:        "success",
			clientID:    "client-123",
			idToken:     "token",
			audience:    "api://tailscale-wif",
			tags:        []string{"tag:test"},
			wantAuthKey: "tskey-auth-xyz",
			wantErr:     "",
		},
		{
			name:        "missing-client-id-noop",
			clientID:    "",
			idToken:     "token",
			audience:    "api://tailscale-wif",
			tags:        []string{"tag:test"},
			wantAuthKey: "",
			wantErr:     "",
		},
		{
			name:     "missing-id-token-and-audience",
			clientID: "client-123",
			idToken:  "",
			audience: "",
			tags:     []string{"tag:test"},
			wantErr:  "federated identity requires either an ID token or an audience",
		},
		{
			name:     "missing-tags",
			clientID: "client-123",
			idToken:  "token",
			audience: "api://tailscale-wif",
			tags:     []string{},
			wantErr:  "federated identity authkeys require --advertise-tags",
		},
		{
			name:     "invalid-client-id-attrs",
			clientID: "client-123?invalid=value",
			idToken:  "token",
			audience: "api://tailscale-wif",
			tags:     []string{"tag:test"},
			wantErr:  `failed to parse optional config attributes: unknown optional config attribute "invalid"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := mockedControlServer(t)
			defer srv.Close()

			authKey, err := resolveAuthKey(context.Background(), tailscale.ResolveAuthKeyWIFArgs{
				BaseURL:  srv.URL,
				ClientID: tt.clientID,
				IDToken:  tt.idToken,
				Audience: tt.audience,
				Tags:     tt.tags,
			})
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
			name:          "default-values",
			clientID:      "client-123",
			wantClientID:  "client-123",
			wantEphemeral: true,
			wantPreauth:   false,
			wantErr:       "",
		},
		{
			name:          "custom-values",
			clientID:      "client-123?ephemeral=false&preauthorized=true",
			wantClientID:  "client-123",
			wantEphemeral: false,
			wantPreauth:   true,
			wantErr:       "",
		},
		{
			name:          "unknown-attribute",
			clientID:      "client-123?unknown=value",
			wantClientID:  "",
			wantEphemeral: false,
			wantPreauth:   false,
			wantErr:       `unknown optional config attribute "unknown"`,
		},
		{
			name:          "invalid-value",
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

func TestResolveAuthKeyRetry(t *testing.T) {
	t.Run("retries-token-exchange-on-503", func(t *testing.T) {
		var tokenCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/oauth/token-exchange"):
				n := tokenCalls.Add(1)
				if n < 3 {
					w.WriteHeader(http.StatusServiceUnavailable)
					w.Write([]byte(`{"error":"service_unavailable"}`))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"access_token":"access-123","token_type":"Bearer","expires_in":3600}`))
			case strings.Contains(r.URL.Path, "/api/v2/tailnet") && strings.Contains(r.URL.Path, "/keys"):
				w.Write([]byte(`{"key":"tskey-auth-xyz","created":"2024-01-01T00:00:00Z"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		authKey, err := resolveAuthKey(context.Background(), tailscale.ResolveAuthKeyWIFArgs{
			BaseURL:              srv.URL,
			ClientID:             "client-123",
			IDToken:              "token",
			Tags:                 []string{"tag:test"},
			RetryTransientAuthErrors: true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if authKey != "tskey-auth-xyz" {
			t.Errorf("got %q, want %q", authKey, "tskey-auth-xyz")
		}
		// The oauth2 library probes two auth styles on the first Exchange() call
		// (2 HTTP requests, both 503), then caches the style for the retry
		// (1 HTTP request, succeeds). Total: 3 HTTP requests across 2 Exchange() calls.
		if got := tokenCalls.Load(); got != 3 {
			t.Errorf("token exchange called %d times, want 3", got)
		}
	})

	t.Run("no-retry-without-flag", func(t *testing.T) {
		var tokenCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/oauth/token-exchange"):
				tokenCalls.Add(1)
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"rate_limited"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		_, err := resolveAuthKey(context.Background(), tailscale.ResolveAuthKeyWIFArgs{
			BaseURL:              srv.URL,
			ClientID:             "client-123",
			IDToken:              "token",
			Tags:                 []string{"tag:test"},
			RetryTransientAuthErrors: false,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		// The oauth2 library probes two auth styles per Exchange call, so a single
		// exchangeJWTForToken invocation sends 2 HTTP requests.
		if got := tokenCalls.Load(); got != 2 {
			t.Errorf("token exchange HTTP requests = %d, want 2 (one Exchange call)", got)
		}
	})

	t.Run("no-retry-on-createkey-503", func(t *testing.T) {
		var keyCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/oauth/token-exchange"):
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"access_token":"access-123","token_type":"Bearer","expires_in":3600}`))
			case strings.Contains(r.URL.Path, "/api/v2/tailnet") && strings.Contains(r.URL.Path, "/keys"):
				keyCalls.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(`{"message":"service unavailable"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		_, err := resolveAuthKey(context.Background(), tailscale.ResolveAuthKeyWIFArgs{
			BaseURL:              srv.URL,
			ClientID:             "client-123",
			IDToken:              "token",
			Tags:                 []string{"tag:test"},
			RetryTransientAuthErrors: true,
		})
		if err == nil {
			t.Fatal("expected error on CreateKey 503")
		}
		if got := keyCalls.Load(); got != 1 {
			t.Errorf("CreateKey called %d times, want 1 (no retry)", got)
		}
	})

	t.Run("retries-token-exchange-on-429", func(t *testing.T) {
		var tokenCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/oauth/token-exchange"):
				n := tokenCalls.Add(1)
				if n < 2 {
					w.WriteHeader(http.StatusTooManyRequests)
					w.Write([]byte(`{"error":"rate_limited"}`))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"access_token":"access-123","token_type":"Bearer","expires_in":3600}`))
			case strings.Contains(r.URL.Path, "/api/v2/tailnet") && strings.Contains(r.URL.Path, "/keys"):
				w.Write([]byte(`{"key":"tskey-auth-xyz","created":"2024-01-01T00:00:00Z"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		authKey, err := resolveAuthKey(context.Background(), tailscale.ResolveAuthKeyWIFArgs{
			BaseURL:              srv.URL,
			ClientID:             "client-123",
			IDToken:              "token",
			Tags:                 []string{"tag:test"},
			RetryTransientAuthErrors: true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if authKey != "tskey-auth-xyz" {
			t.Errorf("got %q, want %q", authKey, "tskey-auth-xyz")
		}
		if got := tokenCalls.Load(); got != 2 {
			t.Errorf("token exchange called %d times, want 2", got)
		}
	})
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
