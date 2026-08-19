// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package oauthkey

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
		tags        []string
		wantAuthKey string
		wantErr     bool
	}{
		{
			name:        "non-client-secret-passthrough",
			clientID:    "tskey-auth-regular",
			tags:        []string{"tag:test"},
			wantAuthKey: "tskey-auth-regular",
			wantErr:     false,
		},
		{
			name:        "client-secret-no-tags",
			clientID:    "tskey-client-abc",
			tags:        nil,
			wantAuthKey: "",
			wantErr:     true,
		},
		{
			name:        "client-secret-default-attrs",
			clientID:    "tskey-client-abc",
			tags:        []string{"tag:test"},
			wantAuthKey: "tskey-auth-xyz",
			wantErr:     false,
		},
		{
			name:        "client-secret-custom-attrs",
			clientID:    "tskey-client-abc?ephemeral=false&preauthorized=true",
			tags:        []string{"tag:test"},
			wantAuthKey: "tskey-auth-xyz",
			wantErr:     false,
		},
		{
			name:        "client-secret-unknown-attr",
			clientID:    "tskey-client-abc?unknown=value",
			tags:        []string{"tag:test"},
			wantAuthKey: "",
			wantErr:     true,
		},
		{
			name:        "client-secret-invalid-attr-value",
			clientID:    "tskey-client-abc?ephemeral=invalid",
			tags:        []string{"tag:test"},
			wantAuthKey: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := mockControlServer(t)
			defer srv.Close()

			// resolveAuthKey reads custom control plane URLs off the baseURL attribute
			// on the client secret string. Therefore, append the baseURL attribute with
			// the mock control server URL to any client secret in order to hit the mock
			// server instead of the default control API.
			if strings.HasPrefix(tt.clientID, "tskey-client") {
				if !strings.Contains(tt.clientID, "?") {
					tt.clientID += "?baseURL=" + srv.URL
				} else {
					tt.clientID += "&baseURL=" + srv.URL
				}
			}

			got, err := resolveAuthKey(context.Background(), tailscale.ResolveAuthKeyArgs{
				AuthKey: tt.clientID,
				Tags:    tt.tags,
			})

			if tt.wantErr {
				if err == nil {
					t.Error("want error but got none")
					return
				}
				return
			}

			if err != nil {
				t.Errorf("want no error, got %q", err)
				return
			}

			if got != tt.wantAuthKey {
				t.Errorf("want authKey = %q, got %q", tt.wantAuthKey, got)
			}
		})
	}
}

func TestResolveAuthKeyAttributes(t *testing.T) {
	tests := []struct {
		name          string
		clientSecret  string
		wantEphemeral bool
		wantPreauth   bool
		wantBaseURL   string
	}{
		{
			name:          "default-values",
			clientSecret:  "tskey-client-abc",
			wantEphemeral: true,
			wantPreauth:   false,
			wantBaseURL:   "https://api.tailscale.com",
		},
		{
			name:          "ephemeral=false",
			clientSecret:  "tskey-client-abc?ephemeral=false",
			wantEphemeral: false,
			wantPreauth:   false,
			wantBaseURL:   "https://api.tailscale.com",
		},
		{
			name:          "preauthorized=true",
			clientSecret:  "tskey-client-abc?preauthorized=true",
			wantEphemeral: true,
			wantPreauth:   true,
			wantBaseURL:   "https://api.tailscale.com",
		},
		{
			name:          "baseURL-custom",
			clientSecret:  "tskey-client-abc?baseURL=https://api.example.com",
			wantEphemeral: true,
			wantPreauth:   false,
			wantBaseURL:   "https://api.example.com",
		},
		{
			name:          "all-custom-values",
			clientSecret:  "tskey-client-abc?ephemeral=false&preauthorized=true&baseURL=https://api.example.com",
			wantEphemeral: false,
			wantPreauth:   true,
			wantBaseURL:   "https://api.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strippedSecret, ephemeral, preauth, baseURL, err := parseOptionalAttributes(tt.clientSecret)
			if err != nil {
				t.Fatalf("want no error, got %q", err)
			}
			if strippedSecret != "tskey-client-abc" {
				t.Errorf("want tskey-client-abc, got %q", strippedSecret)
			}
			if ephemeral != tt.wantEphemeral {
				t.Errorf("want ephemeral = %v, got %v", tt.wantEphemeral, ephemeral)
			}
			if preauth != tt.wantPreauth {
				t.Errorf("want preauth = %v, got %v", tt.wantPreauth, preauth)
			}
			if baseURL != tt.wantBaseURL {
				t.Errorf("want baseURL = %v, got %v", tt.wantBaseURL, baseURL)
			}
		})
	}
}

func TestResolveAuthKeyRetry(t *testing.T) {
	t.Run("refreshes-expired-token-before-createkey", func(t *testing.T) {
		var tokenCalls atomic.Int32
		var gotAuthorization string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/api/v2/oauth/token"):
				n := tokenCalls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if n == 1 {
					w.Write([]byte(`{"access_token":"expired","token_type":"Bearer","expires_in":1}`))
					return
				}
				w.Write([]byte(`{"access_token":"fresh","token_type":"Bearer","expires_in":3600}`))
			case strings.Contains(r.URL.Path, "/api/v2/tailnet") && strings.Contains(r.URL.Path, "/keys"):
				gotAuthorization = r.Header.Get("Authorization")
				w.Write([]byte(`{"key":"tskey-auth-xyz"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		_, err := resolveAuthKey(context.Background(), tailscale.ResolveAuthKeyArgs{
			AuthKey: "tskey-client-abc?baseURL=" + srv.URL,
			Tags:    []string{"tag:test"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := tokenCalls.Load(); got != 2 {
			t.Errorf("token endpoint called %d times, want 2", got)
		}
		if gotAuthorization != "Bearer fresh" {
			t.Errorf("CreateKey Authorization = %q, want fresh token", gotAuthorization)
		}
	})

	t.Run("retries-token-fetch-on-503", func(t *testing.T) {
		var tokenCalls atomic.Int32
		var keyCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/api/v2/oauth/token"):
				n := tokenCalls.Add(1)
				if n < 3 {
					w.WriteHeader(http.StatusServiceUnavailable)
					w.Write([]byte(`{"error":"service_unavailable"}`))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"access_token":"access-123","token_type":"Bearer","expires_in":3600}`))
			case strings.Contains(r.URL.Path, "/api/v2/tailnet") && strings.Contains(r.URL.Path, "/keys"):
				keyCalls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"key":"tskey-auth-xyz"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		authKey, err := resolveAuthKey(context.Background(), tailscale.ResolveAuthKeyArgs{
			AuthKey:                  "tskey-client-abc?baseURL=" + srv.URL,
			Tags:                     []string{"tag:test"},
			RetryTransientAuthErrors: true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if authKey != "tskey-auth-xyz" {
			t.Errorf("got %q, want %q", authKey, "tskey-auth-xyz")
		}
		// The oauth2 library probes two auth styles on the first Token() call
		// (2 HTTP requests, both 503), then caches the style for the retry
		// (1 HTTP request, succeeds). Total: 3 HTTP requests across 2 Token() calls.
		if got := tokenCalls.Load(); got != 3 {
			t.Errorf("token endpoint called %d times, want 3", got)
		}
		if got := keyCalls.Load(); got != 1 {
			t.Errorf("keys endpoint called %d times, want 1", got)
		}
	})

	t.Run("no-retry-without-flag", func(t *testing.T) {
		var tokenCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/api/v2/oauth/token"):
				tokenCalls.Add(1)
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"rate_limited"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		_, err := resolveAuthKey(context.Background(), tailscale.ResolveAuthKeyArgs{
			AuthKey:                  "tskey-client-abc?baseURL=" + srv.URL,
			Tags:                     []string{"tag:test"},
			RetryTransientAuthErrors: false,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		// The oauth2 library probes two auth styles per token fetch, so a single
		// TokenSource().Token() invocation sends 2 HTTP requests.
		if got := tokenCalls.Load(); got != 2 {
			t.Errorf("token endpoint HTTP requests = %d, want 2 (one Token() call)", got)
		}
	})

	t.Run("no-retry-on-createkey-503", func(t *testing.T) {
		var keyCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/api/v2/oauth/token"):
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

		_, err := resolveAuthKey(context.Background(), tailscale.ResolveAuthKeyArgs{
			AuthKey:                  "tskey-client-abc?baseURL=" + srv.URL,
			Tags:                     []string{"tag:test"},
			RetryTransientAuthErrors: true,
		})
		if err == nil {
			t.Fatal("expected error on CreateKey 503")
		}
		if got := keyCalls.Load(); got != 1 {
			t.Errorf("CreateKey called %d times, want 1 (no retry)", got)
		}
	})
}

func mockControlServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/api/v2/oauth/token"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"access-123","token_type":"Bearer","expires_in":3600}`))
		case strings.Contains(r.URL.Path, "/api/v2/tailnet") && strings.Contains(r.URL.Path, "/keys"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"key":"tskey-auth-xyz"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}
