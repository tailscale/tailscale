// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func TestNewStaticClient(t *testing.T) {
	const (
		clientIDFile     = "client-id"
		clientSecretFile = "client-secret"
	)

	tmp := t.TempDir()
	clientIDPath := filepath.Join(tmp, clientIDFile)
	if err := os.WriteFile(clientIDPath, []byte("test-client-id"), 0600); err != nil {
		t.Fatalf("error writing test file %q: %v", clientIDPath, err)
	}
	clientSecretPath := filepath.Join(tmp, clientSecretFile)
	if err := os.WriteFile(clientSecretPath, []byte("test-client-secret"), 0600); err != nil {
		t.Fatalf("error writing test file %q: %v", clientSecretPath, err)
	}

	srv := testAPI(t, 3600)
	cl, err := newTSClient(zap.NewNop().Sugar(), "", clientIDPath, clientSecretPath, srv.URL)
	if err != nil {
		t.Fatalf("error creating Tailscale client: %v", err)
	}

	resp, err := cl.HTTPClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("error making test API call: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading response body: %v", err)
	}
	want := "Bearer " + testToken("/api/v2/oauth/token", "test-client-id", "test-client-secret", "")
	if string(got) != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestNewWorkloadIdentityClient(t *testing.T) {
	// 5 seconds is within expiryDelta leeway, so the access token will
	// immediately be considered expired and get refreshed on each access.
	srv := testAPI(t, 5)
	cl, err := newTSClient(zap.NewNop().Sugar(), "test-client-id", "", "", srv.URL)
	if err != nil {
		t.Fatalf("error creating Tailscale client: %v", err)
	}

	// Modify the path where the JWT will be read from.
	oauth2Transport, ok := cl.HTTPClient.Transport.(*oauth2.Transport)
	if !ok {
		t.Fatalf("expected oauth2.Transport, got %T", cl.HTTPClient.Transport)
	}
	jwtTokenSource, ok := oauth2Transport.Source.(*jwtTokenSource)
	if !ok {
		t.Fatalf("expected jwtTokenSource, got %T", oauth2Transport.Source)
	}
	tmp := t.TempDir()
	jwtPath := filepath.Join(tmp, "token")
	jwtTokenSource.jwtPath = jwtPath

	for _, jwt := range []string{"test-jwt", "updated-test-jwt"} {
		if err := os.WriteFile(jwtPath, []byte(jwt), 0600); err != nil {
			t.Fatalf("error writing test file %q: %v", jwtPath, err)
		}
		resp, err := cl.HTTPClient.Get(srv.URL)
		if err != nil {
			t.Fatalf("error making test API call: %v", err)
		}
		defer resp.Body.Close()

		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("error reading response body: %v", err)
		}
		if want := "Bearer " + testToken("/api/v2/oauth/token-exchange", "test-client-id", "", jwt); string(got) != want {
			t.Errorf("got %q; want %q", got, want)
		}
	}
}

func testAPI(t *testing.T, expirationSeconds int) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("test server got request: %s %s", r.Method, r.URL.Path)
		switch r.URL.Path {
		case "/api/v2/oauth/token", "/api/v2/oauth/token-exchange":
			id, secret, ok := r.BasicAuth()
			if !ok {
				t.Fatal("missing or invalid basic auth")
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]any{
				"access_token": testToken(r.URL.Path, id, secret, r.FormValue("jwt")),
				"token_type":   "Bearer",
				"expires_in":   expirationSeconds,
			}); err != nil {
				t.Fatalf("error writing response: %v", err)
			}
		case "/":
			// Echo back the authz header for test assertions.
			_, err := w.Write([]byte(r.Header.Get("Authorization")))
			if err != nil {
				t.Fatalf("error writing response: %v", err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testToken(path, id, secret, jwt string) string {
	return fmt.Sprintf("%s|%s|%s|%s", path, id, secret, jwt)
}
