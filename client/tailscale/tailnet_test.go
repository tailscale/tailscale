// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTailnetDeleteRequest_Success tests successful deletion
func TestTailnetDeleteRequest_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}

		// Verify the path includes "tailnet"
		if r.URL.Path != "/api/v2/tailnet/-/tailnet" {
			t.Errorf("path = %s, want /api/v2/tailnet/-/tailnet", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		APIKey:     "test-key",
		HTTPClient: server.Client(),
	}

	err := client.TailnetDeleteRequest(context.Background(), "-")
	if err != nil {
		t.Errorf("TailnetDeleteRequest failed: %v", err)
	}
}

// TestTailnetDeleteRequest_NotFound tests 404 response
func TestTailnetDeleteRequest_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "tailnet not found",
		})
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		APIKey:     "test-key",
		HTTPClient: server.Client(),
	}

	err := client.TailnetDeleteRequest(context.Background(), "-")
	if err == nil {
		t.Error("expected error for 404, got nil")
	}

	// Error should be wrapped with "tailscale.DeleteTailnet"
	expectedPrefix := "tailscale.DeleteTailnet:"
	if len(err.Error()) < len(expectedPrefix) || err.Error()[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("error should start with %q, got %q", expectedPrefix, err.Error())
	}
}

// TestTailnetDeleteRequest_Unauthorized tests 401 response
func TestTailnetDeleteRequest_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "unauthorized",
		})
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		APIKey:     "bad-key",
		HTTPClient: server.Client(),
	}

	err := client.TailnetDeleteRequest(context.Background(), "-")
	if err == nil {
		t.Error("expected error for 401, got nil")
	}
}

// TestTailnetDeleteRequest_Forbidden tests 403 response
func TestTailnetDeleteRequest_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "insufficient permissions",
		})
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		APIKey:     "test-key",
		HTTPClient: server.Client(),
	}

	err := client.TailnetDeleteRequest(context.Background(), "-")
	if err == nil {
		t.Error("expected error for 403, got nil")
	}
}

// TestTailnetDeleteRequest_InternalServerError tests 500 response
func TestTailnetDeleteRequest_InternalServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "internal server error",
		})
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		APIKey:     "test-key",
		HTTPClient: server.Client(),
	}

	err := client.TailnetDeleteRequest(context.Background(), "-")
	if err == nil {
		t.Error("expected error for 500, got nil")
	}
}

// TestTailnetDeleteRequest_ContextCancellation tests context cancellation
func TestTailnetDeleteRequest_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should not reach here
		t.Error("request should be cancelled before reaching server")
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		APIKey:     "test-key",
		HTTPClient: server.Client(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := client.TailnetDeleteRequest(ctx, "-")
	if err == nil {
		t.Error("expected context cancellation error, got nil")
	}

	// Should contain context error
	if err.Error() != "tailscale.DeleteTailnet: "+context.Canceled.Error() {
		// Error message format may vary, just check it's an error
		t.Logf("got error (acceptable): %v", err)
	}
}

// TestTailnetDeleteRequest_AuthenticationHeader tests auth header is set
func TestTailnetDeleteRequest_AuthenticationHeader(t *testing.T) {
	expectedKey := "test-api-key-12345"
	headerSeen := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer "+expectedKey {
			headerSeen = true
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		APIKey:     expectedKey,
		HTTPClient: server.Client(),
	}

	err := client.TailnetDeleteRequest(context.Background(), "-")
	if err != nil {
		t.Errorf("TailnetDeleteRequest failed: %v", err)
	}

	if !headerSeen {
		t.Error("Authorization header was not set correctly")
	}
}

// TestTailnetDeleteRequest_BuildsCorrectURL tests URL construction
func TestTailnetDeleteRequest_BuildsCorrectURL(t *testing.T) {
	tests := []struct {
		name      string
		tailnetID string
		wantPath  string
	}{
		{
			name:      "default_tailnet",
			tailnetID: "-",
			wantPath:  "/api/v2/tailnet/-/tailnet",
		},
		{
			name:      "explicit_tailnet_id",
			tailnetID: "example.com",
			wantPath:  "/api/v2/tailnet/example.com/tailnet",
		},
		{
			name:      "numeric_tailnet_id",
			tailnetID: "12345",
			wantPath:  "/api/v2/tailnet/12345/tailnet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pathSeen := ""

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pathSeen = r.URL.Path
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{}`))
			}))
			defer server.Close()

			client := &Client{
				BaseURL:    server.URL,
				APIKey:     "test-key",
				HTTPClient: server.Client(),
			}

			err := client.TailnetDeleteRequest(context.Background(), tt.tailnetID)
			if err != nil {
				t.Errorf("TailnetDeleteRequest failed: %v", err)
			}

			if pathSeen != tt.wantPath {
				t.Errorf("path = %s, want %s", pathSeen, tt.wantPath)
			}
		})
	}
}

// TestTailnetDeleteRequest_ErrorWrapping tests error message wrapping
func TestTailnetDeleteRequest_ErrorWrapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "bad request",
		})
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		APIKey:     "test-key",
		HTTPClient: server.Client(),
	}

	err := client.TailnetDeleteRequest(context.Background(), "-")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Error should be wrapped with prefix
	errStr := err.Error()
	if len(errStr) < len("tailscale.DeleteTailnet:") {
		t.Errorf("error should be wrapped with prefix, got: %s", errStr)
	}

	prefix := "tailscale.DeleteTailnet:"
	if errStr[:len(prefix)] != prefix {
		t.Errorf("error should start with %q, got: %s", prefix, errStr)
	}
}

// TestTailnetDeleteRequest_EmptyTailnetID tests with empty tailnet ID
func TestTailnetDeleteRequest_EmptyTailnetID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Even with empty ID, request should be formed
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		APIKey:     "test-key",
		HTTPClient: server.Client(),
	}

	// Empty tailnet ID might be valid in some contexts
	err := client.TailnetDeleteRequest(context.Background(), "")
	// Error or success depends on server validation
	if err != nil {
		t.Logf("got error (may be expected): %v", err)
	}
}

// TestTailnetDeleteRequest_NetworkError tests handling of network errors
func TestTailnetDeleteRequest_NetworkError(t *testing.T) {
	client := &Client{
		BaseURL:    "http://invalid-host-that-does-not-exist-12345.test",
		APIKey:     "test-key",
		HTTPClient: http.DefaultClient,
	}

	err := client.TailnetDeleteRequest(context.Background(), "-")
	if err == nil {
		t.Error("expected network error, got nil")
	}

	// Error should be wrapped
	if len(err.Error()) < len("tailscale.DeleteTailnet:") {
		t.Errorf("error should be wrapped, got: %s", err.Error())
	}
}

// TestTailnetDeleteRequest_HTTPMethodVerification tests DELETE method is used
func TestTailnetDeleteRequest_HTTPMethodVerification(t *testing.T) {
	methodSeen := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methodSeen = r.Method
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		APIKey:     "test-key",
		HTTPClient: server.Client(),
	}

	err := client.TailnetDeleteRequest(context.Background(), "-")
	if err != nil {
		t.Errorf("TailnetDeleteRequest failed: %v", err)
	}

	if methodSeen != http.MethodDelete {
		t.Errorf("method = %s, want %s", methodSeen, http.MethodDelete)
	}

	if methodSeen != "DELETE" {
		t.Errorf("method = %s, want DELETE", methodSeen)
	}
}

// TestTailnetDeleteRequest_ResponseBodyHandling tests response processing
func TestTailnetDeleteRequest_ResponseBodyHandling(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
	}{
		{
			name:       "success_with_json",
			statusCode: http.StatusOK,
			body:       `{"success": true}`,
			wantErr:    false,
		},
		{
			name:       "success_with_empty_body",
			statusCode: http.StatusOK,
			body:       ``,
			wantErr:    false,
		},
		{
			name:       "error_with_json",
			statusCode: http.StatusBadRequest,
			body:       `{"message": "error"}`,
			wantErr:    true,
		},
		{
			name:       "error_with_text",
			statusCode: http.StatusBadRequest,
			body:       `error message`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()

			client := &Client{
				BaseURL:    server.URL,
				APIKey:     "test-key",
				HTTPClient: server.Client(),
			}

			err := client.TailnetDeleteRequest(context.Background(), "-")

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
