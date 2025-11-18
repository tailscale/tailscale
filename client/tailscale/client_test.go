// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLocalClient_Socket(t *testing.T) {
	tests := []struct {
		name   string
		lc     LocalClient
		want   string
		isPath bool
	}{
		{
			name: "custom_socket",
			lc:   LocalClient{Socket: "/custom/path/tailscaled.sock"},
			want: "/custom/path/tailscaled.sock",
		},
		{
			name:   "default_socket",
			lc:     LocalClient{},
			isPath: true, // Will use platform default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.lc.socket()
			if !tt.isPath && got != tt.want {
				t.Errorf("socket() = %q, want %q", got, tt.want)
			}
			if tt.isPath && got == "" {
				t.Error("socket() returned empty for default")
			}
		})
	}
}

func TestLocalClient_Dialer(t *testing.T) {
	customDialerCalled := false
	customDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		customDialerCalled = true
		return nil, errors.New("custom dialer called")
	}

	lc := &LocalClient{Dial: customDialer}
	dialer := lc.dialer()

	_, err := dialer(context.Background(), "tcp", "test:80")
	if err == nil {
		t.Error("expected error from custom dialer")
	}
	if !customDialerCalled {
		t.Error("custom dialer was not called")
	}
}

func TestLocalClient_DefaultDialer(t *testing.T) {
	lc := &LocalClient{}

	// Test with invalid address
	_, err := lc.defaultDialer(context.Background(), "tcp", "invalid:80")
	if err == nil {
		t.Error("defaultDialer should reject invalid address")
	}
	if !strings.Contains(err.Error(), "unexpected URL address") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestAccessDeniedError(t *testing.T) {
	baseErr := errors.New("permission denied")
	err := &AccessDeniedError{err: baseErr}

	// Test Error()
	if !strings.Contains(err.Error(), "Access denied") {
		t.Errorf("Error() = %q, want to contain 'Access denied'", err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != baseErr {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), baseErr)
	}

	// Test IsAccessDeniedError
	if !IsAccessDeniedError(err) {
		t.Error("IsAccessDeniedError should return true")
	}

	// Test with wrapped error
	wrappedErr := errors.New("outer error")
	if IsAccessDeniedError(wrappedErr) {
		t.Error("IsAccessDeniedError should return false for non-AccessDeniedError")
	}
}

func TestPreconditionsFailedError(t *testing.T) {
	baseErr := errors.New("precondition not met")
	err := &PreconditionsFailedError{err: baseErr}

	// Test Error()
	if !strings.Contains(err.Error(), "Preconditions failed") {
		t.Errorf("Error() = %q, want to contain 'Preconditions failed'", err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != baseErr {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), baseErr)
	}

	// Test IsPreconditionsFailedError
	if !IsPreconditionsFailedError(err) {
		t.Error("IsPreconditionsFailedError should return true")
	}
}

func TestLocalClient_DoLocalRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that Tailscale-Cap header is set
		if r.Header.Get("Tailscale-Cap") == "" {
			t.Error("Tailscale-Cap header not set")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	lc := &LocalClient{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
		OmitAuth: true,
	}

	req, err := http.NewRequest("GET", "http://local-tailscaled.sock/test", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	resp, err := lc.DoLocalRequest(req)
	if err != nil {
		t.Fatalf("DoLocalRequest failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestLocalClient_DoLocalRequest_AccessDenied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "access denied"})
	}))
	defer server.Close()

	lc := &LocalClient{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
		OmitAuth: true,
	}

	req, _ := http.NewRequest("GET", "http://local-tailscaled.sock/test", nil)
	_, err := lc.doLocalRequestNiceError(req)

	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if !IsAccessDeniedError(err) {
		t.Errorf("expected AccessDeniedError, got: %T", err)
	}
}

func TestLocalClient_DoLocalRequest_PreconditionsFailed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
		json.NewEncoder(w).Encode(map[string]string{"error": "preconditions failed"})
	}))
	defer server.Close()

	lc := &LocalClient{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
		OmitAuth: true,
	}

	req, _ := http.NewRequest("GET", "http://local-tailscaled.sock/test", nil)
	_, err := lc.doLocalRequestNiceError(req)

	if err == nil {
		t.Fatal("expected error for 412 response")
	}
	if !IsPreconditionsFailedError(err) {
		t.Errorf("expected PreconditionsFailedError, got: %T", err)
	}
}

func TestLocalClient_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/test/path" {
			t.Errorf("Path = %s, want /test/path", r.URL.Path)
		}

		body, _ := io.ReadAll(r.Body)
		if string(body) != "test body" {
			t.Errorf("Body = %q, want %q", body, "test body")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))
	defer server.Close()

	lc := &LocalClient{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
		OmitAuth: true,
	}

	body := strings.NewReader("test body")
	resp, err := lc.send(context.Background(), "POST", "/test/path", http.StatusOK, body)
	if err != nil {
		t.Fatalf("send failed: %v", err)
	}

	if string(resp) != "response" {
		t.Errorf("response = %q, want %q", resp, "response")
	}
}

func TestLocalClient_Get200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	lc := &LocalClient{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
		OmitAuth: true,
	}

	resp, err := lc.get200(context.Background(), "/test")
	if err != nil {
		t.Fatalf("get200 failed: %v", err)
	}

	if string(resp) != "success" {
		t.Errorf("response = %q, want %q", resp, "success")
	}
}

func TestLocalClient_IncrementCounter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/localapi/v0/upload-client-metrics") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	lc := &LocalClient{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
		OmitAuth: true,
	}

	err := lc.IncrementCounter(context.Background(), "test_counter", 5)
	if err != nil {
		t.Errorf("IncrementCounter failed: %v", err)
	}
}

func TestLocalClient_Goroutines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("goroutine 1 [running]:\nmain.main()\n"))
	}))
	defer server.Close()

	lc := &LocalClient{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
		OmitAuth: true,
	}

	data, err := lc.Goroutines(context.Background())
	if err != nil {
		t.Fatalf("Goroutines failed: %v", err)
	}

	if !strings.Contains(string(data), "goroutine") {
		t.Error("response doesn't contain goroutine info")
	}
}

func TestLocalClient_Metrics(t *testing.T) {
	tests := []struct {
		name   string
		method func(*LocalClient, context.Context) ([]byte, error)
		path   string
	}{
		{
			name:   "DaemonMetrics",
			method: (*LocalClient).DaemonMetrics,
			path:   "/localapi/v0/metrics",
		},
		{
			name:   "UserMetrics",
			method: (*LocalClient).UserMetrics,
			path:   "/localapi/v0/usermetrics",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.path {
					t.Errorf("Path = %s, want %s", r.URL.Path, tt.path)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("# HELP metric_name Help text\n"))
			}))
			defer server.Close()

			lc := &LocalClient{
				Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
				},
				OmitAuth: true,
			}

			data, err := tt.method(lc, context.Background())
			if err != nil {
				t.Fatalf("%s failed: %v", tt.name, err)
			}

			if !strings.Contains(string(data), "HELP") {
				t.Error("response doesn't contain metrics format")
			}
		})
	}
}

func TestLocalClient_ContextCancellation(t *testing.T) {
	// Server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	lc := &LocalClient{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
		OmitAuth: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := lc.get200(ctx, "/test")
	if err == nil {
		t.Error("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "context") {
		t.Errorf("expected context error, got: %v", err)
	}
}

func TestLocalClient_UseSocketOnly(t *testing.T) {
	lc := &LocalClient{
		Socket:        "/tmp/test.sock",
		UseSocketOnly: true,
	}

	// With UseSocketOnly, it should not try TCP port lookup
	_, err := lc.defaultDialer(context.Background(), "tcp", "local-tailscaled.sock:80")
	// We expect an error since /tmp/test.sock doesn't exist
	if err == nil {
		t.Error("expected error when socket doesn't exist")
	}
}

func TestLocalClient_OmitAuth(t *testing.T) {
	authHeaderSet := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			authHeaderSet = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	lc := &LocalClient{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
		OmitAuth: true,
	}

	req, _ := http.NewRequest("GET", "http://local-tailscaled.sock/test", nil)
	_, err := lc.DoLocalRequest(req)
	if err != nil {
		t.Fatalf("DoLocalRequest failed: %v", err)
	}

	if authHeaderSet {
		t.Error("Authorization header should not be set when OmitAuth=true")
	}
}

// Test the error message extraction
func TestErrorMessageFromBody(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{
			name: "json_error",
			body: []byte(`{"error":"test error message"}`),
			want: "test error message",
		},
		{
			name: "plain_text",
			body: []byte("plain error"),
			want: "plain error",
		},
		{
			name: "empty",
			body: []byte{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errorMessageFromBody(tt.body)
			if got != tt.want {
				t.Errorf("errorMessageFromBody() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Benchmark key operations
func BenchmarkLocalClient_Send(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	lc := &LocalClient{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
		OmitAuth: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := lc.get200(context.Background(), "/test")
		if err != nil {
			b.Fatalf("get200 failed: %v", err)
		}
	}
}
