// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package authretry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
	tsclient "tailscale.com/client/tailscale"
)

func TestIsRetriable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil-error", nil, false},
		{"non-retriable-error", errors.New("something went wrong"), false},
		{"deadline-exceeded", context.DeadlineExceeded, true},
		{"wrapped-deadline-exceeded", fmt.Errorf("request failed: %w", context.DeadlineExceeded), true},
		{"err-response-500", tsclient.ErrResponse{Status: 500, Message: "internal server error"}, true},
		{"err-response-502", tsclient.ErrResponse{Status: 502, Message: "bad gateway"}, true},
		{"err-response-503", tsclient.ErrResponse{Status: 503, Message: "service unavailable"}, true},
		{"err-response-504", tsclient.ErrResponse{Status: 504, Message: "gateway timeout"}, true},
		{"err-response-400", tsclient.ErrResponse{Status: 400, Message: "bad request"}, false},
		{"err-response-401", tsclient.ErrResponse{Status: 401, Message: "unauthorized"}, false},
		{"err-response-403", tsclient.ErrResponse{Status: 403, Message: "forbidden"}, false},
		{"err-response-404", tsclient.ErrResponse{Status: 404, Message: "not found"}, false},
		{"wrapped-err-response-400", fmt.Errorf("create key: %w", tsclient.ErrResponse{Status: 400}), false},
		{
			"oauth2-retrieve-error-503",
			&oauth2.RetrieveError{Response: &http.Response{StatusCode: 503}, Body: []byte("service unavailable")},
			true,
		},
		{
			"oauth2-retrieve-error-400",
			&oauth2.RetrieveError{Response: &http.Response{StatusCode: 400}, Body: []byte("bad request")},
			false,
		},
		{
			"wrapped-oauth2-retrieve-error-504",
			fmt.Errorf("token exchange: %w", &oauth2.RetrieveError{Response: &http.Response{StatusCode: 504}, Body: []byte("gateway timeout")}),
			true,
		},
		{
			"oauth2-retrieve-error-nil-response",
			&oauth2.RetrieveError{Response: nil, Body: []byte("no response")},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetriableError(tt.err); got != tt.want {
				t.Errorf("isRetriable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRetryOnTransient(t *testing.T) {
	t.Run("calls-once-on-retriable-error-when-retry-disabled", func(t *testing.T) {
		var calls atomic.Int32
		_, err := RetryOnTransientFailure(context.Background(), "test", false, func() (string, error) {
			calls.Add(1)
			return "", tsclient.ErrResponse{Status: 503, Message: "unavailable"}
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if got := calls.Load(); got != 1 {
			t.Errorf("got %d calls, want 1", got)
		}
	})

	t.Run("success-case-retry-disabled", func(t *testing.T) {
		result, err := RetryOnTransientFailure(context.Background(), "test", false, func() (string, error) {
			return "key-123", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "key-123" {
			t.Errorf("got %q, want %q", result, "key-123")
		}
	})

	t.Run("retries-on-retriable-error", func(t *testing.T) {
		var calls atomic.Int32
		result, err := RetryOnTransientFailure(context.Background(), "test", true, func() (string, error) {
			n := calls.Add(1)
			if n < 3 {
				return "", tsclient.ErrResponse{Status: 503, Message: "unavailable"}
			}
			return "key-123", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "key-123" {
			t.Errorf("got %q, want %q", result, "key-123")
		}
		if got := calls.Load(); got != 3 {
			t.Errorf("got %d calls, want 3", got)
		}
	})

	t.Run("calls-once-on-non-retriable-error", func(t *testing.T) {
		var calls atomic.Int32
		_, err := RetryOnTransientFailure(context.Background(), "test", true, func() (string, error) {
			calls.Add(1)
			return "", tsclient.ErrResponse{Status: 400, Message: "bad request"}
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if got := calls.Load(); got != 1 {
			t.Errorf("got %d calls, want 1", got)
		}
	})

	t.Run("exhausts-retries", func(t *testing.T) {
		var calls atomic.Int32
		_, err := RetryOnTransientFailure(context.Background(), "test", true, func() (string, error) {
			calls.Add(1)
			return "", tsclient.ErrResponse{Status: 503, Message: "unavailable"}
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if got := calls.Load(); got != int32(MaxAttempts) {
			t.Errorf("got %d calls, want %d", got, MaxAttempts)
		}
	})

	t.Run("respects-context-cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var calls atomic.Int32
		_, err := RetryOnTransientFailure(ctx, "test", true, func() (string, error) {
			n := calls.Add(1)
			if n == 1 {
				cancel()
			}
			return "", tsclient.ErrResponse{Status: 503, Message: "unavailable"}
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if got := calls.Load(); got > 2 {
			t.Errorf("got %d calls, want at most 2", got)
		}
	})

	t.Run("success-on-first-try", func(t *testing.T) {
		var calls atomic.Int32
		result, err := RetryOnTransientFailure(context.Background(), "test", true, func() (string, error) {
			calls.Add(1)
			return "key-abc", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "key-abc" {
			t.Errorf("got %q, want %q", result, "key-abc")
		}
		if got := calls.Load(); got != 1 {
			t.Errorf("got %d calls, want 1", got)
		}
	})

	t.Run("retries-deadline-exceeded", func(t *testing.T) {
		var calls atomic.Int32
		result, err := RetryOnTransientFailure(context.Background(), "test", true, func() (string, error) {
			n := calls.Add(1)
			if n < 2 {
				return "", context.DeadlineExceeded
			}
			return "key-456", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "key-456" {
			t.Errorf("got %q, want %q", result, "key-456")
		}
		if got := calls.Load(); got != 2 {
			t.Errorf("got %d calls, want 2", got)
		}
	})

	t.Run("retry-after-respects-cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var calls atomic.Int32
		start := time.Now()
		go func() {
			time.Sleep(200 * time.Millisecond)
			cancel()
		}()
		_, err := RetryOnTransientFailure(ctx, "test", true, func() (string, error) {
			calls.Add(1)
			return "", &oauth2.RetrieveError{
				Response: &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{"Retry-After": []string{"10"}},
				},
				Body: []byte("rate limited"),
			}
		})
		if err == nil {
			t.Fatal("expected error")
		}
		elapsed := time.Since(start)
		if elapsed > 2*time.Second {
			t.Errorf("expected early exit on cancellation, took %v", elapsed)
		}
	})
}
