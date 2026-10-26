// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type delegateBackend struct {
	ipnLocalBackend
	request func(*http.Request) (*http.Response, error)
}

func (b *delegateBackend) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	return b.request(req)
}

func TestFetchSSHActionTimeout(t *testing.T) {
	for _, mode := range []string{"timeout", "retry-timeout", "parent-deadline", "parent-cancel"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				wantDeadline := start.Add(delegateFetchTimeout)
				wantElapsed := delegateFetchTimeout
				wantErr := context.DeadlineExceeded
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				switch mode {
				case "parent-deadline":
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, time.Minute)
					defer stop()
					wantElapsed = time.Minute
					wantDeadline = start.Add(wantElapsed)
				case "parent-cancel":
					time.AfterFunc(time.Minute, cancel)
					wantElapsed = time.Minute
					wantErr = context.Canceled
				}
				calls := 0
				b := &delegateBackend{request: func(req *http.Request) (*http.Response, error) {
					calls++
					if got, ok := req.Context().Deadline(); !ok || !got.Equal(wantDeadline) {
						t.Errorf("request deadline = %v, %v; want %v", got, ok, wantDeadline)
					}
					if mode == "retry-timeout" {
						return nil, errors.New("temporarily unavailable")
					}
					<-req.Context().Done()
					return nil, req.Context().Err()
				}}
				c := &conn{srv: &server{lb: b, logf: t.Logf}}
				if _, err := c.fetchSSHAction(ctx, "https://unused/action"); !errors.Is(err, wantErr) {
					t.Errorf("fetchSSHAction error = %v, want %v", err, wantErr)
				}
				if got := time.Since(start); got != wantElapsed {
					t.Errorf("fetch duration = %v, want %v", got, wantElapsed)
				}
				if calls == 0 || mode == "retry-timeout" && calls < 2 {
					t.Errorf("request calls = %d", calls)
				}
			})
		})
	}
}

func TestFetchSSHActionCancelsRequestOnSuccess(t *testing.T) {
	var requestContext context.Context
	b := &delegateBackend{request: func(req *http.Request) (*http.Response, error) {
		requestContext = req.Context()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"Accept":true}`)),
		}, nil
	}}
	c := &conn{srv: &server{lb: b, logf: t.Logf}}
	action, err := c.fetchSSHAction(context.Background(), "https://unused/action")
	if err != nil {
		t.Fatal(err)
	}
	if !action.Accept {
		t.Fatal("delegated action did not accept")
	}
	if err := requestContext.Err(); err != context.Canceled {
		t.Errorf("request context error = %v, want context.Canceled", err)
	}
}
