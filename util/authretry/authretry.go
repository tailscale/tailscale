// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package authretry provides retry logic for transient errors encountered
// during auth key generation (OAuth token fetch, WIF token exchange).
package authretry

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	tsclient "tailscale.com/client/tailscale"
	"tailscale.com/util/backoff"
)

const MaxAttempts = 3

// RetryOnTransientFailure calls fn, retrying up to MaxAttempts times with
// exponential backoff when retryEnabled is true and the error is transient.
// When retryEnabled is false fn is called exactly once.
func RetryOnTransientFailure(ctx context.Context, name string, retryEnabled bool, fn func() (string, error)) (string, error) {
	attempts := 1
	if retryEnabled {
		attempts = MaxAttempts
	}
	var bo *backoff.Backoff
	if retryEnabled {
		bo = backoff.NewBackoff(name, log.Printf, 30*time.Second)
	}
	var lastErr error
	for i := range attempts {
		result, err := fn()
		if err == nil {
			return result, nil
		}
		lastErr = err
		if !retryEnabled || i == attempts-1 || !isRetriableError(err) {
			return "", err
		}
		log.Printf("%s: transient error (attempt %d/%d), retrying: %v", name, i+1, attempts, err)
		bo.BackOff(ctx, err)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
	return "", lastErr
}

// isRetriableError reports whether err is a transient error that may succeed on
// retry: e.g., any 5xx status (from either tsclient.ErrResponse or *oauth2.RetrieveError),
// or context.DeadlineExceeded.
//
// TODO(mpminardi): add-in handling for 429 if / when these are returned from the upstream
// endpoints that are hit in the auth exchange flows.
func isRetriableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errResp, ok := errors.AsType[tsclient.ErrResponse](err); ok {
		return errResp.Status >= http.StatusInternalServerError
	}
	if retrieveErr, ok := errors.AsType[*oauth2.RetrieveError](err); ok && retrieveErr.Response != nil {
		return retrieveErr.Response.StatusCode >= http.StatusInternalServerError
	}
	return false
}
