// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package acme

import (
	"net/http"
	"strconv"
	"time"

	"tailscale.com/tsweb"
)

// certRateLimitedError is returned when the upstream ACME CA rate-limited
// the issuance. It exists so cert-fetching failures can surface as HTTP
// 429 responses via [tsweb.HTTPStatuser].
type certRateLimitedError struct {
	retryAfter time.Duration
	underlying error
}

func (e certRateLimitedError) Error() string { return e.underlying.Error() }
func (e certRateLimitedError) Unwrap() error { return e.underlying }

// HTTPStatus implements [tsweb.HTTPStatuser].
func (e certRateLimitedError) HTTPStatus() tsweb.HTTPError {
	h := http.Header{}
	if e.retryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(int(e.retryAfter.Seconds())))
	}
	return tsweb.HTTPError{
		Code:   http.StatusTooManyRequests,
		Msg:    e.Error(),
		Header: h,
	}
}
