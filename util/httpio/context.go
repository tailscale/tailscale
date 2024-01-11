// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package httpio

import (
	"context"
	"net/http"

	"tailscale.com/util/httphdr"
)

type headerKey struct{}

// WithHeader specifies the HTTP header to use with a client request.
// It only affects [Do], [Get], [Post], [Put], and [Delete].
//
// Example usage:
//
//	ctx = httpio.WithHeader(ctx, http.Header{"DD-API-KEY": ...})
func WithHeader(ctx context.Context, hdr http.Header) context.Context {
	return context.WithValue(ctx, headerKey{}, hdr)
}

type authKey struct{}

// WithAuth specifies an "Authorization" header to use with a client request.
// This takes precedence over any "Authorization" header that may be present
// in the [http.Header] provided to [WithHeader].
// It only affects [Do], [Get], [Post], [Put], and [Delete].
//
// Example usage:
//
//	ctx = httpio.WithAuth(ctx, httphdr.BasicAuth{
//		Username: "admin",
//		Password: "password",
//	})
func WithAuth(ctx context.Context, auth httphdr.AuthScheme) context.Context {
	return context.WithValue(ctx, authKey{}, auth)
}

// TODO: Add extraction functionality to retrieve the original
// *http.Request and http.ResponseWriter for use with [Handler].
