// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsweb

import (
	"context"
	"net/http"
	"time"

	"tailscale.com/util/ctxkey"
	"tailscale.com/util/rands"
)

// RequestID is an opaque identifier for a HTTP request, used to correlate
// user-visible errors with backend server logs. The RequestID is typically
// threaded through an HTTP Middleware (WithRequestID) and then can be extracted
// by HTTP Handlers to include in their logs.
//
// RequestID is an opaque identifier for a HTTP request, used to correlate
// user-visible errors with backend server logs. If present in the context, the
// RequestID will be printed alongside the message text and logged in the
// AccessLogRecord.
//
// A RequestID has the format "REQ-1{ID}", and the ID should be treated as an
// opaque string. The current implementation uses a UUID.
type RequestID string

// String returns the string format of the request ID, for use in e.g. setting
// a [http.Header].
func (r RequestID) String() string {
	return string(r)
}

// RequestIDKey stores and loads [RequestID] values within a [context.Context].
var RequestIDKey ctxkey.Key[RequestID]

// RequestIDHeader is a custom HTTP header that the WithRequestID middleware
// uses to determine whether to re-use a given request ID from the client
// or generate a new one.
const RequestIDHeader = "X-Tailscale-Request-Id"

// GenerateRequestID generates a new request ID with the current format.
func GenerateRequestID() RequestID {
	// Return a string of the form "REQ-<VersionByte><...>"
	// Previously we returned "REQ-1<UUIDString>".
	// Now we return "REQ-2" version, where the "2" doubles as the year 2YYY
	// in a leading date.
	now := time.Now().UTC()
	return RequestID("REQ-" + now.Format("20060102150405") + rands.HexString(16))
}

// SetRequestID is an HTTP middleware that injects a RequestID in the
// *http.Request Context. The value of that request id is either retrieved from
// the RequestIDHeader or a randomly generated one if not exists. Inner
// handlers can retrieve this ID from the RequestIDFromContext function.
func SetRequestID(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rid RequestID
		if id := r.Header.Get(RequestIDHeader); id != "" {
			rid = RequestID(id)
		} else {
			rid = GenerateRequestID()
		}
		ctx := RequestIDKey.WithValue(r.Context(), rid)
		r = r.WithContext(ctx)
		h.ServeHTTP(w, r)
	})
}

// RequestIDFromContext retrieves the RequestID from context that can be set by
// the SetRequestID function.
//
// Deprecated: Use [RequestIDKey.Value] instead.
func RequestIDFromContext(ctx context.Context) RequestID {
	return RequestIDKey.Value(ctx)
}
