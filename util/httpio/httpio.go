// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package httpio assists in handling HTTP operations on structured
// input and output types. It automatically handles encoding of data
// in the URL path, URL query parameters, and the HTTP body.
package httpio

import (
	"context"
	"net/http"

	"tailscale.com/util/httpm"
)

// Request is a structured Go type that contains fields representing arguments
// in the URL path, URL query parameters, and optionally the HTTP request body.
//
// Typically, this is a Go struct:
//
//   - with fields tagged as `urlpath` to represent arguments in the URL path
//     (e.g., "/tailnet/{tailnetId}/devices/{deviceId}").
//     See [tailscale.com/util/httpio/urlpath] for details.
//
//   - with fields tagged as `urlquery` to represent URL query parameters
//     (e.g., "?after=18635&limit=5").
//     See [tailscale.com/util/httpio/urlquery] for details.
//
//   - with possibly other fields used to serialize as the HTTP body.
//     By default, [encoding/json] is used to marshal the entire struct value.
//     To prevent fields specific to `urlpath` or `urlquery` from being marshaled
//     as part of the body, explicitly ignore those fields with `json:"-"`.
//     An HTTP body is only populated if there are any exported fields
//     without the `urlpath` or `urlquery` struct tags.
//
// Since GET and DELETE methods usually have no associated body,
// requests for such methods often only have `urlpath` and `urlquery` fields.
//
// Example GET request type:
//
//	type GetDevicesRequest struct {
//		TailnetID tailcfg.TailnetID `urlpath:"tailnetId"`
//
//		Limit uint             `urlquery:"limit"`
//		After tailcfg.DeviceID `urlquery:"after"`
//	}
//
// Example PUT request type:
//
//	type PutDeviceRequest struct {
//		TailnetID tailcfg.TailnetID `urlpath:"tailnetId" json:"-"`
//		DeviceID  tailcfg.DeviceID  `urlpath:"deviceId" json:"-"`
//
//		Hostname string       `json:"hostname,omitempty"``
//		IPv4     netip.IPAddr `json:"ipv4,omitzero"``
//	}
//
// By convention, request struct types are named "{Method}{Resource}Request",
// where {Method} is the HTTP method (e.g., "Post, "Get", "Put", "Delete", etc.)
// and {Resource} is some resource acted upon (e.g., "Device", "Routes", etc.).
type Request = any

// Response is a structured Go type to represent the HTTP response body.
//
// By default, [encoding/json] is used to unmarshal the response value.
// Unlike [Request], there is no support for `urlpath` and `urlquery` struct tags.
//
// Example response type:
//
//	type GetDevicesResponses struct {
//		Devices []Device       `json:"devices"`
//		Error   ErrorResponse  `json:"error"`
//	}
//
// By convention, response struct types are named "{Method}{Resource}Response",
// where {Method} is the HTTP method (e.g., "Post, "Get", "Put", "Delete", etc.)
// and {Resource} is some resource acted upon (e.g., "Device", "Routes", etc.).
type Response = any

// Handler wraps a caller-provided handle function that operates on
// concrete input and output types and returns a [http.Handler] function.
func Handler[In Request, Out Response](handle func(ctx context.Context, in In) (out Out, err error), opts ...Option) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: How do we respond to the user if err is non-nil?
		// Do we default to status 500?
		panic("not implemented")
	})
}

// TODO: Should url be a *url.URL? In the usage below, the caller should not pass query parameters.

// Post performs a POST call to the provided url with the given input
// and returns the response output.
func Post[In Request, Out Response](ctx context.Context, url string, in In, opts ...Option) (Out, error) {
	return Do[In, Out](ctx, httpm.POST, url, in, opts...)
}

// Get performs a GET call to the provided url with the given input
// and returns the response output.
func Get[In Request, Out Response](ctx context.Context, url string, in In, opts ...Option) (Out, error) {
	return Do[In, Out](ctx, httpm.GET, url, in, opts...)
}

// Put performs a PUT call to the provided url with the given input
// and returns the response output.
func Put[In Request, Out Response](ctx context.Context, url string, in In, opts ...Option) (Out, error) {
	return Do[In, Out](ctx, httpm.PUT, url, in, opts...)
}

// Delete performs a DELETE call to the provided url with the given input
// and returns the response output.
func Delete[In Request, Out Response](ctx context.Context, url string, in In, opts ...Option) (Out, error) {
	return Do[In, Out](ctx, httpm.DELETE, url, in, opts...)
}

// Do performs an HTTP method call to the provided url with the given input
// and returns the response output.
func Do[In Request, Out Response](ctx context.Context, method, url string, in In, opts ...Option) (out Out, err error) {
	// TOOD: If the server returned a non-2xx code, we should report a Go error.
	panic("not implemented")
}
