// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package httpio

import (
	"context"
	"strings"
)

// Endpoint annotates an HTTP method and path with input and output types.
//
// The intent is to declare this in a shared package between client and server
// implementations as a means to structurally describe how they interact.
//
// Example usage:
//
//	package tsapi
//
//	const BaseURL = "https://api.tailscale.com/api/v2/"
//
//	var (
//		GetDevice    = httpio.Endpoint[GetDeviceRequest, GetDeviceResponse]{Method: "GET", Pattern: "/device/{DeviceID}"}.WithHost(BaseURL)
//		DeleteDevice = httpio.Endpoint[DeleteDeviceRequest, DeleteDeviceResponse]{Method: "DELETE", Pattern: "/device/{DeviceID}"}.WithHost(BaseURL)
//	)
//
//	type GetDeviceRequest struct {
//		ID     int      `urlpath:"DeviceID"`
//		Fields []string `urlquery:"fields"`
//		...
//	}
//	type GetDeviceResponse struct {
//		ID        int          `json:"id"`
//		Addresses []netip.Addr `json:"addresses"`
//		...
//	}
//	type DeleteDeviceRequest struct { ... }
//	type DeleteDeviceResponse struct { ... }
//
// Example usage by client code:
//
//	ctx = httpio.WithAuth(ctx, ...)
//	device, err := tsapi.GetDevice.Do(ctx, {ID: 1234})
//
// Example usage by server code:
//
//	mux := http.NewServeMux()
//	mux.Handle(tsapi.GetDevice.String(), checkAuth(httpio.Handler(getDevice)))
//	mux.Handle(tsapi.DeleteDevice.String(), checkAuth(httpio.Handler(deleteDevice)))
//
//	func checkAuth(http.Handler) http.Handler { ... }
//	func getDevice(ctx context.Context, in GetDeviceRequest) (out GetDeviceResponse, err error) { ... }
//	func deleteDevice(ctx context.Context, in DeleteDeviceRequest) (out DeleteDeviceResponse, err error) { ... }
type Endpoint[In Request, Out Response] struct {
	// Method is a valid HTTP method (e.g., "GET").
	Method string
	// Pattern must be a pattern that complies with [mux.ServeMux.Handle] and
	// not be preceded by a method or host (e.g., "/api/v2/device/{DeviceID}").
	// It must start with a leading "/".
	Pattern string
}

// String returns a combination of the method and pattern,
// which is a valid pattern for [mux.ServeMux.Handle].
func (e Endpoint[In, Out]) String() string { return e.Method + " " + e.Pattern }

// Do performs an HTTP call to the target endpoint at the specified host.
// The hostPrefix must be a URL prefix containing the scheme and host,
// but not contain any URL query parameters (e.g., "https://api.tailscale.com/api/v2/").
func (e Endpoint[In, Out]) Do(ctx context.Context, hostPrefix string, in In, opts ...Option) (out Out, err error) {
	return Do[In, Out](ctx, e.Method, strings.TrimRight(hostPrefix, "/")+e.Pattern, in, opts...)
}

// TODO: Should hostPrefix be a *url.URL?

// WithHost constructs a [HostedEndpoint],
// which is an HTTP endpoint hosted at a particular URL prefix.
func (e Endpoint[In, Out]) WithHost(hostPrefix string) HostedEndpoint[In, Out] {
	return HostedEndpoint[In, Out]{Prefix: hostPrefix, Endpoint: e}
}

// HostedEndpoint is an HTTP endpoint hosted under a particular URL prefix.
type HostedEndpoint[In Request, Out Response] struct {
	// Prefix is a URL prefix containing the scheme, host, and
	// an optional path prefix (e.g., "https://api.tailscale.com/api/v2/").
	Prefix string
	Endpoint[In, Out]
}

// Do performs an HTTP call to the target hosted endpoint.
func (e HostedEndpoint[In, Out]) Do(ctx context.Context, in In, opts ...Option) (out Out, err error) {
	return Do[In, Out](ctx, e.Method, strings.TrimSuffix(e.Prefix, "/")+e.Pattern, in, opts...)
}
