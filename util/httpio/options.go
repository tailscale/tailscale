// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package httpio

import (
	"io"
	"net/http"
)

// Option is an option to alter the behavior of [httpio] functionality.
type Option interface{ option() }

// WithClient specifies the [http.Client] to use in client-initiated requests.
// It only affects [Do], [Get], [Post], [Put], and [Delete].
// It has no effect on [Handler].
func WithClient(c *http.Client) Option {
	panic("not implemented")
}

// WithMarshaler specifies an marshaler to use for a particular "Content-Type".
//
// For client-side requests (e.g., [Do], [Get], [Post], [Put], and [Delete]),
// the first specified encoder is used to specify the "Content-Type" and
// to marshal the HTTP request body.
//
// For server-side responses (e.g., [Handler]), the first match between
// the client-provided "Accept" header is used to select the encoder to use.
// If no match is found, the first specified encoder is used regardless.
//
// If no encoder is specified, by default the "application/json" content type
// is used with the [encoding/json] as the marshal implementation.
func WithMarshaler(contentType string, marshal func(io.Writer, any) error) Option {
	panic("not implemented")
}

// WithUnmarshaler specifies an unmarshaler to use for a particular "Content-Type".
//
// For both client-side responses and server-side requests,
// the provided "Content-Type" header is used to select which decoder to use.
// If no match is found, the first specified encoder is used regardless.
func WithUnmarshaler(contentType string, unmarshal func(io.Reader, any) error) Option {
	panic("not implemented")
}
