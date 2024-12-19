// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Enabling H2C for LocalAPI is not Windows-specific.
// However, Windows is expected to benefit the most
// due to additional, potentially slow authentication steps
// performed for each new named pipe connection.
// As an experiment, we are enabling it on Windows first.
//go:build windows

package tailscale

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

func init() {
	h2cTransport = func(dialer DialFunc) http.RoundTripper {
		return &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return dialer(ctx, network, addr)
			},
		}
	}
}
