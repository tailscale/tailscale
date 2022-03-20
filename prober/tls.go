// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// TLS returns a Probe that healthchecks a TLS endpoint.
//
// The ProbeFunc connects to hostname, does a TLS handshake, verifies
// that the hostname matches the presented certificate, and that the
// certificate expires in more than 7 days from the probe time.
func TLS(hostname string) ProbeFunc {
	return func(ctx context.Context) error {
		return probeTLS(ctx, hostname)
	}
}

func probeTLS(ctx context.Context, hostname string) error {
	var d net.Dialer
	conn, err := tls.DialWithDialer(&d, "tcp", hostname+":443", nil)
	if err != nil {
		return fmt.Errorf("connecting to %q: %w", hostname, err)
	}
	if err := conn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake error with %q: %w", hostname, err)
	}
	if err := conn.VerifyHostname(hostname); err != nil {
		return fmt.Errorf("Host %q TLS verification failed: %w", hostname, err)
	}

	latestAllowedExpiration := time.Now().Add(7 * 24 * time.Hour) // 7 days from now
	if expires := conn.ConnectionState().PeerCertificates[0].NotAfter; latestAllowedExpiration.After(expires) {
		left := expires.Sub(time.Now())
		return fmt.Errorf("TLS certificate for %q expires in %v", hostname, left)
	}

	return nil
}
