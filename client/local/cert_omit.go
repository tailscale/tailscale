// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && ts_omit_acme

package local

import (
	"crypto/tls"

	"tailscale.com/feature"
)

// GetCertificate returns an error because ACME is omitted from this build.
func (*Client) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, feature.ErrUnavailable
}
