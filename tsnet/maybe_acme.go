// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !ts_omit_acme

package tsnet

// Link in the ACME/TLS-cert feature so [Server.CertDomains],
// [Server.ListenTLS], and related cert-fetch paths work out of the box.
// Build with the ts_omit_acme tag to omit it.

import (
	"crypto/tls"

	_ "tailscale.com/feature/acme"
)

// getCert is the GetCertificate function used by ListenTLS and ListenFunnel.
func (s *Server) getCert(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	lc, err := s.LocalClient()
	if err != nil {
		return nil, err
	}
	return lc.GetCertificate(hi)
}
