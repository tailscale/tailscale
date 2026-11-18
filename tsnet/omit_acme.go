// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js || ts_omit_acme

package tsnet

import (
	"crypto/tls"

	"tailscale.com/feature"
)

func (s *Server) getCert(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, feature.ErrUnavailable
}
