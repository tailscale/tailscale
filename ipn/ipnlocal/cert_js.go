// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
)

type TLSCertKeyPair struct {
	CertPEM, KeyPEM []byte
}

func (b *LocalBackend) GetCertPEM(ctx context.Context, domain string) (*TLSCertKeyPair, error) {
	return nil, errors.New("not implemented for js/wasm")
}
