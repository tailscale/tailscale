// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"time"
)

type TLSCertKeyPair struct {
	CertPEM, KeyPEM []byte
}

func (b *LocalBackend) GetCertPEM(ctx context.Context, domain string) (*TLSCertKeyPair, error) {
	return nil, errors.New("not implemented for js/wasm")
}

var errCertExpired = errors.New("cert expired")

type certStore interface{}

func getCertPEMCached(cs certStore, domain string, now time.Time) (p *TLSCertKeyPair, err error) {
	return nil, errors.New("not implemented for js/wasm")
}

func (b *LocalBackend) getCertStore() (certStore, error) {
	return nil, errors.New("not implemented for js/wasm")
}
