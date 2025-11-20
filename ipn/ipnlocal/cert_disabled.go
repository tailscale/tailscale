// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build js || ts_omit_acme

package ipnlocal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

func init() {
	RegisterC2N("GET /tls-cert-status", handleC2NTLSCertStatusDisabled)
}

var errNoCerts = errors.New("cert support not compiled in this build")

type TLSCertKeyPair struct {
	CertPEM, KeyPEM []byte
}

func (b *LocalBackend) GetCertPEM(ctx context.Context, domain string) (*TLSCertKeyPair, error) {
	return nil, errNoCerts
}

var errCertExpired = errors.New("cert expired")

type certStore interface{}

func getCertPEMCached(cs certStore, domain string, now time.Time) (p *TLSCertKeyPair, err error) {
	return nil, errNoCerts
}

func (b *LocalBackend) getCertStore() (certStore, error) {
	return nil, errNoCerts
}

func handleC2NTLSCertStatusDisabled(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"Missing":true}`) // a minimal tailcfg.C2NTLSCertInfo
}
