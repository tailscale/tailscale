// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
