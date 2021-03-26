// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	"tailscale.com/types/wgkey"
)

var (
	errNoCertStore              = errors.New("no certificate store")
	errCertificateNotConfigured = errors.New("no certificate subject configured")
)

// HashRegisterRequest generates the hash required sign or verify a
// tailcfg.RegisterRequest with tailcfg.SignatureV1.
func HashRegisterRequest(ts time.Time, serverURL string, deviceCert []byte, serverPubKey, machinePubKey wgkey.Key) []byte {
	h := crypto.SHA256.New()

	// hash.Hash.Write never returns an error, so we don't check for one here.
	fmt.Fprintf(h, "%s%s%s%s%s",
		ts.UTC().Format(time.RFC3339), serverURL, deviceCert, serverPubKey, machinePubKey)

	return h.Sum(nil)
}
