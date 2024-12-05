// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var (
	errNoCertStore                 = errors.New("no certificate store")
	errCertificateNotConfigured    = errors.New("no certificate subject configured")
	errUnsupportedSignatureVersion = errors.New("unsupported signature version")
)

// HashRegisterRequest generates the hash required sign or verify a
// tailcfg.RegisterRequest.
func HashRegisterRequest(
	version tailcfg.SignatureType, ts time.Time, serverURL string, deviceCert []byte,
	serverPubKey, machinePubKey key.MachinePublic) ([]byte, error) {
	h := crypto.SHA256.New()

	// hash.Hash.Write never returns an error, so we don't check for one here.
	switch version {
	case tailcfg.SignatureV1:
		fmt.Fprintf(h, "%s%s%s%s%s",
			ts.UTC().Format(time.RFC3339), serverURL, deviceCert, serverPubKey.ShortString(), machinePubKey.ShortString())
	case tailcfg.SignatureV2:
		fmt.Fprintf(h, "%s%s%s%s%s",
			ts.UTC().Format(time.RFC3339), serverURL, deviceCert, serverPubKey, machinePubKey)
	default:
		return nil, errUnsupportedSignatureVersion
	}

	return h.Sum(nil), nil
}
