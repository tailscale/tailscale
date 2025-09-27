// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_tailnetlock

package tka

import (
	"errors"

	"tailscale.com/types/tkatype"
)

// signatureVerify returns a nil error if the signature is valid over the
// provided AUM BLAKE2s digest, using the given key.
func signatureVerify(s *tkatype.Signature, aumDigest tkatype.AUMSigHash, key Key) error {
	return errors.New("tailnetlock disabled in build")
}
