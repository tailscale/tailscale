// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tpm

package ipnlocal

import (
	"errors"

	"tailscale.com/feature"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/persist"
)

func init() {
	feature.HookGenerateAttestationKeyIfEmpty.Set(generateAttestationKeyIfEmpty)
}

// generateAttestationKeyIfEmpty generates a new hardware attestation key if
// none exists. It returns true if a new key was generated and stored in
// p.AttestationKey.
func generateAttestationKeyIfEmpty(p *persist.Persist, logf logger.Logf) (bool, error) {
	// attempt to generate a new hardware attestation key if none exists
	var ak key.HardwareAttestationKey
	if p != nil {
		ak = p.AttestationKey
	}

	if ak == nil || ak.IsZero() {
		var err error
		ak, err = key.NewHardwareAttestationKey()
		if err != nil {
			if !errors.Is(err, key.ErrUnsupported) {
				logf("failed to create hardware attestation key: %v", err)
			}
		} else if ak != nil {
			logf("using new hardware attestation key: %v", ak.Public())
			if p == nil {
				p = &persist.Persist{}
			}
			p.AttestationKey = ak
			return true, nil
		}
	}
	return false, nil
}
