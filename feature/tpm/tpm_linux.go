// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tpm

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

func open() (transport.TPMCloser, error) {
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err == nil {
		return tpm, nil
	}
	return linuxtpm.Open("/dev/tpm0")
}
