// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tpm

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

func open() (transport.TPMCloser, error) {
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err == nil {
		return tpm, nil
	}
	errs := []error{err}
	tpm, err = linuxtpm.Open("/dev/tpm0")
	if err == nil {
		return tpm, nil
	}
	return nil, errors.Join(errs...)
}
