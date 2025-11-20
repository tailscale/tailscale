// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !windows

package tpm

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
)

func open() (transport.TPMCloser, error) {
	return nil, errors.New("TPM not supported on this platform")
}
