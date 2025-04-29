// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tpm

import (
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
	"tailscale.com/tailcfg"
)

func info() *tailcfg.TPMInfo {
	t, err := windowstpm.Open()
	if err != nil {
		return nil
	}
	defer t.Close()
	return infoFromCapabilities(t)
}
