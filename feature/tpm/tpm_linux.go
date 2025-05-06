// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tpm

import (
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"tailscale.com/tailcfg"
)

func info() *tailcfg.TPMInfo {
	t, err := linuxtpm.Open("/dev/tpm0")
	if err != nil {
		return nil
	}
	defer t.Close()
	return infoFromCapabilities(t)
}
