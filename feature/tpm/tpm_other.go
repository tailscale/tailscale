// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !windows

package tpm

import "tailscale.com/tailcfg"

func info() *tailcfg.TPMInfo {
	return nil
}
