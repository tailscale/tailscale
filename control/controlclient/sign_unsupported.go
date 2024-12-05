// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package controlclient

import (
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// signRegisterRequest on non-supported platforms always returns errNoCertStore.
func signRegisterRequest(req *tailcfg.RegisterRequest, serverURL string, serverPubKey, machinePubKey key.MachinePublic) error {
	return errNoCertStore
}
