// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package controlclient

import (
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/syspolicy/policyclient"
)

// signRegisterRequest on non-supported platforms always returns errNoCertStore.
func signRegisterRequest(polc policyclient.Client, req *tailcfg.RegisterRequest, serverURL string, serverPubKey, machinePubKey key.MachinePublic) error {
	return errNoCertStore
}
