// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows !cgo

package controlclient

import (
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

// signRegisterRequest on non-supported platforms always returns errNoCertStore.
func signRegisterRequest(req *tailcfg.RegisterRequest, serverURL string, serverPubKey, machinePubKey wgkey.Key) error {
	return errNoCertStore
}
