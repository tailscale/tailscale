// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19 && (linux || darwin || freebsd || openbsd) && !ts_omit_bird

package main

import (
	"tailscale.com/chirp"
	"tailscale.com/wgengine"
)

func init() {
	createBIRDClient = func(ctlSocket string) (wgengine.BIRDClient, error) {
		return chirp.New(ctlSocket)
	}
}
