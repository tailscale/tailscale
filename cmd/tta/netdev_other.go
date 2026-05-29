// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package main

import "net/http"

func handleNetdevFeatures(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "netdev-features not supported on this platform", http.StatusNotImplemented)
}
