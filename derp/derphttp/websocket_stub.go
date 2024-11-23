// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(js || ((linux || darwin) && ts_debug_websockets))

package derphttp

const canWebsockets = false
