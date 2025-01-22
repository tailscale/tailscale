// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(linux || windows || (darwin && !ios) || !js)

package derphttp

const canWebsockets = false
