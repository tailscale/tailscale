// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(cgo && darwin && !ios)

package hostinfo

import "os"

func GetHostname() string {
	h, _ := os.Hostname()
	return h
}
