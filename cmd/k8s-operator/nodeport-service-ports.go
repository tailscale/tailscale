// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"math/rand/v2"
)

const (
	tailscaledPortMax = 65535
	tailscaledPortMin = 1024
)

func getRandomPort() uint16 {
	return uint16(rand.IntN(tailscaledPortMax-tailscaledPortMin+1) + tailscaledPortMin)
}
