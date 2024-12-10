// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin

package prober

import (
	"fmt"
	"net/netip"
	"runtime"
)

const tunName = "unused"

func configureTUN(addr netip.Prefix, tunname string) error {
	return fmt.Errorf("not implemented on " + runtime.GOOS)
}
