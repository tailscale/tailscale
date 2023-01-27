// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package winutil

import (
	"fmt"
	"os/user"
	"runtime"
)

const regBase = ``

func getPolicyString(name, defval string) string { return defval }

func getPolicyInteger(name string, defval uint64) uint64 { return defval }

func getRegString(name, defval string) string { return defval }

func getRegInteger(name string, defval uint64) uint64 { return defval }

func isSIDValidPrincipal(uid string) bool { return false }

func lookupPseudoUser(uid string) (*user.User, error) {
	return nil, fmt.Errorf("unimplemented on %v", runtime.GOOS)
}

func IsCurrentProcessElevated() bool { return false }
