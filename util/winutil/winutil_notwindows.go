// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package winutil

import (
	"errors"
	"fmt"
	"os/user"
	"runtime"
)

const regBase = ``
const regPolicyBase = ``

var ErrNoValue = errors.New("no value because registry is unavailable on this OS")

func getPolicyString(name string) (string, error) { return "", ErrNoValue }

func getPolicyInteger(name string) (uint64, error) { return 0, ErrNoValue }

func getPolicyStringArray(name string) ([]string, error) { return nil, ErrNoValue }

func getRegString(name string) (string, error) { return "", ErrNoValue }

func getRegInteger(name string) (uint64, error) { return 0, ErrNoValue }

func isSIDValidPrincipal(uid string) bool { return false }

func lookupPseudoUser(uid string) (*user.User, error) {
	return nil, fmt.Errorf("unimplemented on %v", runtime.GOOS)
}

func IsCurrentProcessElevated() bool { return false }

func registerForRestart(opts RegisterForRestartOpts) error { return nil }
