// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows || wasm || plan9 || tamago

package cli

import (
	"errors"
	"os"
)

// Stats a path and returns the owning uid and gid. Errors on non-unix platforms.
func fileStat(_f *os.File) (int, int, error) {
	return -1, -1, errors.New("Not implemented")
}
