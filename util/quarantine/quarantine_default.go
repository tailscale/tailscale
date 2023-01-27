// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin && !windows

package quarantine

import (
	"os"
)

func setQuarantineAttr(f *os.File) error {
	return nil
}
