// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package integration

import (
	"errors"
	"os"
)

func tryLinkat(_ *os.File, _ string) error {
	return errors.New("linkat with AT_EMPTY_PATH not supported on this OS")
}
