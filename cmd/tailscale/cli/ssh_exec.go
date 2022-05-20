// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !js && !windows
// +build !js,!windows

package cli

import (
	"errors"
	"os"
	"syscall"
)

func execSSH(ssh string, argv []string) error {
	if err := syscall.Exec(ssh, argv, os.Environ()); err != nil {
		return err
	}
	return errors.New("unreachable")
}
