// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !windows

package cli

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func findSSH() (string, error) {
	return exec.LookPath("ssh")
}

func execSSH(ssh string, argv []string) error {
	if err := syscall.Exec(ssh, argv, os.Environ()); err != nil {
		return err
	}
	return errors.New("unreachable")
}
