// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package main

import (
	"os"
	"os/exec"
)

func doExec(cmd string, args []string, environ []string) error {
	c := exec.Command(cmd, args...)
	c.Env = environ
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	return c.Run()
}
