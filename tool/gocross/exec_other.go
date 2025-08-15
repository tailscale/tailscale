// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package main

import (
	"os"
	"os/exec"
)

func doExec(cmd string, args []string, env []string) error {
	c := exec.Command(cmd, args[1:]...)
	c.Env = env
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
