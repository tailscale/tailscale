// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import "golang.org/x/sys/unix"

func doExec(cmd string, args []string, environ []string) error {
	return unix.Exec(cmd, args, environ)
}
