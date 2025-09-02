// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestOmitSSH(t *testing.T) {
	const msg = "unexpected with ts_omit_ssh"
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_ssh",
		BadDeps: map[string]string{
			"tailscale.com/ssh/tailssh":            msg,
			"tailscale.com/sessionrecording":       msg,
			"github.com/anmitsu/go-shlex":          msg,
			"github.com/creack/pty":                msg,
			"github.com/kr/fs":                     msg,
			"github.com/pkg/sftp":                  msg,
			"github.com/u-root/u-root/pkg/termios": msg,
			"tempfork/gliderlabs/ssh":              msg,
		},
	}.Check(t)
}

func TestOmitSyspolicy(t *testing.T) {
	const msg = "unexpected syspolicy usage with ts_omit_syspolicy"
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_syspolicy,ts_include_cli",
		BadDeps: map[string]string{
			"tailscale.com/util/syspolicy":         msg,
			"tailscale.com/util/syspolicy/setting": msg,
			"tailscale.com/util/syspolicy/rsop":    msg,
		},
	}.Check(t)
}
