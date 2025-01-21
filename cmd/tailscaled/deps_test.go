// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "darwin",
		GOARCH: "arm64",
		BadDeps: map[string]string{
			"testing":                        "do not use testing package in production code",
			"gvisor.dev/gvisor/pkg/hostarch": "will crash on non-4K page sizes; see https://github.com/tailscale/tailscale/issues/8658",
		},
	}.Check(t)

	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "arm64",
		BadDeps: map[string]string{
			"testing":                                        "do not use testing package in production code",
			"gvisor.dev/gvisor/pkg/hostarch":                 "will crash on non-4K page sizes; see https://github.com/tailscale/tailscale/issues/8658",
			"google.golang.org/protobuf/proto":               "unexpected",
			"github.com/prometheus/client_golang/prometheus": "use tailscale.com/metrics in tailscaled",
		},
	}.Check(t)
}

func TestOmitSSH(t *testing.T) {
	const msg = "unexpected with ts_omit_ssh"
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_ssh",
		BadDeps: map[string]string{
			"tailscale.com/ssh/tailssh":            msg,
			"golang.org/x/crypto/ssh":              msg,
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
	const msg = "unexpected with ts_omit_syspolicy"
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_syspolicy",
		BadDeps: map[string]string{
			"tailscale.com/util/syspolicy":                  msg,
			"tailscale.com/util/syspolicy/internal":         msg,
			"tailscale.com/util/syspolicy/setting":          msg,
			"tailscale.com/util/syspolicy/rsop":             msg,
			"tailscale.com/util/syspolicy/internal/metrics": msg,
			"tailscale.com/util/syspolicy/internal/loggerx": msg,
			"tailscale.com/util/syspolicy/source":           msg,
			// Only /pkey and /policyclient are allowed.
		},
	}.Check(t)
}
