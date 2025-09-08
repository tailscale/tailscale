// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
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

// Test that we can build a binary without reflect.MethodByName.
// See https://github.com/tailscale/tailscale/issues/17063
func TestOmitReflectThings(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_include_cli,ts_omit_systray,ts_omit_debugeventbus,ts_omit_webclient",
		BadDeps: map[string]string{
			"text/template": "unexpected text/template usage",
			"html/template": "unexpected text/template usage",
		},
		OnDep: func(dep string) {
			if strings.Contains(dep, "systray") {
				t.Errorf("unexpected systray dep %q", dep)
			}
		},
	}.Check(t)
}

func TestOmitDrive(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_drive,ts_include_cli",
		OnDep: func(dep string) {
			if strings.Contains(dep, "driveimpl") {
				t.Errorf("unexpected dep with ts_omit_drive: %q", dep)
			}
			if strings.Contains(dep, "webdav") {
				t.Errorf("unexpected dep with ts_omit_drive: %q", dep)
			}
		},
	}.Check(t)
}
