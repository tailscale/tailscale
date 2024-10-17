// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package iosdeps

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "ios",
		GOARCH: "arm64",
		BadDeps: map[string]string{
			"testing":                             "do not use testing package in production code",
			"text/template":                       "linker bloat (MethodByName)",
			"html/template":                       "linker bloat (MethodByName)",
			"tailscale.com/net/wsconn":            "https://github.com/tailscale/tailscale/issues/13762",
			"github.com/coder/websocket":          "https://github.com/tailscale/tailscale/issues/13762",
			"github.com/mitchellh/go-ps":          "https://github.com/tailscale/tailscale/pull/13759",
			"database/sql/driver":                 "iOS doesn't use an SQL database",
			"github.com/google/uuid":              "see tailscale/tailscale#13760",
			"tailscale.com/clientupdate/distsign": "downloads via AppStore, not distsign",
			"github.com/tailscale/hujson":         "no config file support on iOS",
		},
	}.Check(t)
}
