// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_taildrop

package ipnlocal

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestOmitTaildropDeps(t *testing.T) {
	deptest.DepChecker{
		Tags:   "ts_omit_taildrop",
		GOOS:   "linux",
		GOARCH: "amd64",
		BadDeps: map[string]string{
			"tailscale.com/taildrop":         "should be omitted",
			"tailscale.com/feature/taildrop": "should be omitted",
		},
	}.Check(t)
}
