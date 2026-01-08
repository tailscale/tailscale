// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestOmitQRCodes(t *testing.T) {
	const msg = "unexpected with ts_omit_qrcodes"
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_qrcodes",
		BadDeps: map[string]string{
			"github.com/skip2/go-qrcode": msg,
		},
	}.Check(t)
}
