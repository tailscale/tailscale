// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !js

package ipnlocal

import (
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func init() {
	addH2C = func(s *http.Server) {
		h2s := &http2.Server{}
		s.Handler = h2c.NewHandler(s.Handler, h2s)
	}
}
