// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Enabling H2C for LocalAPI is not Windows-specific.
// However, Windows is expected to benefit the most
// due to additional, potentially slow authentication steps
// performed for each new named pipe connection.
// As an experiment, we are enabling it on Windows first.
//go:build windows

package ipnserver

import (
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func init() {
	addH2C = func(s *http.Server) {
		h2s := &http2.Server{}
		s.Handler = h2c.NewHandler(s.Handler, h2s)
		// [http2.ConfigureServer] sets up a server shutdown handler that gracefully
		// closes connections when [http.Server.Shutdown] is called.
		// Otherwise, it leaks goroutines.
		http2.ConfigureServer(s, h2s)
	}
}
