// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package health

import (
	"net/http"

	"tailscale.com/types/logger"
)

// RegisterReadyzHandlers registers a readiness probe at /readyz, so each part
// of the proxy can keep the Pod out of its Service's endpoints until it can
// carry traffic. Register every check on the returned Probe before serving
// mux, as a Probe with no checks passes.
func RegisterReadyzHandlers(mux *http.ServeMux, logf logger.Logf) *Probe {
	p := &Probe{name: "readyz", logf: logf}
	mux.Handle("GET /readyz", p)
	return p
}
