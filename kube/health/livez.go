// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package health

import (
	"net/http"

	"tailscale.com/types/logger"
)

// RegisterLivezHandlers registers a liveness probe at /livez, which fails so
// that Kubernetes restarts the container. Only register checks for states a
// restart fixes: a proxy that has lost its connection to control, or is
// waiting for the operator to issue a new auth key, is still live. Register
// every check on the returned Probe before serving mux, as a Probe with no
// checks passes.
func RegisterLivezHandlers(mux *http.ServeMux, logf logger.Logf) *Probe {
	p := &Probe{name: "livez", logf: logf}
	mux.Handle("GET /livez", p)
	return p
}
