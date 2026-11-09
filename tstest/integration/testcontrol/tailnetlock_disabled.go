// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !experiment.reco && ts_omit_tailnetlock

package testcontrol

import (
	"net/http"

	"tailscale.com/tailcfg"
)

type tkaState struct{}

func (s *Server) serveTKA(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Tailnet Lock support is not compiled in", http.StatusNotImplemented)
}

func (s *Server) tkaInfo() *tailcfg.TKAInfo { return nil }
