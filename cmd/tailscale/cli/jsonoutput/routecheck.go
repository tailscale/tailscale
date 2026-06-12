// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_routecheck

package jsonoutput

import (
	"time"

	"tailscale.com/net/routecheck"
)

// RouteCheckReport is the JSON form of [routecheck.Report].
// Experimental: This output is not yet stable: tailscale/tailscale#17366.
type RouteCheckReport struct {
	Done   time.Time                   `json:"done"`
	Routes routecheck.RoutablePrefixes `json:"routes"`
}
