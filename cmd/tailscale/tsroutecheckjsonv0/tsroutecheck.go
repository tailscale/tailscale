// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_routecheck

// Package tsroutecheckjsonv0 provides types for unmarshalling the JSON output of the
// "tailscale routecheck --json" command:
//
//   - [ReportResponse] will unmarshal the output of "tailscale routecheck --json"
//
// # WARNING: unstable
//
// Format is "v0" and is subject to change.
// There is no guarantee of backwards or forwards compatibility.
package tsroutecheckjsonv0

import (
	"time"

	"tailscale.com/net/routecheck"
)

// ReportResponse is the JSON form of [routecheck.Report].
// Experimental: This output is not yet stable: tailscale/tailscale#17366.
type ReportResponse struct {
	Done   time.Time                   `json:"done"`
	Routes routecheck.RoutablePrefixes `json:"routes"`
}
