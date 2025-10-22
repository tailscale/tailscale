// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_netlog || ts_omit_logtail

package netlog

type Logger struct{}

func (*Logger) Startup(...any) error   { return nil }
func (*Logger) Running() bool          { return false }
func (*Logger) Shutdown(any) error     { return nil }
func (*Logger) ReconfigNetworkMap(any) {}
func (*Logger) ReconfigRoutes(any)     {}
