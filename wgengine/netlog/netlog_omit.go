// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_netlog || ts_omit_logtail

package netlog

type Logger struct{}

// NodeSource is a stub kept so the omit build does not break consumers that
// reference the type. It has no methods.
type NodeSource any

func (*Logger) Startup(...any) error { return nil }
func (*Logger) Running() bool        { return false }
func (*Logger) Shutdown(any) error   { return nil }
func (*Logger) ReconfigRoutes(any)   {}
