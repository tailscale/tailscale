// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_debug && ts_omit_clientmetrics && ts_omit_usermetrics

// excluding the package from builds.
package expvar

type Int int64

func (*Int) Add(int64) {}
