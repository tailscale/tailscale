// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(ts_omit_debug && ts_omit_clientmetrics && ts_omit_usermetrics)

// Package expvar contains type aliases for expvar types, to allow conditionally
// excluding the package from builds.
package expvar

import "expvar"

type Int = expvar.Int
