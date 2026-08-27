// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android && !ts_omit_cpucaps

package varz

import (
	"expvar"

	"tailscale.com/util/cpucaps"
)

func init() {
	var capable any = cpucaps.HostGOAMD64Level()
	expvar.Publish("gauge_goamd64_capable", expvar.Func(func() any { return capable }))
	var compiled any = cpucaps.CompiledGOAMD64Level()
	expvar.Publish("gauge_goamd64_compiled", expvar.Func(func() any { return compiled }))
}
