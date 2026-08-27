// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_cpucaps

package cpucaps

// Host returns 0 in binaries built with ts_omit_cpucaps.
func Host() Caps { return 0 }

// HostGOAMD64Level returns 0 in binaries built with ts_omit_cpucaps.
func HostGOAMD64Level() int { return 0 }

// CompiledGOAMD64Level returns 0 in binaries built with ts_omit_cpucaps.
func CompiledGOAMD64Level() int { return 0 }
