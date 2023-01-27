// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || ts_omit_tap

package tstun

func (*Wrapper) handleTAPFrame([]byte) bool { panic("unreachable") }
