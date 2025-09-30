// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build js || ts_omit_debug

package wgengine

func NewWatchdog(e Engine) Engine { return e }
