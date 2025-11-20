// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios || android || ts_omit_debugeventbus

package eventbus

type tswebDebugHandler = any // actually *tsweb.DebugHandler; any to avoid import tsweb with ts_omit_debugeventbus

func (*Debugger) RegisterHTTP(td tswebDebugHandler) {}
