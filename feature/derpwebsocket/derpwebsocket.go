// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package derpwebsocket registers a fallback for DERP clients to speak DERP
// inside WebSockets, as browsers do, when their HTTP upgrade to DERP fails.
// This gets through HTTP proxies that intercept TLS and allow WebSocket
// upgrades but block others, as in some sandboxes for AI agents.
//
// Neither tailscaled nor tsnet links it in. Programs that want it must
// import it themselves.
//
// On js/wasm, where DERP clients always use WebSockets, importing it does
// nothing.
package derpwebsocket
