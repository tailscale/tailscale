// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package controlwebsocket registers a fallback for control clients to speak
// the Noise control protocol inside WebSockets, as browsers do, when their
// HTTP upgrade to it fails. This gets through HTTP proxies that pass
// WebSocket upgrades but no others, such as Cloudflare's, so a control server
// like Headscale can sit behind one.
//
// It's the control plane's counterpart to feature/derpwebsocket. Neither
// tailscaled nor tsnet links it in. Programs that want it must import it
// themselves.
//
// On js/wasm, where control clients always use WebSockets, importing it does
// nothing.
package controlwebsocket
