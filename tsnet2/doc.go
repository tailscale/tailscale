// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tsnet2 is an out-of-process variant of [tailscale.com/tsnet]
// where the WireGuard cryptography, control-plane state, and LocalBackend
// all live in a separate long-lived daemon process (tsnet2d). The
// in-application code is a thin shim that talks to the daemon over a Unix
// socket.
//
// This gives a single chokepoint for auditing/logging cleartext traffic to
// and from the application — something that is not possible with stock
// tsnet because everything outside the process is encrypted WireGuard.
//
// The API is intentionally a drop-in replacement for [tsnet.Server]: the
// same field names and method signatures, so existing consumers can
// migrate by changing one import line.
//
// See PLAN.tsnet2.md at the repository root for the full design,
// including the wire protocol between the application and the daemon
// and the traffic-logging record format.
//
// This package is a work in progress. Most public methods currently
// return errors indicating they are not implemented.
package tsnet2
