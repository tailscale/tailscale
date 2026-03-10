// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ((linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9) && !ts_omit_ssh

// Package ssh registers the Tailscale SSH feature, including host key
// management and the SSH server.
package ssh

// Register implementations of various SSH hooks.
import _ "tailscale.com/ssh/tailssh"
