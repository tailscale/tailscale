// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || darwin || freebsd || openbsd || plan9) && !ts_omit_ssh

package main

// Force registration of tailssh with LocalBackend.
import _ "tailscale.com/ssh/tailssh"
