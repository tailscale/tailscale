// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || darwin || freebsd || openbsd || plan9) && !ts_omit_ssh

package main

// Register implementations of various SSH hooks.
import _ "tailscale.com/feature/ssh"
