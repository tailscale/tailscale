// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(linux || darwin || freebsd || openbsd || dragonfly || netbsd)

package sysresources

func totalMemoryImpl() uint64 { return 0 }
