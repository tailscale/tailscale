// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_netstack

package gro

func RXChecksumOffload(any) any {
	panic("unreachable")
}
