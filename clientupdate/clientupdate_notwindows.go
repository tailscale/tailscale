// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package clientupdate

func (up *Updater) updateWindows() error {
	panic("unreachable")
}
