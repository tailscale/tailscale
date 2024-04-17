// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (!linux && !darwin) || android || ios

package magicsock

func (c *Conn) DontFragSetting() (bool, error) {
	return false, nil
}

func (c *Conn) ShouldPMTUD() bool {
	return false
}

func (c *Conn) PeerMTUEnabled() bool {
	return false
}

func (c *Conn) UpdatePMTUD() {
}
