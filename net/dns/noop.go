// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !linux,!freebsd,!openbsd,!windows

package dns

type noopManager struct{}

// Up implements managerImpl.
func (m noopManager) Up(OSConfig) error { return nil }

// Down implements managerImpl.
func (m noopManager) Down() error { return nil }

func newNoopManager() managerImpl {
	return noopManager{}
}
