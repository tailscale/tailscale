// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !linux,!freebsd,!openbsd,!windows

package dns

type noopManager struct{}

func (m noopManager) Set(OSConfig) error       { return nil }
func (m noopManager) RoutingMode() RoutingMode { return RoutingModeNone }
func (m noopManager) Close() error             { return nil }

func newNoopManager() noopManager {
	return noopManager{}
}
