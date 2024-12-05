// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package dns

func (m *directManager) runFileWatcher() {
	// Not implemented on other platforms. Maybe it could resort to polling.
}
