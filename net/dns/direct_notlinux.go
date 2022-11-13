// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux

package dns

func (m *directManager) runFileWatcher() {
	// Not implemented on other platforms. Maybe it could resort to polling.
}
