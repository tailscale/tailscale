// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (!linux && !freebsd && !windows && !darwin) || android
// +build !linux,!freebsd,!windows,!darwin android

package monitor

import (
	"tailscale.com/types/logger"
)

func newOSMon(logf logger.Logf, m *Mon) (osMon, error) {
	return newPollingMon(logf, m)
}

// unspecifiedMessage is a minimal message implementation that should not
// be ignored. In general, OS-specific implementations should use better
// types and avoid this if they can.
type unspecifiedMessage struct{}

func (unspecifiedMessage) ignore() bool { return false }
