// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (!linux && !freebsd && !windows && !darwin) || android

package netmon

import (
	"tailscale.com/types/logger"
)

func newOSMon(logf logger.Logf, m *Monitor) (osMon, error) {
	return newPollingMon(logf, m)
}

// unspecifiedMessage is a minimal message implementation that should not
// be ignored. In general, OS-specific implementations should use better
// types and avoid this if they can.
type unspecifiedMessage struct{}

func (unspecifiedMessage) ignore() bool { return false }
