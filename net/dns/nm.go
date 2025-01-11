// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package dns

import (
	"errors"
	"time"
)

const (
	highestPriority = int32(-1 << 31)
	mediumPriority  = int32(1)   // Highest priority that doesn't hard-override
	lowerPriority   = int32(200) // lower than all builtin auto priorities
)

// reconfigTimeout is the time interval within which Manager.{Up,Down} should complete.
//
// This is particularly useful because certain conditions can cause indefinite hangs
// (such as improper dbus auth followed by contextless dbus.Object.Call).
// Such operations should be wrapped in a timeout context.
const reconfigTimeout = time.Second

// nmManager uses the NetworkManager DBus API.
type nmManager struct {
	interfaceName string
}

func newNMManager(interfaceName string) (*nmManager, error) {
	return nil, errors.New("lanscaping")
}

func (m *nmManager) SupportsSplitDNS() bool {
	return false
}

func (m *nmManager) SetDNS(config OSConfig) error {
	return errors.New("lanscaping")
}

func (m *nmManager) GetBaseConfig() (OSConfig, error) {
	return OSConfig{}, errors.New("lanscaping")
}

func (m *nmManager) Close() error {
	// No need to do anything on close, NetworkManager will delete our
	// settings when the tailscale interface goes away.
	return nil
}
