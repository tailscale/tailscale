// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"time"

	"tailscale.com/types/logger"
)

// setTimeout is the time interval within which Manager.Set should complete.
//
// This is particularly useful because certain conditions can cause indefinite hangs
// (such as improper dbus auth followed by contextless dbus.Object.Call).
// Such operations should be wrapped in a timeout context.
const setTimeout = time.Second

type managerImpl interface {
	Set(Config) error
	Get() Config
	Reset() error
}

type Manager struct {
	impl      managerImpl
	oldConfig Config
}

func NewManager(logf logger.Logf, interfaceName string) *Manager {
	return &Manager{
		impl: newManager(logf, interfaceName),
	}
}

func (m *Manager) Up(config Config) error {
	if len(config.Nameservers) == 0 {
		return m.impl.Down()
	}

	if config.EquivalentTo(m.oldConfig) {
		return nil
	}

	err := m.impl.Up(config)
	if err == nil {
		m.oldConfig = config
	}

	return err
}

func (m *Manager) Down() error {
	return m.impl.Down()
}
