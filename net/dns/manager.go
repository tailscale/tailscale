// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"time"

	"tailscale.com/types/logger"
)

// We use file-ignore below instead of ignore because on some platforms,
// the lint exception is necessary and on others it is not,
// and plain ignore complains if the exception is unnecessary.

//lint:file-ignore U1000 reconfigTimeout is used on some platforms but not others

// reconfigTimeout is the time interval within which Manager.{Up,Down} should complete.
//
// This is particularly useful because certain conditions can cause indefinite hangs
// (such as improper dbus auth followed by contextless dbus.Object.Call).
// Such operations should be wrapped in a timeout context.
const reconfigTimeout = time.Second

// Manager manages system DNS settings.
type Manager struct {
	logf logger.Logf

	impl OSConfigurator

	config OSConfig
}

// NewManagers created a new manager from the given config.
func NewManager(logf logger.Logf, oscfg OSConfigurator) *Manager {
	logf = logger.WithPrefix(logf, "dns: ")
	m := &Manager{
		logf: logf,
		impl: oscfg,
	}

	m.logf("using %T", m.impl)
	return m
}

func (m *Manager) Set(config OSConfig) error {
	if config.Equal(m.config) {
		return nil
	}

	m.logf("Set: %+v", config)

	if len(config.Nameservers) == 0 {
		err := m.impl.Set(OSConfig{})
		// If we save the config, we will not retry next time. Only do this on success.
		if err == nil {
			m.config = config
		}
		return err
	}

	err := m.impl.Set(config)
	// If we save the config, we will not retry next time. Only do this on success.
	if err == nil {
		m.config = config
	}

	return err
}

func (m *Manager) Up() error {
	return m.impl.Set(m.config)
}

func (m *Manager) Down() error {
	return m.impl.Close()
}

// Cleanup restores the system DNS configuration to its original state
// in case the Tailscale daemon terminated without closing the router.
// No other state needs to be instantiated before this runs.
func Cleanup(logf logger.Logf, interfaceName string) {
	oscfg := NewOSConfigurator(logf, interfaceName)
	dns := NewManager(logf, oscfg)
	if err := dns.Down(); err != nil {
		logf("dns down: %v", err)
	}
}
