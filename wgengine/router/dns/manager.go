// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"tailscale.com/types/logger"
)

// Manager manages system DNS settings.
type Manager interface {
	// Set updates system DNS settings to match the given configuration.
	Set(Config) error
	// Down undoes the effects of Set.
	// It is idempotent and performs no action if Set has never been called.
	Down() error
}

type wrappedManager struct {
	logf   logger.Logf
	impl   Manager
	config Config
}

// NewManager creates a new manager from the given config.
func NewManager(mconfig ManagerConfig) Manager {
	mconfig.Logf = logger.WithPrefix(mconfig.Logf, "dns: ")
	m := &wrappedManager{
		logf: mconfig.Logf,
		impl: newManager(mconfig),
	}

	m.logf("using %T", m.impl)
	return m
}

func (m *wrappedManager) Set(config Config) error {
	if config.Equal(m.config) {
		return nil
	}

	m.logf("set: %+v", config)

	err := m.impl.Set(config)
	if err == nil {
		m.config = config
	}
	return err
}

func (m *wrappedManager) Down() error {
	return m.impl.Down()
}
