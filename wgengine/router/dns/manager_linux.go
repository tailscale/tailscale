// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"context"
	"sync"
	"time"

	"tailscale.com/logtail/backoff"
	"tailscale.com/types/logger"
)

var reconfigTimeout = 5 * time.Second

type dnsMode uint8

const (
	noMode dnsMode = iota
	nmMode
	resolvedMode
	resolvconfMode
	directMode
)

func (m dnsMode) String() string {
	switch m {
	case noMode:
		return "none"
	case nmMode:
		return "NetworkManager"
	case resolvedMode:
		return "systemd-resolved"
	case resolvconfMode:
		return "resolvconf"
	case directMode:
		return "direct"
	default:
		return "???"
	}
}

// linuxManager manages system configuration asynchronously with backoff on errors.
// This is useful because nmManager and resolvedManager cannot be used
// until the Tailscale network interface is ready from the point of view
// of NetworkManager/systemd-resolved, which can take a unspecified amount of time.
type linuxManager struct {
	logf    logger.Logf
	mconfig ManagerConfig

	config chan Config

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func configToMode(config Config) dnsMode {
	switch {
	case isNMActive():
		return nmMode
	case isResolvedActive() && config.PerDomain:
		return resolvedMode
	case isResolvconfActive():
		return resolvconfMode
	default:
		return directMode
	}
}

func (m *linuxManager) modeToImpl(mode dnsMode) Manager {
	switch mode {
	case nmMode:
		return newNMManager(m.mconfig)
	case resolvedMode:
		return newResolvedManager(m.mconfig)
	case resolvconfMode:
		return newResolvconfManager(m.mconfig)
	case directMode:
		return newDirectManager(m.mconfig)
	default:
		return newNoopManager(m.mconfig)
	}
}

func newManager(mconfig ManagerConfig) Manager {
	// For cleanup, don't try anything fancy.
	if mconfig.Cleanup {
		switch {
		case isNMActive(), isResolvedActive():
			return newNoopManager(mconfig)
		case isResolvconfActive():
			return newResolvconfManager(mconfig)
		default:
			return newDirectManager(mconfig)
		}
	}

	return &linuxManager{
		logf:    mconfig.Logf,
		mconfig: mconfig,
		config:  make(chan Config, 1),
	}
}

func (m *linuxManager) background() {
	defer m.wg.Done()

	var mode dnsMode
	var impl Manager
	var config Config

	bo := backoff.NewBackoff("dns", m.logf, 30*time.Second)
	for {
		select {
		case <-m.ctx.Done():
			if err := impl.Down(); err != nil {
				m.logf("stop: down: %v", err)
			}
			return
		case config = <-m.config:
			// continue
		}

		newMode := configToMode(config)
		if newMode != mode {
			m.logf("changing mode: %v -> %v", mode, newMode)
			// If a non-noop manager was active, deactivate it first.
			if mode != noMode {
				if err := impl.Down(); err != nil {
					m.logf("mode change: down: %v", err)
				}
			}
			mode = newMode
			impl = m.modeToImpl(newMode)
		}

		err := impl.Set(config)
		if err != nil {
			m.logf("set: %v", err)
			// Force another iteration.
			select {
			case m.config <- config:
				// continue
			default:
				// continue
			}
		}
		bo.BackOff(m.ctx, err)
	}
}

// Set implements Manager.
func (m *linuxManager) Set(config Config) error {
	if m.ctx == nil {
		m.ctx, m.cancel = context.WithCancel(context.Background())
		m.wg.Add(1)
		go m.background()
	}
	select {
	case <-m.ctx.Done():
		return nil
	case m.config <- config:
		// continue
	default:
		<-m.config
		m.config <- config
	}
	return nil
}

// Down implements Manager.
func (m *linuxManager) Down() error {
	m.cancel()
	m.wg.Wait()
	m.ctx = nil
	return nil
}
