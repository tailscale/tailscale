// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package dns

import (
	"sync"

	"tailscale.com/types/logger"
)

var (
	currentModeMu  sync.Mutex
	currentMode    string
	currentModeSet bool
)

// currentMode is a cached value set the first time CurrentDNSMode is called or
// when the DNS engine initializes via SetCurrentDNSMode. It reflects the mode
// tailscaled is actively using and is safe for repeated reads without further
// system probing.

// CurrentDNSMode reports the DNS manager mode detected on this system.
// The result is cached after the first call or after SetCurrentDNSMode
// updates it when the engine starts.
func CurrentDNSMode() string {
	currentModeMu.Lock()
	if !currentModeSet {
		mode, err := dnsMode(logger.Discard, nil, newOSConfigEnv{
			fs:                directFS{},
			dbusPing:          dbusPing,
			dbusReadString:    dbusReadString,
			nmIsUsingResolved: nmIsUsingResolved,
			nmVersionBetween:  nmVersionBetween,
			resolvconfStyle:   resolvconfStyle,
		})
		if err == nil {
			currentMode = mode
			currentModeSet = true
		}
	}
	m := currentMode
	currentModeMu.Unlock()
	return m
}

// SetCurrentDNSMode sets the cached DNS manager mode. 
// It is intended for use by NewOSConfigurator to record the
// mode that tailscaled actually uses.
func SetCurrentDNSMode(mode string) {
	if mode == "" {
		return
	}
	currentModeMu.Lock()
	currentMode = mode
	currentModeSet = true
	currentModeMu.Unlock()
}
