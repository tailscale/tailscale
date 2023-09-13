// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mdm contains functions to read platform-specific MDM-enforced flags
// in a platform-independent manner.
package mdm

import "sync/atomic"

type MDMHandler struct {
	Settings *MDMSettings
}

var mdmHandler atomic.Value // of MDMHandler type

// MDMSettings gets MDM settings from device.
type MDMSettings interface {
	// ReadBool returns a boolean whether the given MDM key exists or not on device settings.
	ReadBool(key string) (bool, error)
	// ReadString reads the MDM settings value string given the key.
	ReadString(key string) (string, error)
}

func RegisterMDMSettings(settings *MDMSettings) *MDMHandler {
	if e, ok := mdmHandler.Load().(*MDMHandler); ok {
		return e
	}
	e := &MDMHandler{Settings: settings}
	mdmHandler.Store(e)
	return e
}
