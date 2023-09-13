// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mdm contains functions to read platform-specific MDM-enforced flags
// in a platform-independent manner.
package mdm

type MDMHandler struct {
	Settings *MDMSettings
}

// MDMSettings gets MDM settings from device.
type MDMSettings interface {
	// ReadBool returns a boolean whether the given MDM key exists or not on device settings.
	ReadBool(key string) (bool, error)
	// ReadString reads the MDM settings value string given the key.
	ReadString(key string) (string, error)
}

func (handler *MDMHandler) ReadBool(key string) (bool, error) {
	return handler.ReadBool(key)
}

func (handler *MDMHandler) ReadString(key string) (string, error) {
	return handler.ReadString(key)
}
