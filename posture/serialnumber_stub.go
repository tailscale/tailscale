// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// ios: Apple does not allow getting serials on iOS
// android: not implemented
// js: not implemented
// plan9: not implemented
// solaris: currently unsupported by go-smbios:
// https://github.com/digitalocean/go-smbios/pull/21

//go:build ios || android || solaris || plan9 || js || wasm || (darwin && !cgo) || tamago || aix

package posture

import (
	"errors"

	"tailscale.com/types/logger"
)

// GetSerialNumber returns client machine serial number(s).
func GetSerialNumbers(_ logger.Logf) ([]string, error) {
	return nil, errors.New("not implemented")
}
