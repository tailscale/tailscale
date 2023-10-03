// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package posture

import "errors"

// GetSerialNumber returns client machine serial number(s).
func GetSerialNumbers() ([]string, error) {
	return nil, errors.New("not implemented")
}
