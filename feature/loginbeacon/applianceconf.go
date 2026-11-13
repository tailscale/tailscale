// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// appliancePath is where `tailscale configure flash-appliance
// --enable-login-beacon` writes the runtime config. /perm is the writable
// partition on gokrazy.
const appliancePath = "/perm/loginbeacon.json"

type ApplianceConfig struct {
	Enabled  bool   `json:"enabled"`
	Hostname string `json:"hostname,omitempty"`
}

// LoadApplianceConfig returns (nil, nil) if the file is absent, which is
// treated as "beacon disabled".
func LoadApplianceConfig() (*ApplianceConfig, error) {
	return loadApplianceConfigFrom(appliancePath)
}

func loadApplianceConfigFrom(path string) (*ApplianceConfig, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("loginbeacon: reading %s: %w", path, err)
	}
	var c ApplianceConfig
	if err := json.Unmarshal(buf, &c); err != nil {
		return nil, fmt.Errorf("loginbeacon: parsing %s: %w", path, err)
	}
	return &c, nil
}
