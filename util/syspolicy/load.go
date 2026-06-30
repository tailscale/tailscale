// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"errors"
	"fmt"
	"io/fs"

	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
)

// LoadJSONPolicyFile loads policy settings from the JSON file at path and
// registers them as a [setting.DeviceScope] policy source under sourceName.
//
// If path does not exist, no source is registered and the function returns
// nil. Malformed JSON, unknown setting keys, or values that cannot be
// decoded as the registered type for their key all surface as errors here
// rather than at first use, and nothing is registered.
//
// LoadJSONPolicyFile is intended to be called once, early in process
// startup, after command-line flags are parsed but before any policy
// setting is read.
func LoadJSONPolicyFile(sourceName, path string) error {
	store, err := source.NewJSONPolicyStoreFromFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("syspolicy: loading %s: %w", path, err)
	}
	if err := store.Validate(); err != nil {
		return fmt.Errorf("syspolicy: invalid %s:\n%w", path, err)
	}
	if _, err := rsop.RegisterStore(sourceName, setting.DeviceScope, store); err != nil {
		return fmt.Errorf("syspolicy: registering %s: %w", path, err)
	}
	return nil
}
