// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package envknob

import (
	"os"
	"path/filepath"
)

func init() {
	platformApplyDiskConfig = platformApplyDiskConfigWindows
}

func platformApplyDiskConfigWindows() error {
	name := filepath.Join(os.Getenv("ProgramData"), "Tailscale", "tailscaled-env.txt")
	f, err := os.Open(name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	return applyKeyValueEnv(f)
}
