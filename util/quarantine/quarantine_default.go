// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !darwin && !windows

package quarantine

import (
	"os"
)

func setQuarantineAttr(f *os.File) error {
	return nil
}
