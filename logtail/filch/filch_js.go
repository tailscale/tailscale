// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filch

import (
	"os"
)

func saveStderr() (*os.File, error) {
	return os.Stderr, nil
}

func unsaveStderr(f *os.File) error {
	os.Stderr = f
	return nil
}

func dup2Stderr(f *os.File) error {
	return nil
}
