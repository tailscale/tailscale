// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package cli

import "fmt"

// The github.com/mitchellh/go-ps package doesn't work on all platforms,
// so just don't diagnose connect failures.

func fixTailscaledConnectError(origErr error) error {
	return fmt.Errorf("failed to connect to local tailscaled process (is it running?); got: %w", origErr)
}
