// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !darwin && !ios

package dns

func flushCaches() error {
	return nil
}
