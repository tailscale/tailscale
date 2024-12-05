// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package netstat

// OSMetadata includes any additional OS-specific information that may be
// obtained during the retrieval of a given Entry.
type OSMetadata struct{}

func get() (*Table, error) {
	return nil, ErrNotImplemented
}
