// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows

package netstat

// OSMetadata includes any additional OS-specific information that may be
// obtained during the retrieval of a given Entry.
type OSMetadata struct{}

func get() (*Table, error) {
	return nil, ErrNotImplemented
}
