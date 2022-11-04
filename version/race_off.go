// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !race

package version

// IsRace reports whether the current binary was built with the Go
// race detector enabled.
func IsRace() bool { return false }
