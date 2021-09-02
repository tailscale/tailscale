// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import "os"

func currentFDs() int {
	// TODO(bradfitz): do this without so many allocations on Linux.
	ents, _ := os.ReadDir("/proc/self/fd")
	return len(ents)
}
