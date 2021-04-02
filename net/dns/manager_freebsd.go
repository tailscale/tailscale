// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import "tailscale.com/types/logger"

func newManager(logf logger.Logf, _ string) managerImpl {
	switch {
	case isResolvconfActive():
		return newResolvconfManager(logf)
	default:
		return newDirectManager()
	}
}
