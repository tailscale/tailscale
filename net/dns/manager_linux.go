// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

func newManager(mconfig ManagerConfig) managerImpl {
	switch {
	case isResolvedActive():
		if mconfig.Cleanup {
			return newNoopManager(mconfig)
		} else {
			return newResolvedManager(mconfig)
		}
	case isNMActive():
		if mconfig.Cleanup {
			return newNoopManager(mconfig)
		} else {
			return newNMManager(mconfig)
		}
	case isResolvconfActive():
		return newResolvconfManager(mconfig)
	default:
		return newDirectManager(mconfig)
	}
}
