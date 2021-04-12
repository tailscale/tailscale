// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import "tailscale.com/types/logger"

func NewOSConfigurator(logf logger.Logf, interfaceName string) (OSConfigurator, error) {
	switch {
	case isResolvedActive():
		return newResolvedManager(logf)
	case isNMActive():
		return newNMManager(interfaceName)
	case isResolvconfActive():
		return newResolvconfManager(logf)
	default:
		return newDirectManager()
	}
}
