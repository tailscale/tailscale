// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import "tailscale.com/ipn"

func applyServeMutation(current *ipn.ServeConfig, command []string) (*ipn.ServeConfig, error) {
	if len(command) == 0 {
		return current, nil
	}
	panic("TODO")
}
