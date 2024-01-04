// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"strings"

	"go4.org/netipx"
)

func advertiseRoutes(set *netipx.IPSet) {
	fmt.Println()
	prefixes := set.Prefixes()
	pfxs := make([]string, 0, len(prefixes))
	for _, pfx := range prefixes {
		pfxs = append(pfxs, pfx.String())
	}
	fmt.Printf("--advertise-routes=%s", strings.Join(pfxs, ","))
	fmt.Println()
}
