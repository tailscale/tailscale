// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"fmt"
	"net/netip"

	"tailscale.com/ipn"
)

// checkAcceptRoutes validates stored subnet route filters even when RouteAll is
// false, so enabling route acceptance cannot activate an invalid filter.
func checkAcceptRoutes(p *ipn.Prefs) error {
	var errs []error
	for _, filter := range []struct {
		flag     string
		prefixes []netip.Prefix
	}{
		{"accept-routes-allow", p.AcceptRoutesAllow},
		{"accept-routes-deny", p.AcceptRoutesDeny},
	} {
		for _, prefix := range filter.prefixes {
			switch {
			case !prefix.IsValid():
				errs = append(errs, fmt.Errorf("--%s contains an invalid prefix", filter.flag))
			case prefix.Addr().Is4In6():
				errs = append(errs, fmt.Errorf("--%s: %s is an IPv4-mapped IPv6 prefix; use an IPv4 prefix instead", filter.flag, prefix))
			case prefix != prefix.Masked():
				errs = append(errs, fmt.Errorf("--%s: %s has non-address bits set; expected %s", filter.flag, prefix, prefix.Masked()))
			}
		}
	}
	return errors.Join(errs...)
}
