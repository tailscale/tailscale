// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tlsdial originally existed to set up a tls.Config for x509
// validation, using a memory-optimized path for iOS, but then we
// moved that to the tailscale/go tree instead, so now this package
// does very little. But for now we keep it as a unified point where
// we might want to add shared policy on outgoing TLS connections from
// the 3 places in the client that connect to Tailscale (logs,
// control, DERP).
package tlsdial

import "crypto/tls"

// Config returns a tls.Config for dialing the given host.
// If base is non-nil, it's cloned as the base config before
// being configured and returned.
func Config(host string, base *tls.Config) *tls.Config {
	var conf *tls.Config
	if base == nil {
		conf = new(tls.Config)
	} else {
		conf = base.Clone()
	}
	conf.ServerName = host

	return conf
}
