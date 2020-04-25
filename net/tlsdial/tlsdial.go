// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tlsdial sets up a tls.Config for x509 validation, using
// a memory-optimized path for iOS.
package tlsdial

import "crypto/tls"

var platformModifyConf func(*tls.Config)

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

	if platformModifyConf != nil {
		platformModifyConf(conf)
	}

	return conf
}
