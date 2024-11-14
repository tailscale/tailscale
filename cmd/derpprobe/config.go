// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import "time"

type config struct {
	// DerpMap is a URL to a DERP map file.
	DerpMap string

	// ListenAddr is the address at which derpprobe should listen for HTTP requests.
	ListenAddr string

	// ProbeOnce, if true, causes dermap to run only one round of probes and then terminate.
	ProbeOnce bool

	// Spread introduces a random delay before the first run of any probe.
	Spread bool

	// MapInterval specifies how frequently to fetch an updated DERP map.
	MapInterval time.Duration

	// Mesh configures mesh probing.
	Mesh ProbeConfig

	// STUN configures STUN probing.
	STUN ProbeConfig

	// TLS configures TLS probing.
	TLS ProbeConfig

	// Banwdith configures bandwidth probing.
	Bandwidth BandwidthConfig
}

// ProbeConfig configures a specific type of probe. It is only exported
// because the cmp.Diff requires it to be.
type ProbeConfig struct {
	// Interval specifies how frequently to run the probe.
	Interval time.Duration

	// Regions, if non-empty, restricts this probe to the specified region codes.
	Regions []string
}

// BandwidthConfig is a specialized form of [ProbeConfig] for bandwidth probes.
// It is only exported because cmp.Diff requires it to be.
type BandwidthConfig struct {
	// Interval specifies how frequently to run the probe.
	Interval time.Duration

	// Regions, if non-empty, restricts this probe to the specified region codes.
	Regions []string

	// Size specifies how many bytes of data to send with each bandwidth probe.
	Size int64
}
