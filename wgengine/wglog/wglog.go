// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wglog contains logging helpers for wireguard-go.
package wglog

import (
	"encoding/base64"
	"strings"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/types/logger"
)

// A Logger is a wireguard-go log wrapper that cleans up and rewrites log lines.
// It can be modified at run time to adjust to new wireguard-go configurations.
type Logger struct {
	DeviceLogger *device.Logger
	replacer     atomic.Value // of *strings.Replacer
}

// NewLogger creates a new logger for use with wireguard-go.
// This logger silences repetitive/unhelpful noisy log lines
// and rewrites peer keys from wireguard-go into Tailscale format.
// Peer key rewriting only takes effect if logf was wrapped in logger.ApplyPostProcess.
func NewLogger(logf logger.Logf) *Logger {
	ret := new(Logger)

	logf = logger.RateLimitContext(logf, "wireguard-go")
	allow := func(s string) bool {
		// wireguard-go logs as it starts and stops routines.
		// Drop those lines; there are a lot of them, and they're just noise.
		return !strings.Contains(s, "Routine:")
	}
	logf = logger.Filtered(logf, allow)
	// Rewrite peer identifiers.
	post := func(s string) string {
		r := ret.replacer.Load()
		if r == nil {
			return s
		}
		return r.(*strings.Replacer).Replace(s)
	}
	logf = logger.PostProcess(logf, post)

	std := logger.StdLogger(logf)
	ret.DeviceLogger = &device.Logger{
		Debug: std,
		Info:  std,
		Error: std,
	}
	return ret
}

// SetPeers adjusts x to rewrite the peer public keys found in peers.
// SetPeers is safe for concurrent use.
func (x *Logger) SetPeers(peers []wgcfg.Peer) {
	// Construct a new peer public key log rewriter.
	var replace []string
	for _, peer := range peers {
		old := "peer(" + wireguardGoString(peer.PublicKey) + ")"
		new := peer.PublicKey.ShortString()
		replace = append(replace, old, new)
	}
	r := strings.NewReplacer(replace...)
	x.replacer.Store(r)
}

// wireguardGoString prints p in the same format used by wireguard-go.
func wireguardGoString(k wgcfg.Key) string {
	base64Key := base64.StdEncoding.EncodeToString(k[:])
	abbreviatedKey := "invalid"
	if len(base64Key) == 44 {
		abbreviatedKey = base64Key[0:4] + "…" + base64Key[39:43]
	}
	return abbreviatedKey
}
