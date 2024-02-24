// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package wglog contains logging helpers for wireguard-go.
package wglog

import (
	"fmt"
	"strings"
	"sync"

	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/envknob"
	"tailscale.com/syncs"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/wgcfg"
)

// A Logger is a wireguard-go log wrapper that cleans up and rewrites log lines.
// It can be modified at run time to adjust to new wireguard-go configurations.
type Logger struct {
	DeviceLogger *device.Logger
	replace      syncs.AtomicValue[map[string]string]
	mu           sync.Mutex                   // protects strs
	strs         map[key.NodePublic]*strCache // cached strs used to populate replace
}

// strCache holds a wireguard-go and a Tailscale style peer string.
type strCache struct {
	wg, ts string
	used   bool // track whether this strCache was used in a particular round
}

// NewLogger creates a new logger for use with wireguard-go.
// This logger silences repetitive/unhelpful noisy log lines
// and rewrites peer keys from wireguard-go into Tailscale format.
func NewLogger(logf logger.Logf) *Logger {
	const prefix = "wg: "
	ret := new(Logger)
	wrapper := func(format string, args ...any) {
		if strings.Contains(format, "Routine:") && !strings.Contains(format, "receive incoming") {
			// wireguard-go logs as it starts and stops routines.
			// Drop those; there are a lot of them, and they're just noise.
			return
		}
		if strings.Contains(format, "Failed to send data packet") {
			// Drop. See https://github.com/tailscale/tailscale/issues/1239.
			return
		}
		if strings.Contains(format, "Interface up requested") || strings.Contains(format, "Interface down requested") {
			// Drop. Logs 1/s constantly while the tun device is open.
			// See https://github.com/tailscale/tailscale/issues/1388.
			return
		}
		if strings.Contains(format, "Adding allowedip") {
			// Drop. See https://github.com/tailscale/corp/issues/17532.
			// AppConnectors (as one example) may have many subnet routes, and
			// the messaging related to these is not specific enough to be
			// useful.
			return
		}
		replace := ret.replace.Load()
		if replace == nil {
			// No replacements specified; log as originally planned.
			logf(format, args...)
			return
		}
		// Duplicate the args slice so that we can modify it.
		// This is not always required, but the code required to avoid it is not worth the complexity.
		newargs := make([]any, len(args))
		copy(newargs, args)
		for i, arg := range newargs {
			// We want to replace *device.Peer args with the Tailscale-formatted version of themselves.
			// Using *device.Peer directly makes this hard to test, so we string any fmt.Stringers,
			// and if the string ends up looking exactly like a known Peer, we replace it.
			// This is slightly imprecise, in that we don't check the formatting verb. Oh well.
			s, ok := arg.(fmt.Stringer)
			if !ok {
				continue
			}
			wgStr := s.String()
			tsStr, ok := replace[wgStr]
			if !ok {
				continue
			}
			newargs[i] = tsStr
		}
		logf(format, newargs...)
	}
	if envknob.Bool("TS_DEBUG_RAW_WGLOG") {
		wrapper = logf
	}
	ret.DeviceLogger = &device.Logger{
		Verbosef: logger.WithPrefix(wrapper, prefix+"[v2] "),
		Errorf:   logger.WithPrefix(wrapper, prefix),
	}
	ret.strs = make(map[key.NodePublic]*strCache)
	return ret
}

// SetPeers adjusts x to rewrite the peer public keys found in peers.
// SetPeers is safe for concurrent use.
func (x *Logger) SetPeers(peers []wgcfg.Peer) {
	x.mu.Lock()
	defer x.mu.Unlock()
	// Construct a new peer public key log rewriter.
	replace := make(map[string]string)
	for _, peer := range peers {
		c, ok := x.strs[peer.PublicKey] // look up cached strs
		if !ok {
			wg := peer.PublicKey.WireGuardGoString()
			ts := peer.PublicKey.ShortString()
			c = &strCache{wg: wg, ts: ts}
			x.strs[peer.PublicKey] = c
		}
		c.used = true
		replace[c.wg] = c.ts
	}
	// Remove any unused cached strs.
	for k, c := range x.strs {
		if !c.used {
			delete(x.strs, k)
			continue
		}
		// Mark c as unused for next round.
		c.used = false
	}
	x.replace.Store(replace)
}
