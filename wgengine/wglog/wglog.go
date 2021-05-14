// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wglog contains logging helpers for wireguard-go.
package wglog

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/device"
	"tailscale.com/types/logger"
	"tailscale.com/types/wgkey"
	"tailscale.com/wgengine/wgcfg"
)

// A Logger is a wireguard-go log wrapper that cleans up and rewrites log lines.
// It can be modified at run time to adjust to new wireguard-go configurations.
type Logger struct {
	DeviceLogger *device.Logger
	replace      atomic.Value            // of map[string]string
	mu           sync.Mutex              // protects strs
	strs         map[wgkey.Key]*strCache // cached strs used to populate replace
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
	ret := new(Logger)
	wrapper := func(format string, args ...interface{}) {
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
		replace, _ := ret.replace.Load().(map[string]string)
		if replace == nil {
			// No replacements specified; log as originally planned.
			logf(format, args...)
			return
		}
		// Duplicate the args slice so that we can modify it.
		// This is not always required, but the code required to avoid it is not worth the complexity.
		newargs := make([]interface{}, len(args))
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
	ret.DeviceLogger = &device.Logger{
		Verbosef: logger.WithPrefix(wrapper, "[v2] "),
		Errorf:   wrapper,
	}
	ret.strs = make(map[wgkey.Key]*strCache)
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
			wg := wireguardGoString(peer.PublicKey)
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

// wireguardGoString prints p in the same format used by wireguard-go.
func wireguardGoString(k wgkey.Key) string {
	src := k
	b64 := func(input byte) byte {
		return input + 'A' + byte(((25-int(input))>>8)&6) - byte(((51-int(input))>>8)&75) - byte(((61-int(input))>>8)&15) + byte(((62-int(input))>>8)&3)
	}
	b := []byte("peer(____…____)")
	const first = len("peer(")
	const second = len("peer(____…")
	b[first+0] = b64((src[0] >> 2) & 63)
	b[first+1] = b64(((src[0] << 4) | (src[1] >> 4)) & 63)
	b[first+2] = b64(((src[1] << 2) | (src[2] >> 6)) & 63)
	b[first+3] = b64(src[2] & 63)
	b[second+0] = b64(src[29] & 63)
	b[second+1] = b64((src[30] >> 2) & 63)
	b[second+2] = b64(((src[30] << 4) | (src[31] >> 4)) & 63)
	b[second+3] = b64((src[31] << 2) & 63)
	return string(b)
}
