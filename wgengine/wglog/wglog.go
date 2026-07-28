// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wglog contains logging helpers for wireguard-go.
package wglog

import (
	"fmt"
	"strings"
	"sync"

	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/envknob"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

// A Logger is a wireguard-go log wrapper that cleans up and rewrites log lines.
// It rewrites wireguard-go peer references like "peer(XXXX…YYYY)" into the
// Tailscale-conventional short string form like "[XXXXX]".
type Logger struct {
	DeviceLogger *device.Logger

	// lookup, when non-nil, returns the Tailscale-conventional short
	// string for a wireguard-go-formatted peer string (e.g. it maps
	// "peer(IMTB…r7lM)" to "[IMTBr]"), or "", false if no peer matches.
	// It is set once at construction and not changed afterwards.
	lookup func(wgString string) (tsString string, ok bool)

	mu sync.Mutex // protects cache

	// cache memoizes lookup results. The key is the wireguard-go
	// peer-string form ("peer(XXXX…YYYY)") and the value is the
	// Tailscale-conventional short-string form ("[XXXXX]").
	// It is cleared in bulk by Invalidate when the underlying peer set
	// may have changed.
	cache map[string]string
}

// NewLogger creates a new logger for use with wireguard-go.
// This logger silences repetitive/unhelpful noisy log lines
// and rewrites peer keys from wireguard-go into Tailscale format.
//
// lookup, if non-nil, is consulted on cache misses to translate
// wireguard-go peer references in log lines. If lookup is nil,
// peer references are passed through unchanged.
func NewLogger(logf logger.Logf, lookup func(wgString string) (tsString string, ok bool)) *Logger {
	const prefix = "wg: "
	ret := &Logger{lookup: lookup}
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
		if ret.lookup == nil {
			// No lookup; log as originally planned.
			logf(format, args...)
			return
		}
		// Replace any *device.Peer-shaped fmt.Stringer args with the
		// Tailscale-formatted version of themselves. Using *device.Peer
		// directly makes this hard to test, so we string any fmt.Stringers,
		// and if the string ends up matching a known peer, we substitute.
		// This is slightly imprecise, in that we don't check the formatting
		// verb. Oh well.
		var newargs []any
		for i, arg := range args {
			s, ok := arg.(fmt.Stringer)
			if !ok {
				continue
			}
			tsStr, ok := ret.peerStringFor(s.String())
			if !ok {
				continue
			}
			if newargs == nil {
				newargs = make([]any, len(args))
				copy(newargs, args)
			}
			newargs[i] = tsStr
		}
		if newargs == nil {
			logf(format, args...)
			return
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
	return ret
}

// peerStringFor returns the Tailscale-conventional short string for
// wgString, if wgString is a wireguard-go-formatted peer string for a
// peer known to x.lookup. Results are memoized in x.cache for
// subsequent log lines.
func (x *Logger) peerStringFor(wgString string) (tsString string, ok bool) {
	// Fast path: only strings shaped like wireguard-go's
	// "peer(XXXX…YYYY)" output can be peer references; skip the cache
	// and lookup call for anything else (e.g. arbitrary stringers used
	// in unrelated log args).
	if !strings.HasPrefix(wgString, "peer(") || !strings.HasSuffix(wgString, ")") {
		return "", false
	}
	x.mu.Lock()
	if v, ok := x.cache[wgString]; ok {
		x.mu.Unlock()
		return v, true
	}
	x.mu.Unlock()

	// Call lookup without x.mu held so we don't have to reason about
	// deadlocks between x.mu and any locks lookup acquires.
	// In the worst case, two goroutines concurrently miss the cache
	// for the same wgString and both call lookup; the redundant call
	// is wasted but harmless.
	tsString, ok = x.lookup(wgString)
	if !ok {
		return "", false
	}
	x.mu.Lock()
	mak.Set(&x.cache, wgString, tsString)
	x.mu.Unlock()
	return tsString, true
}

// Invalidate clears the peer-string rewrite cache.
//
// Callers should invoke Invalidate when the set of wireguard-go peers
// has changed so that the next log line re-resolves peer references
// against the current lookup. It is safe to call concurrently with
// logging.
func (x *Logger) Invalidate() {
	x.mu.Lock()
	clear(x.cache)
	x.mu.Unlock()
}
