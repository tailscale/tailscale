// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package limiter provides a keyed token bucket rate limiter.
package limiter

import (
	"fmt"
	"html"
	"io"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/util/lru"
)

// Limiter is a keyed token bucket rate limiter.
//
// Each key gets its own separate token bucket to pull from, enabling
// enforcement on things like "requests per IP address". To avoid
// unbounded memory growth, Limiter actually only tracks limits
// precisely for the N most recently seen keys, and assumes that
// untracked keys are well-behaved. This trades off absolute precision
// for bounded memory use, while still enforcing well for outlier
// keys.
//
// As such, Limiter should only be used in situations where "rough"
// enforcement of outliers only is sufficient, such as throttling
// egregious outlier keys (e.g. something sending 100 queries per
// second, where everyone else is sending at most 5).
//
// Each key's token bucket behaves like a regular token bucket, with
// the added feature that a bucket's token count can optionally go
// negative. This implements a form of "cooldown" for keys that exceed
// the rate limit: once a key starts getting denied, it must stop
// requesting tokens long enough for the bucket to return to a
// positive balance. If the key keeps hammering the limiter in excess
// of the rate limit, the token count will remain negative, and the
// key will not be allowed to proceed at all. This is in contrast to
// the classic token bucket, where a key trying to use more than the
// rate limit will get capped at the limit, but can still occasionally
// consume a token as one becomes available.
//
// The zero value is a valid limiter that rejects all requests. A
// useful limiter must specify a Size, Max and RefillInterval.
type Limiter[K comparable] struct {
	// Size is the number of keys to track. Only the Size most
	// recently seen keys have their limits enforced precisely, older
	// keys are assumed to not be querying frequently enough to bother
	// tracking.
	Size int

	// Max is the number of tokens available for a key to consume
	// before time-based rate limiting kicks in. An unused limiter
	// regains available tokens over time, up to Max tokens. A newly
	// tracked key initially receives Max tokens.
	Max int64

	// RefillInterval is the interval at which a key regains tokens for
	// use, up to Max tokens.
	RefillInterval time.Duration

	// Overdraft is the amount of additional tokens a key can be
	// charged for when it exceeds its rate limit. Each additional
	// request issued for the key charges one unit of overdraft, up to
	// this limit. Overdraft tokens are refilled at the normal rate,
	// and must be fully repaid before any tokens become available for
	// requests.
	//
	// A non-zero Overdraft results in "cooldown" behavior: with a
	// normal token bucket that bottoms out at zero tokens, an abusive
	// key can still consume one token every RefillInterval. With a
	// non-zero overdraft, a throttled key must stop requesting tokens
	// entirely for a cooldown period, otherwise they remain
	// perpetually in debt and cannot proceed at all.
	Overdraft int64

	mu    syncs.Mutex
	cache *lru.Cache[K, *bucket]
}

// QPSInterval returns the interval between events corresponding to
// the given queries/second rate.
//
// This is a helper to be used when populating Limiter.RefillInterval.
func QPSInterval(qps float64) time.Duration {
	return time.Duration(float64(time.Second) / qps)
}

type bucket struct {
	cur        int64     // current available tokens
	lastUpdate time.Time // last timestamp at which cur was updated
}

// Allow charges the key one token (up to the overdraft limit), and
// reports whether the key can perform an action.
func (lm *Limiter[K]) Allow(key K) bool {
	return lm.allow(key, time.Now())
}

func (lm *Limiter[K]) allow(key K, now time.Time) bool {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	return lm.allowBucketLocked(lm.getBucketLocked(key, now), now)
}

func (lm *Limiter[K]) getBucketLocked(key K, now time.Time) *bucket {
	if lm.cache == nil {
		lm.cache = &lru.Cache[K, *bucket]{MaxEntries: lm.Size}
	} else if b := lm.cache.Get(key); b != nil {
		return b
	}
	b := &bucket{
		cur:        lm.Max,
		lastUpdate: now.Truncate(lm.RefillInterval),
	}
	lm.cache.Set(key, b)
	return b
}

func (lm *Limiter[K]) allowBucketLocked(b *bucket, now time.Time) bool {
	// Only update the bucket quota if needed to process request.
	if b.cur <= 0 {
		lm.updateBucketLocked(b, now)
	}
	ret := b.cur > 0
	if b.cur > -lm.Overdraft {
		b.cur--
	}
	return ret
}

func (lm *Limiter[K]) updateBucketLocked(b *bucket, now time.Time) {
	now = now.Truncate(lm.RefillInterval)
	if now.Before(b.lastUpdate) {
		return
	}
	timeDelta := max(now.Sub(b.lastUpdate), 0)
	tokenDelta := int64(timeDelta / lm.RefillInterval)
	b.cur = min(b.cur+tokenDelta, lm.Max)
	b.lastUpdate = now
}

// peekForTest returns the number of tokens for key, also reporting
// whether key was present.
func (lm *Limiter[K]) tokensForTest(key K) (int64, bool) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	if b, ok := lm.cache.PeekOk(key); ok {
		return b.cur, true
	}
	return 0, false
}

// DumpHTML writes the state of the limiter to the given writer,
// formatted as an HTML table. If onlyLimited is true, the output only
// lists keys that are currently being limited.
//
// DumpHTML blocks other callers of the limiter while it collects the
// state for dumping. It should not be called on large limiters
// involved in hot codepaths.
func (lm *Limiter[K]) DumpHTML(w io.Writer, onlyLimited bool) {
	lm.dumpHTML(w, onlyLimited, time.Now())
}

func (lm *Limiter[K]) dumpHTML(w io.Writer, onlyLimited bool, now time.Time) {
	dump := lm.collectDump(now)
	io.WriteString(w, "<table><tr><th>Key</th><th>Tokens</th></tr>")
	for _, line := range dump {
		if onlyLimited && line.Tokens > 0 {
			continue
		}
		kStr := html.EscapeString(fmt.Sprint(line.Key))
		format := "<tr><td>%s</td><td>%d</td></tr>"
		if !onlyLimited && line.Tokens <= 0 {
			// Make limited entries stand out when showing
			// limited+non-limited together
			format = "<tr><td>%s</td><td><b>%d</b></td></tr>"
		}
		fmt.Fprintf(w, format, kStr, line.Tokens)
	}
	io.WriteString(w, "</table>")
}

// collectDump grabs a copy of the limiter state needed by DumpHTML.
func (lm *Limiter[K]) collectDump(now time.Time) []dumpEntry[K] {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	ret := make([]dumpEntry[K], 0, lm.cache.Len())
	lm.cache.ForEach(func(k K, v *bucket) {
		lm.updateBucketLocked(v, now) // so stats are accurate
		ret = append(ret, dumpEntry[K]{k, v.cur})
	})
	return ret
}

// dumpEntry is the per-key information that DumpHTML needs to print
// limiter state.
type dumpEntry[K comparable] struct {
	Key    K
	Tokens int64
}
