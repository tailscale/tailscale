/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package ratelimiter

import (
	"net"
	"sync"
	"time"
)

const (
	packetsPerSecond   = 20
	packetsBurstable   = 5
	garbageCollectTime = time.Second
	packetCost         = 1000000000 / packetsPerSecond
	maxTokens          = packetCost * packetsBurstable
)

type RatelimiterEntry struct {
	mu       sync.Mutex
	lastTime time.Time
	tokens   int64
}

type Ratelimiter struct {
	mu      sync.RWMutex
	timeNow func() time.Time

	stopReset chan struct{} // send to reset, close to stop
	tableIPv4 map[[net.IPv4len]byte]*RatelimiterEntry
	tableIPv6 map[[net.IPv6len]byte]*RatelimiterEntry
}

func (rate *Ratelimiter) Close() {
	rate.mu.Lock()
	defer rate.mu.Unlock()

	if rate.stopReset != nil {
		close(rate.stopReset)
	}
}

func (rate *Ratelimiter) Init() {
	rate.mu.Lock()
	defer rate.mu.Unlock()

	if rate.timeNow == nil {
		rate.timeNow = time.Now
	}

	// stop any ongoing garbage collection routine
	if rate.stopReset != nil {
		close(rate.stopReset)
	}

	rate.stopReset = make(chan struct{})
	rate.tableIPv4 = make(map[[net.IPv4len]byte]*RatelimiterEntry)
	rate.tableIPv6 = make(map[[net.IPv6len]byte]*RatelimiterEntry)

	stopReset := rate.stopReset // store in case Init is called again.

	// Start garbage collection routine.
	go func() {
		ticker := time.NewTicker(time.Second)
		ticker.Stop()
		for {
			select {
			case _, ok := <-stopReset:
				ticker.Stop()
				if !ok {
					return
				}
				ticker = time.NewTicker(time.Second)
			case <-ticker.C:
				if rate.cleanup() {
					ticker.Stop()
				}
			}
		}
	}()
}

func (rate *Ratelimiter) cleanup() (empty bool) {
	rate.mu.Lock()
	defer rate.mu.Unlock()

	for key, entry := range rate.tableIPv4 {
		entry.mu.Lock()
		if rate.timeNow().Sub(entry.lastTime) > garbageCollectTime {
			delete(rate.tableIPv4, key)
		}
		entry.mu.Unlock()
	}

	for key, entry := range rate.tableIPv6 {
		entry.mu.Lock()
		if rate.timeNow().Sub(entry.lastTime) > garbageCollectTime {
			delete(rate.tableIPv6, key)
		}
		entry.mu.Unlock()
	}

	return len(rate.tableIPv4) == 0 && len(rate.tableIPv6) == 0
}

func (rate *Ratelimiter) Allow(ip net.IP) bool {
	var entry *RatelimiterEntry
	var keyIPv4 [net.IPv4len]byte
	var keyIPv6 [net.IPv6len]byte

	// lookup entry

	IPv4 := ip.To4()
	IPv6 := ip.To16()

	rate.mu.RLock()

	if IPv4 != nil {
		copy(keyIPv4[:], IPv4)
		entry = rate.tableIPv4[keyIPv4]
	} else {
		copy(keyIPv6[:], IPv6)
		entry = rate.tableIPv6[keyIPv6]
	}

	rate.mu.RUnlock()

	// make new entry if not found

	if entry == nil {
		entry = new(RatelimiterEntry)
		entry.tokens = maxTokens - packetCost
		entry.lastTime = rate.timeNow()
		rate.mu.Lock()
		if IPv4 != nil {
			rate.tableIPv4[keyIPv4] = entry
			if len(rate.tableIPv4) == 1 && len(rate.tableIPv6) == 0 {
				rate.stopReset <- struct{}{}
			}
		} else {
			rate.tableIPv6[keyIPv6] = entry
			if len(rate.tableIPv6) == 1 && len(rate.tableIPv4) == 0 {
				rate.stopReset <- struct{}{}
			}
		}
		rate.mu.Unlock()
		return true
	}

	// add tokens to entry

	entry.mu.Lock()
	now := rate.timeNow()
	entry.tokens += now.Sub(entry.lastTime).Nanoseconds()
	entry.lastTime = now
	if entry.tokens > maxTokens {
		entry.tokens = maxTokens
	}

	// subtract cost of packet

	if entry.tokens > packetCost {
		entry.tokens -= packetCost
		entry.mu.Unlock()
		return true
	}
	entry.mu.Unlock()
	return false
}
