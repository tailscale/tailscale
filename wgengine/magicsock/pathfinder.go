// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"fmt"
	"net/netip"
	"time"

	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

// startPathFinder initializes the sendFunc, and
// will eventually kick off a goroutine that monitors whether
// that sendFunc is still the best option for the endpoint
// to use and adjusts accordingly.
func (de *endpoint) startPathFinder() {
	go func() {
		for mono.Since(de.lastSendAtomic.Load()) < sessionActiveTimeout {
			de.mu.Lock()
			de.pathFinderRunning = true
			de.mu.Unlock()

			// while the session has not timed out yet,
			// check whether path needs to be upgraded on an interval
			de.updateSendPathIfNecessary(mono.Now())

			// TODO(2022-10-20): should not be using heartbeat at all, currently just
			// trying to replicate existing behaviour
			time.Sleep(heartbeatInterval)
		}
	}()
}

// updateSendPathIfNecessary optionally upates sendFunc
// based on analysis of current conditions
func (de *endpoint) updateSendPathIfNecessary(now mono.Time) {
	de.mu.Lock()
	defer de.mu.Unlock()

	// default happy state is: use UDP, don't use Derp
	useUDP := true
	useDerp := false

	// if it's been longer than 6.5 seconds, also send useDerp
	if now.After(de.trustBestAddrUntil) {
		useDerp = true
	}

	derpAddr := de.derpAddr
	udpAddr := de.bestAddr.AddrPort

	// do final checks to make sure the addresses we want to send to are valid
	if useUDP && !udpAddr.IsValid() {
		de.c.logf(fmt.Sprintf("magicsock: silent-disco: invalid UDP addr found: %s", udpAddr))
		return
	}
	if useDerp && !derpAddr.IsValid() {
		de.c.logf(fmt.Sprintf("magicsock: silent-disco: invalid DERP addr found: %s", derpAddr))
		return
	}

	if useUDP && useDerp {
		de.sendFunc.Store(de.sendDerpAndUDP(udpAddr, derpAddr, de.publicKey))
	} else if useUDP {
		de.sendFunc.Store(de.sendSinglePath(udpAddr, de.publicKey))
	} else if useDerp {
		de.sendFunc.Store(de.sendSinglePath(derpAddr, de.publicKey))
	}

	if de.wantFullPingLocked(now) {
		de.sendPingsLocked(now, true) // spray endpoints, and enqueue CMM
	}

	// currently does not re-implement the heartbeat calling startPingLocked
	// keep-alive every 3 seconds. this is where the bulk of the new upgrade
	// logic should be, I think?
}

func (de *endpoint) sendSinglePath(addr netip.AddrPort, pubKey key.NodePublic) endpointSendFunc {
	return func(b []byte) error {
		_, err := de.c.sendAddr(addr, pubKey, b)
		return err
	}
}

func (de *endpoint) sendDerpAndUDP(udpAddr netip.AddrPort, derpAddr netip.AddrPort, pubKey key.NodePublic) endpointSendFunc {
	return func(b []byte) error {
		_, udpErr := de.c.sendAddr(udpAddr, de.publicKey, b)
		_, derpErr := de.c.sendAddr(derpAddr, de.publicKey, b)
		if derpErr == nil || udpErr == nil {
			// at least one packet send succeeded, good enough
			return nil
		}
		return udpErr // error from UDP send supersedes error from Derp send
	}
}
