// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// RunWatchConnectionLoop loops until ctx is done, sending WatchConnectionChanges and subscribing to
// connection changes.
//
// If the server's public key is ignoreServerKey, RunWatchConnectionLoop returns.
//
// Otherwise, the add and remove funcs are called as clients come & go.
//
// infoLogf, if non-nil, is the logger to write periodic status
// updates about how many peers are on the server. Error log output is
// set to the c's logger, regardless of infoLogf's value.
//
// To force RunWatchConnectionLoop to return quickly, its ctx needs to
// be closed, and c itself needs to be closed.
func (c *Client) RunWatchConnectionLoop(ctx context.Context, ignoreServerKey key.NodePublic, infoLogf logger.Logf, add func(key.NodePublic, netip.AddrPort), remove func(key.NodePublic)) {
	if infoLogf == nil {
		infoLogf = logger.Discard
	}
	logf := c.logf
	const retryInterval = 5 * time.Second
	const statusInterval = 10 * time.Second
	var (
		mu              sync.Mutex
		present         = map[key.NodePublic]bool{}
		loggedConnected = false
	)
	clear := func() {
		mu.Lock()
		defer mu.Unlock()
		if len(present) == 0 {
			return
		}
		logf("reconnected; clearing %d forwarding mappings", len(present))
		for k := range present {
			remove(k)
		}
		present = map[key.NodePublic]bool{}
	}
	lastConnGen := 0
	lastStatus := c.clock.Now()
	logConnectedLocked := func() {
		if loggedConnected {
			return
		}
		infoLogf("connected; %d peers", len(present))
		loggedConnected = true
	}

	const logConnectedDelay = 200 * time.Millisecond
	timer := c.clock.AfterFunc(2*time.Second, func() {
		mu.Lock()
		defer mu.Unlock()
		logConnectedLocked()
	})
	defer timer.Stop()

	updatePeer := func(k key.NodePublic, ipPort netip.AddrPort, isPresent bool) {
		if isPresent {
			add(k, ipPort)
		} else {
			remove(k)
		}

		mu.Lock()
		defer mu.Unlock()
		if isPresent {
			present[k] = true
			if !loggedConnected {
				timer.Reset(logConnectedDelay)
			}
		} else {
			// If we got a peerGone message, that means the initial connection's
			// flood of peerPresent messages is done, so we can log already:
			logConnectedLocked()
			delete(present, k)
		}
	}

	sleep := func(d time.Duration) {
		t, tChannel := c.clock.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-tChannel:
		}
	}

	for ctx.Err() == nil {
		err := c.WatchConnectionChanges()
		if err != nil {
			clear()
			logf("WatchConnectionChanges: %v", err)
			sleep(retryInterval)
			continue
		}

		if c.ServerPublicKey() == ignoreServerKey {
			logf("detected self-connect; ignoring host")
			return
		}
		for {
			m, connGen, err := c.RecvDetail()
			if err != nil {
				clear()
				logf("Recv: %v", err)
				sleep(retryInterval)
				break
			}
			if connGen != lastConnGen {
				lastConnGen = connGen
				clear()
			}
			switch m := m.(type) {
			case derp.PeerPresentMessage:
				updatePeer(m.Key, m.IPPort, true)
			case derp.PeerGoneMessage:
				switch m.Reason {
				case derp.PeerGoneReasonDisconnected:
					// Normal case, log nothing
				case derp.PeerGoneReasonNotHere:
					logf("Recv: peer %s not connected to %s",
						key.NodePublic(m.Peer).ShortString(), c.ServerPublicKey().ShortString())
				default:
					logf("Recv: peer %s not at server %s for unknown reason %v",
						key.NodePublic(m.Peer).ShortString(), c.ServerPublicKey().ShortString(), m.Reason)
				}
				updatePeer(key.NodePublic(m.Peer), netip.AddrPort{}, false)
			default:
				continue
			}
			if now := c.clock.Now(); now.Sub(lastStatus) > statusInterval {
				lastStatus = now
				infoLogf("%d peers", len(present))
			}
		}
	}
}
