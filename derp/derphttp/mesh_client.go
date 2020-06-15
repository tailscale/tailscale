// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derphttp

import (
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/types/key"
)

// RunWatchConnectionLoop loops forever, sending WatchConnectionChanges and subscribing to
// connection changes.
//
// If the server's public key is ignoreServerKey, RunWatchConnectionLoop returns.
//
// Otherwise, the add and remove funcs are called as clients come & go.
func (c *Client) RunWatchConnectionLoop(ignoreServerKey key.Public, add, remove func(key.Public)) {
	logf := c.logf
	const retryInterval = 5 * time.Second
	const statusInterval = 10 * time.Second
	var (
		mu              sync.Mutex
		present         = map[key.Public]bool{}
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
		present = map[key.Public]bool{}
	}
	lastConnGen := 0
	lastStatus := time.Now()
	logConnectedLocked := func() {
		if loggedConnected {
			return
		}
		logf("connected; %d peers", len(present))
		loggedConnected = true
	}

	const logConnectedDelay = 200 * time.Millisecond
	timer := time.AfterFunc(2*time.Second, func() {
		mu.Lock()
		defer mu.Unlock()
		logConnectedLocked()
	})
	defer timer.Stop()

	updatePeer := func(k key.Public, isPresent bool) {
		if isPresent {
			add(k)
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

	for {
		err := c.WatchConnectionChanges()
		if err != nil {
			clear()
			logf("WatchConnectionChanges: %v", err)
			time.Sleep(retryInterval)
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
				time.Sleep(retryInterval)
				break
			}
			if connGen != lastConnGen {
				lastConnGen = connGen
				clear()
			}
			switch m := m.(type) {
			case derp.PeerPresentMessage:
				updatePeer(key.Public(m), true)
			case derp.PeerGoneMessage:
				updatePeer(key.Public(m), false)
			default:
				continue
			}
			if now := time.Now(); now.Sub(lastStatus) > statusInterval {
				lastStatus = now
				logf("%d peers", len(present))
			}
		}
	}

}
