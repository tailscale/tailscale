// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"context"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

var retryInterval = 5 * time.Second

// testHookWatchLookConnectResult, if non-nil for tests, is called by RunWatchConnectionLoop
// with the connect result. If it returns false, the loop ends.
var testHookWatchLookConnectResult func(connectError error, wasSelfConnect bool) (keepRunning bool)

// RunWatchConnectionLoop loops until ctx is done, sending
// WatchConnectionChanges and subscribing to connection changes.
//
// If the server's public key is ignoreServerKey, RunWatchConnectionLoop
// returns.
//
// Otherwise, the add and remove funcs are called as clients come & go.
// Note that add is called for every new connection and remove is only
// called for the final disconnection. See https://github.com/tailscale/tailscale/issues/13566.
// This behavior will likely change. Callers should do their own accounting
// and dup suppression as needed.
//
// infoLogf, if non-nil, is the logger to write periodic status updates about
// how many peers are on the server. Error log output is set to the c's logger,
// regardless of infoLogf's value.
//
// To force RunWatchConnectionLoop to return quickly, its ctx needs to be
// closed, and c itself needs to be closed.
//
// It is a fatal error to call this on an already-started Client without having
// initialized Client.WatchConnectionChanges to true.
//
// If the DERP connection breaks and reconnects, remove will be called for all
// previously seen peers, with Reason type PeerGoneReasonSynthetic. Those
// clients are likely still connected and their add message will appear after
// reconnect.
func (c *Client) RunWatchConnectionLoop(ctx context.Context, ignoreServerKey key.NodePublic, infoLogf logger.Logf, add func(derp.PeerPresentMessage), remove func(derp.PeerGoneMessage)) {
	if !c.WatchConnectionChanges {
		if c.isStarted() {
			panic("invalid use of RunWatchConnectionLoop on already-started Client without setting Client.RunWatchConnectionLoop")
		}
		c.WatchConnectionChanges = true
	}
	if infoLogf == nil {
		infoLogf = logger.Discard
	}
	logf := c.logf
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
			remove(derp.PeerGoneMessage{Peer: k, Reason: derp.PeerGoneReasonMeshConnBroke})
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

	updatePeer := func(k key.NodePublic, isPresent bool) {
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
		// Make sure we're connected before calling s.ServerPublicKey.
		_, _, err := c.connect(ctx, "RunWatchConnectionLoop")
		if err != nil {
			if f := testHookWatchLookConnectResult; f != nil && !f(err, false) {
				return
			}
			logf("mesh connect: %v", err)
			sleep(retryInterval)
			continue
		}
		selfConnect := c.ServerPublicKey() == ignoreServerKey
		if f := testHookWatchLookConnectResult; f != nil && !f(err, selfConnect) {
			return
		}
		if selfConnect {
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
				add(m)
				updatePeer(m.Key, true)
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
				remove(m)
				updatePeer(m.Peer, false)
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
