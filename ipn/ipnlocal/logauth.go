// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"fmt"
	"sync"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/mak"
)

type logAuthID string
type logAuthToken string

// logAuthCache caches log upload auth tokens keyed by auth ID ("nodeid:<nodeID>").
// Tokens arrive proactively from control via [tailcfg.NodeAttrLogUploadAuth]
// on netmap updates; the client does not refresh them itself.
//
// All methods are safe for concurrent use.
type logAuthCache struct {
	logf logger.Logf

	mu     sync.Mutex
	tokens map[logAuthID]logAuthToken
}

// storeToken stores token for authID.
func (c *logAuthCache) storeToken(id logAuthID, tok logAuthToken) {
	if id == "" || tok == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	mak.Set(&c.tokens, id, tok)
}

// loadToken returns the cached bearer token for authID, or "" if none.
// An empty result means the uploader proceeds unauthenticated (matching
// historical logtail behavior when no auth is available).
func (c *logAuthCache) loadToken(id logAuthID) logAuthToken {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tokens[id]
}

// updateLogUploadAuth applies netmap-driven log upload authentication
// to the main tailscaled [logtail.Logger] and updates the token cache.
//
// When nm is nil or lacks a self node, new log entries are stamped with an
// empty auth ID, but previously cached tokens are retained so buffered logs
// from the prior node can still upload with Authorization.
//
// When CapMap carries [tailcfg.NodeAttrLogUploadAuth], the token is cached.
// Control is expected to push a refreshed token via netmap
// before the previous one expires.
//
// Even when a new auth token arrives as a concise netmap delta
// with just the self CapMap for the [tailcfg.NodeAttrLogUploadAuth],
// the LocalBackend still triggers a full netmap install.
// Note that peer deltas cannot carry this attribute.
func (b *LocalBackend) updateLogUploadAuth(nm *netmap.NetworkMap) {
	if !buildfeatures.HasLogTail {
		return
	}

	lg := b.logUploader
	if lg == nil || nm == nil || !nm.SelfNode.Valid() {
		if lg != nil {
			lg.SetAuthID("")
		}
		return
	}

	// Configure the logger to log under the context of the current node.
	authID := formatAuthID(nm.SelfNode.ID())
	lg.SetAuthID(string(authID))
	lg.RegisterAuthToken(string(authID), func() string {
		return string(b.logAuth.loadToken(authID))
	})

	// Cache any token provided in the netmap CapMap.
	tokens, err := tailcfg.UnmarshalNodeCapViewJSON[string](nm.SelfNode.CapMap(), tailcfg.NodeAttrLogUploadAuth)
	if err != nil {
		b.logf("logauth: CapMap %s: %v", tailcfg.NodeAttrLogUploadAuth, err)
		return
	}
	for _, tok := range tokens {
		if tok != "" {
			b.logAuth.storeToken(authID, logAuthToken(tok))
		}
	}
}

// formatAuthID returns the canonical auth ID for authenticated log uploads:
// "nodeid:<nodeID>". A node ID change implies a tailnet change, so the auth ID
// does not include a separate tailnet component.
func formatAuthID(nodeID tailcfg.NodeID) logAuthID {
	return logAuthID(fmt.Sprintf("nodeid:%d", nodeID))
}
