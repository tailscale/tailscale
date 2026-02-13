// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsconsensus

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
	"tailscale.com/types/views"
	"tailscale.com/util/set"
)

// defaultStatusCacheTimeout is the duration after which cached status will be
// disregarded. See tailscaleStatusGetter.cacheTimeout.
const defaultStatusCacheTimeout = time.Second

type statusGetter interface {
	getStatus(context.Context) (*ipnstate.Status, error)
}

type tailscaleStatusGetter struct {
	ts *tsnet.Server

	// cacheTimeout is used to determine when the cached status should be
	// disregarded and a new status fetched. Zero means ignore the cache.
	cacheTimeout time.Duration

	mu             sync.Mutex // protects the following
	lastStatus     *ipnstate.Status
	lastStatusTime time.Time
}

func (sg *tailscaleStatusGetter) fetchStatus(ctx context.Context) (*ipnstate.Status, error) {
	lc, err := sg.ts.LocalClient()
	if err != nil {
		return nil, err
	}
	return lc.Status(ctx)
}

func (sg *tailscaleStatusGetter) getStatus(ctx context.Context) (*ipnstate.Status, error) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	if sg.lastStatus != nil && time.Since(sg.lastStatusTime) < sg.cacheTimeout {
		return sg.lastStatus, nil
	}
	status, err := sg.fetchStatus(ctx)
	if err != nil {
		return nil, err
	}
	sg.lastStatus = status
	sg.lastStatusTime = time.Now()
	return status, nil
}

type authorization struct {
	sg  statusGetter
	tag string

	mu    sync.Mutex
	peers *peers // protected by mu
}

func newAuthorization(ts *tsnet.Server, tag string) *authorization {
	return newAuthorizationWithCacheTimeout(ts, tag, defaultStatusCacheTimeout)
}

func newAuthorizationWithCacheTimeout(ts *tsnet.Server, tag string, cacheTimeout time.Duration) *authorization {
	return &authorization{
		sg: &tailscaleStatusGetter{
			ts:           ts,
			cacheTimeout: cacheTimeout,
		},
		tag: tag,
	}
}

func newAuthorizationForTest(ts *tsnet.Server, tag string) *authorization {
	return newAuthorizationWithCacheTimeout(ts, tag, 0)
}

func (a *authorization) Refresh(ctx context.Context) error {
	tStatus, err := a.sg.getStatus(ctx)
	if err != nil {
		return err
	}
	if tStatus == nil {
		return errors.New("no status")
	}
	if tStatus.BackendState != ipn.Running.String() {
		return errors.New("ts Server is not running")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.peers = newPeers(tStatus, a.tag)
	return nil
}

func (a *authorization) AllowsHost(addr netip.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.peers == nil {
		return false
	}
	return a.peers.addrs.Contains(addr)
}

func (a *authorization) SelfAllowed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.peers == nil {
		return false
	}
	return a.peers.status.Self.Tags != nil && views.SliceContains(*a.peers.status.Self.Tags, a.tag)
}

func (a *authorization) AllowedPeers() views.Slice[*ipnstate.PeerStatus] {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.peers == nil {
		return views.Slice[*ipnstate.PeerStatus]{}
	}
	return views.SliceOf(a.peers.statuses)
}

type peers struct {
	status   *ipnstate.Status
	addrs    set.Set[netip.Addr]
	statuses []*ipnstate.PeerStatus
}

func newPeers(status *ipnstate.Status, tag string) *peers {
	ps := &peers{
		status: status,
		addrs:  set.Set[netip.Addr]{},
	}
	for _, p := range status.Peer {
		if p.Tags != nil && views.SliceContains(*p.Tags, tag) {
			ps.statuses = append(ps.statuses, p)
			ps.addrs.AddSlice(p.TailscaleIPs)
		}
	}
	return ps
}
