// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsconsensus

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
	"tailscale.com/types/views"
	"tailscale.com/util/set"
)

type statusGetter interface {
	getStatus(context.Context) (*ipnstate.Status, error)
}

type tailscaleStatusGetter struct {
	ts *tsnet.Server
}

func (sg tailscaleStatusGetter) getStatus(ctx context.Context) (*ipnstate.Status, error) {
	lc, err := sg.ts.LocalClient()
	if err != nil {
		return nil, err
	}
	return lc.Status(ctx)
}

type authorization struct {
	sg  statusGetter
	tag string

	mu    sync.Mutex
	peers *peers // protected by mu
}

func newAuthorization(ts *tsnet.Server, tag string) *authorization {
	return &authorization{
		sg: tailscaleStatusGetter{
			ts: ts,
		},
		tag: tag,
	}
}

func (a *authorization) refresh(ctx context.Context) error {
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

func (a *authorization) allowsHost(addr netip.Addr) bool {
	if a.peers == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.peers.peerExists(addr, a.tag)
}

func (a *authorization) selfAllowed() bool {
	if a.peers == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.peers.status.Self.Tags != nil && slices.Contains(a.peers.status.Self.Tags.AsSlice(), a.tag)
}

func (a *authorization) allowedPeers() views.Slice[*ipnstate.PeerStatus] {
	if a.peers == nil {
		return views.SliceOf([]*ipnstate.PeerStatus{})
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return views.SliceOf(a.peers.allowedPeers)
}

type peers struct {
	status             *ipnstate.Status
	allowedRemoteAddrs set.Set[netip.Addr]
	allowedPeers       []*ipnstate.PeerStatus
}

func (ps *peers) peerExists(a netip.Addr, tag string) bool {
	return ps.allowedRemoteAddrs.Contains(a)
}

func newPeers(status *ipnstate.Status, tag string) *peers {
	ps := &peers{
		status:             status,
		allowedRemoteAddrs: set.Set[netip.Addr]{},
	}
	for _, p := range status.Peer {
		if p.Tags != nil && p.Tags.ContainsFunc(func(s string) bool {
			return s == tag
		}) {
			ps.allowedPeers = append(ps.allowedPeers, p)
			for _, addr := range p.TailscaleIPs {
				ps.allowedRemoteAddrs.Add(addr)
			}
		}
	}
	return ps
}
