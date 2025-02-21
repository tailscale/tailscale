package tsconsensus

import (
	"context"
	"net/netip"
	"slices"
	"sync"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

type authorization struct {
	ts    *tsnet.Server
	tag   string
	peers *peers
	mu    sync.Mutex
}

func (a *authorization) refresh(ctx context.Context) error {
	lc, err := a.ts.LocalClient()
	if err != nil {
		return err
	}
	tStatus, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.peers = newPeers(tStatus)
	return nil
}

func (a *authorization) allowsHost(addr netip.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.peers.peerExists(addr, a.tag)
}

func (a *authorization) selfAllowed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.peers.status.Self.Tags != nil && slices.Contains(a.peers.status.Self.Tags.AsSlice(), a.tag)
}

func (a *authorization) allowedPeers() []*ipnstate.PeerStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.peers.allowedPeers == nil {
		return []*ipnstate.PeerStatus{}
	}
	return a.peers.allowedPeers
}

type peers struct {
	status                *ipnstate.Status
	peerByIPAddressAndTag map[netip.Addr]map[string]*ipnstate.PeerStatus
	allowedPeers          []*ipnstate.PeerStatus
}

func (ps *peers) peerExists(a netip.Addr, tag string) bool {
	byTag, ok := ps.peerByIPAddressAndTag[a]
	if !ok {
		return false
	}
	_, ok = byTag[tag]
	return ok
}

func newPeers(status *ipnstate.Status) *peers {
	ps := &peers{
		peerByIPAddressAndTag: map[netip.Addr]map[string]*ipnstate.PeerStatus{},
		status:                status,
	}
	for _, p := range status.Peer {
		for _, addr := range p.TailscaleIPs {
			if ps.peerByIPAddressAndTag[addr] == nil {
				ps.peerByIPAddressAndTag[addr] = map[string]*ipnstate.PeerStatus{}
			}
			if p.Tags != nil {
				for _, tag := range p.Tags.AsSlice() {
					ps.peerByIPAddressAndTag[addr][tag] = p
					ps.allowedPeers = append(ps.allowedPeers, p)
				}
			}
		}
	}
	return ps
}
