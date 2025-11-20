// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ippool

import (
	"encoding/json"
	"io"
	"log"
	"maps"
	"net/netip"

	"github.com/hashicorp/raft"
	"go4.org/netipx"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
)

// Snapshot and Restore enable the raft lib to do log compaction.
// https://pkg.go.dev/github.com/hashicorp/raft#FSM

// Snapshot is part of the raft.FSM interface.
// According to the docs it:
//   - should return quickly
//   - will not be called concurrently with Apply
//   - the snapshot returned will have Persist called on it concurrently with Apply
//     (so it should not contain pointers to the original data that's being mutated)
func (ipp *ConsensusIPPool) Snapshot() (raft.FSMSnapshot, error) {
	// everything is safe for concurrent reads and this is not called concurrently with Apply which is
	// the only thing that writes, so we do not need to lock
	return ipp.getPersistable(), nil
}

type persistableIPSet struct {
	Ranges []persistableIPRange
}

func getPersistableIPSet(i *netipx.IPSet) persistableIPSet {
	rs := []persistableIPRange{}
	for _, r := range i.Ranges() {
		rs = append(rs, getPersistableIPRange(r))
	}
	return persistableIPSet{Ranges: rs}
}

func (mips *persistableIPSet) toIPSet() (*netipx.IPSet, error) {
	b := netipx.IPSetBuilder{}
	for _, r := range mips.Ranges {
		b.AddRange(r.toIPRange())
	}
	return b.IPSet()
}

type persistableIPRange struct {
	From netip.Addr
	To   netip.Addr
}

func getPersistableIPRange(r netipx.IPRange) persistableIPRange {
	return persistableIPRange{
		From: r.From(),
		To:   r.To(),
	}
}

func (mipr *persistableIPRange) toIPRange() netipx.IPRange {
	return netipx.IPRangeFrom(mipr.From, mipr.To)
}

// Restore is part of the raft.FSM interface.
// According to the docs it:
//   - will not be called concurrently with any other command
//   - the FSM must discard all previous state before restoring
func (ipp *ConsensusIPPool) Restore(rc io.ReadCloser) error {
	var snap fsmSnapshot
	if err := json.NewDecoder(rc).Decode(&snap); err != nil {
		return err
	}
	ipset, ppm, err := snap.getData()
	if err != nil {
		return err
	}
	ipp.IPSet = ipset
	ipp.perPeerMap = ppm
	return nil
}

type fsmSnapshot struct {
	IPSet      persistableIPSet
	PerPeerMap map[tailcfg.NodeID]persistablePPS
}

// Persist is part of the raft.FSMSnapshot interface
// According to the docs Persist may be called concurrently with Apply
func (f fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	if err := json.NewEncoder(sink).Encode(f); err != nil {
		log.Printf("Error encoding snapshot as JSON: %v", err)
		return sink.Cancel()
	}
	return sink.Close()
}

// Release is part of the raft.FSMSnapshot interface
func (f fsmSnapshot) Release() {}

// getPersistable returns an object that:
//   - contains all the data in ConsensusIPPool
//   - doesn't share any pointers with it
//   - can be marshalled to JSON
//
// part of the raft snapshotting, getPersistable will be called during Snapshot
// and the results used during persist (concurrently with Apply)
func (ipp *ConsensusIPPool) getPersistable() fsmSnapshot {
	ppm := map[tailcfg.NodeID]persistablePPS{}
	for k, v := range ipp.perPeerMap.All() {
		ppm[k] = v.getPersistable()
	}
	return fsmSnapshot{
		IPSet:      getPersistableIPSet(ipp.IPSet),
		PerPeerMap: ppm,
	}
}

func (f fsmSnapshot) getData() (*netipx.IPSet, *syncs.Map[tailcfg.NodeID, *consensusPerPeerState], error) {
	ppm := syncs.Map[tailcfg.NodeID, *consensusPerPeerState]{}
	for k, v := range f.PerPeerMap {
		ppm.Store(k, v.toPerPeerState())
	}
	ipset, err := f.IPSet.toIPSet()
	if err != nil {
		return nil, nil, err
	}
	return ipset, &ppm, nil
}

// getPersistable returns an object that:
//   - contains all the data in consensusPerPeerState
//   - doesn't share any pointers with it
//   - can be marshalled to JSON
//
// part of the raft snapshotting, getPersistable will be called during Snapshot
// and the results used during persist (concurrently with Apply)
func (ps *consensusPerPeerState) getPersistable() persistablePPS {
	return persistablePPS{
		AddrToDomain: maps.Collect(ps.addrToDomain.All()),
		DomainToAddr: maps.Clone(ps.domainToAddr),
	}
}

type persistablePPS struct {
	DomainToAddr map[string]netip.Addr
	AddrToDomain map[netip.Addr]whereWhen
}

func (p persistablePPS) toPerPeerState() *consensusPerPeerState {
	atd := &syncs.Map[netip.Addr, whereWhen]{}
	for k, v := range p.AddrToDomain {
		atd.Store(k, v)
	}
	return &consensusPerPeerState{
		domainToAddr: p.DomainToAddr,
		addrToDomain: atd,
	}
}
