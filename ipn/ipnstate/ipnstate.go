// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ipnstate captures the entire state of the Tailscale network.
//
// It's a leaf package so both ipn, wgengine, and magicsock can all depend on it.
package ipnstate

import (
	"bytes"
	"log"
	"sort"
	"sync"
	"time"

	"tailscale.com/types/key"
)

// Status represents the entire state of the IPN network.
type Status struct {
	BackendState string
	Peer         map[key.Public]*PeerStatus
}

func (s *Status) Peers() []key.Public {
	kk := make([]key.Public, 0, len(s.Peer))
	for k := range s.Peer {
		kk = append(kk, k)
	}
	sort.Slice(kk, func(i, j int) bool { return bytes.Compare(kk[i][:], kk[j][:]) < 0 })
	return kk
}

type PeerStatus struct {
	PublicKey     key.Public
	HostName      string // HostInfo's Hostname (not a DNS name or necessarily unique)
	OS            string // HostInfo.OS
	Addrs         []string
	CurAddr       string // one of Addrs, or unique if roaming
	RxBytes       int64
	TxBytes       int64
	Created       time.Time // time registered with tailcontrol
	LastSeen      time.Time // last seen to tailcontrol
	LastHandshake time.Time // with local wireguard
	KeepAlive     bool
	InNetworkMap  bool
	InMagicSock   bool
	InEngine      bool
}

type StatusBuilder struct {
	mu     sync.Mutex
	locked bool
	st     Status
}

func (sb *StatusBuilder) Status() *Status {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.locked = true
	return &sb.st
}

func (sb *StatusBuilder) AddPeer(peer key.Public, st *PeerStatus) {
	if st == nil {
		panic("nil PeerStatus")
	}

	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.locked {
		log.Printf("[unexpected] ipnstate: AddPeer after Locked")
		return
	}

	if sb.st.Peer == nil {
		sb.st.Peer = make(map[key.Public]*PeerStatus)
	}
	e, ok := sb.st.Peer[peer]
	if !ok {
		sb.st.Peer[peer] = st
		st.PublicKey = peer
		return
	}

	if st.HostName != "" {
		e.HostName = st.HostName
	}
	if st.OS != "" {
		e.OS = st.OS
	}
	if st.Addrs != nil {
		e.Addrs = st.Addrs
	}
	if st.CurAddr != "" {
		e.CurAddr = st.CurAddr
	}
	if st.RxBytes != 0 {
		e.RxBytes = st.RxBytes
	}
	if st.TxBytes != 0 {
		e.TxBytes = st.TxBytes
	}
	if t := st.LastHandshake; !t.IsZero() {
		e.LastHandshake = t
	}
	if t := st.Created; !t.IsZero() {
		e.Created = t
	}
	if t := st.LastSeen; !t.IsZero() {
		e.LastSeen = t
	}
	if st.InNetworkMap {
		e.InNetworkMap = true
	}
	if st.InMagicSock {
		e.InMagicSock = true
	}
	if st.InEngine {
		e.InEngine = true
	}
	if st.KeepAlive {
		e.KeepAlive = true
	}
}

type StatusUpdater interface {
	UpdateStatus(*StatusBuilder)
}
