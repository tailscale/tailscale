// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"bufio"
	"bytes"
	"fmt"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/envknob"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
)

const peerCacheDisableEnv = "TS_DEBUG_DERP_DISABLE_PEER_CACHE"

func setPeerCacheDisabled(tb testing.TB, disabled bool) {
	tb.Helper()
	envknob.Setenv(peerCacheDisableEnv, fmt.Sprint(disabled))
	tb.Cleanup(func() { envknob.Setenv(peerCacheDisableEnv, "") })
}

func TestLookupDestCachesLocalClient(t *testing.T) {
	setPeerCacheDisabled(t, false)

	s := &Server{
		clients:     map[key.NodePublic]*clientSet{},
		clientsMesh: map[key.NodePublic]PacketForwarder{},
		clock:       tstime.StdClock{},
	}
	src := pubAll(1)
	dst := pubAll(2)
	dstClient := &sclient{key: dst}
	cs := &clientSet{}
	cs.activeClient.Store(dstClient)
	s.clients[dst] = cs

	c := &sclient{s: s, key: src}
	got, fwd, dstLen := c.lookupDest(dst)
	if got != dstClient || fwd != nil || dstLen != 1 {
		t.Fatalf("lookupDest = (%v, %v, %d), want (%v, nil, 1)", got, fwd, dstLen, dstClient)
	}
	if got := s.peerLookupCacheMisses.Value(); got != 1 {
		t.Fatalf("peerLookupCacheMisses = %d, want 1", got)
	}
	if c.peerCache.Len() != 1 {
		t.Fatalf("peerCache.Len = %d, want 1", c.peerCache.Len())
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	done := make(chan *sclient, 1)
	go func() {
		got, _, _ := c.lookupDest(dst)
		done <- got
	}()
	select {
	case got := <-done:
		if got != dstClient {
			t.Fatalf("cached lookupDest got %v, want %v", got, dstClient)
		}
		if got := s.peerLookupCacheMisses.Value(); got != 1 {
			t.Fatalf("peerLookupCacheMisses = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("cached lookupDest blocked on Server.mu")
	}
}

func TestSetPeerCacheConfig(t *testing.T) {
	s := &Server{}
	if got := s.peerCacheConfig.effectiveMaxEntries(); got != DefaultPeerCacheMaxEntries {
		t.Fatalf("maxEntries = %d, want %d", got, DefaultPeerCacheMaxEntries)
	}
	if got := s.peerCacheConfig.effectiveMaxIdle(); got != DefaultPeerCacheMaxIdle {
		t.Fatalf("maxIdle = %v, want %v", got, DefaultPeerCacheMaxIdle)
	}
	if got := s.peerCacheConfig.effectiveLastUsedUpdateEvery(); got != defaultPeerCacheLastUsedUpdateInterval {
		t.Fatalf("lastUsedUpdateEvery = %v, want %v", got, defaultPeerCacheLastUsedUpdateInterval)
	}
	if !s.peerCacheEnabled() {
		t.Fatal("peer cache is disabled with default config")
	}

	s.SetPeerCacheConfig(-1, 0)
	if s.peerCacheEnabled() {
		t.Fatal("peer cache is enabled with maxEntries=-1")
	}

	const maxIdle = 2 * time.Second
	s.SetPeerCacheConfig(8, maxIdle)
	if got := s.peerCacheConfig.effectiveMaxEntries(); got != 8 {
		t.Fatalf("maxEntries = %d, want 8", got)
	}
	if got := s.peerCacheConfig.effectiveMaxIdle(); got != maxIdle {
		t.Fatalf("maxIdle = %v, want %v", got, maxIdle)
	}
	if got := s.peerCacheConfig.effectiveLastUsedUpdateEvery(); got != maxIdle {
		t.Fatalf("lastUsedUpdateEvery = %v, want %v", got, maxIdle)
	}
}

func TestLookupDestDoesNotCacheForwardersOrMisses(t *testing.T) {
	setPeerCacheDisabled(t, false)

	s := &Server{
		clients:     map[key.NodePublic]*clientSet{},
		clientsMesh: map[key.NodePublic]PacketForwarder{},
		clock:       tstime.StdClock{},
	}
	src := pubAll(1)
	dst := pubAll(2)
	c := &sclient{s: s, key: src}

	s.clientsMesh[dst] = testFwd(1)
	got, fwd, dstLen := c.lookupDest(dst)
	if got != nil || fwd != testFwd(1) || dstLen != 0 {
		t.Fatalf("lookupDest = (%v, %v, %d), want (nil, testFwd(1), 0)", got, fwd, dstLen)
	}
	if c.peerCache.Len() != 0 {
		t.Fatalf("peerCache.Len = %d, want 0", c.peerCache.Len())
	}

	s.clientsMesh[dst] = testFwd(2)
	got, fwd, dstLen = c.lookupDest(dst)
	if got != nil || fwd != testFwd(2) || dstLen != 0 {
		t.Fatalf("lookupDest after forwarder update = (%v, %v, %d), want (nil, testFwd(2), 0)", got, fwd, dstLen)
	}
}

func TestLookupDestRevalidatesStaleCachedClientSet(t *testing.T) {
	setPeerCacheDisabled(t, false)

	s := &Server{
		clients:     map[key.NodePublic]*clientSet{},
		clientsMesh: map[key.NodePublic]PacketForwarder{},
		clock:       tstime.StdClock{},
	}
	src := pubAll(1)
	dst := pubAll(2)
	c := &sclient{s: s, key: src}

	oldSet := &clientSet{}
	now := s.clock.Now()
	c.peerCache.Set(dst, cachedPeer{cs: oldSet, lastUsed: &now})

	newClient := &sclient{key: dst}
	newSet := &clientSet{}
	newSet.activeClient.Store(newClient)
	s.clients[dst] = newSet

	got, fwd, dstLen := c.lookupDest(dst)
	if got != newClient || fwd != nil || dstLen != 1 {
		t.Fatalf("lookupDest = (%v, %v, %d), want (%v, nil, 1)", got, fwd, dstLen, newClient)
	}
}

func TestLookupDestUpdatesCachedPeerLastUsedCoarsely(t *testing.T) {
	setPeerCacheDisabled(t, false)

	clock := tstest.NewClock(tstest.ClockOpts{})
	s := &Server{
		clients:     map[key.NodePublic]*clientSet{},
		clientsMesh: map[key.NodePublic]PacketForwarder{},
		clock:       clock,
	}
	src := pubAll(1)
	dst := pubAll(2)
	dstClient := &sclient{key: dst}
	cs := &clientSet{}
	cs.activeClient.Store(dstClient)
	s.clients[dst] = cs

	c := &sclient{s: s, key: src}
	if got, _, _ := c.lookupDest(dst); got != dstClient {
		t.Fatalf("lookupDest got %v, want %v", got, dstClient)
	}
	peer, ok := c.peerCache.PeekOk(dst)
	if !ok {
		t.Fatal("peer cache is empty")
	}
	firstLastUsed := *peer.lastUsed

	clock.Advance(defaultPeerCacheLastUsedUpdateInterval / 2)
	if got, _, _ := c.lookupDest(dst); got != dstClient {
		t.Fatalf("lookupDest got %v, want %v", got, dstClient)
	}
	if got := *peer.lastUsed; !got.Equal(firstLastUsed) {
		t.Fatalf("lastUsed updated too soon: got %v, want %v", got, firstLastUsed)
	}

	clock.Advance(defaultPeerCacheLastUsedUpdateInterval)
	if got, _, _ := c.lookupDest(dst); got != dstClient {
		t.Fatalf("lookupDest got %v, want %v", got, dstClient)
	}
	if got := *peer.lastUsed; !got.After(firstLastUsed) {
		t.Fatalf("lastUsed was not refreshed: got %v, want after %v", got, firstLastUsed)
	}
}

func TestCleanPeerCacheRemovesIdlePeers(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{})
	s := &Server{clock: clock}
	c := &sclient{s: s}

	freshTime := clock.Now()
	staleTime := freshTime.Add(-DefaultPeerCacheMaxIdle - time.Second)
	freshKey := pubAll(1)
	staleKey := pubAll(2)
	c.peerCache.Set(freshKey, cachedPeer{cs: &clientSet{}, lastUsed: &freshTime})
	c.peerCache.Set(staleKey, cachedPeer{cs: &clientSet{}, lastUsed: &staleTime})

	c.cleanPeerCache()
	if _, ok := c.peerCache.PeekOk(staleKey); ok {
		t.Fatal("stale peer cache entry was not removed")
	}
	if _, ok := c.peerCache.PeekOk(freshKey); !ok {
		t.Fatal("fresh peer cache entry was removed")
	}
}

func TestPeerCacheCleanedOnPing(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{})
	s := &Server{clock: clock}
	c := &sclient{s: s}

	staleTime := clock.Now().Add(-DefaultPeerCacheMaxIdle - time.Second)
	staleKey := pubAll(1)
	c.peerCache.Set(staleKey, cachedPeer{cs: &clientSet{}, lastUsed: &staleTime})
	c.br = bufio.NewReader(bytes.NewReader(make([]byte, len(derp.PingMessage{}))))
	c.sendPongCh = make(chan [8]byte, 1)
	if err := c.handleFramePing(derp.FramePing, uint32(len(derp.PingMessage{}))); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.peerCache.PeekOk(staleKey); ok {
		t.Fatal("stale peer cache entry was not removed")
	}
}

func BenchmarkLookupDestPeerCache(b *testing.B) {
	s := &Server{
		clients:     map[key.NodePublic]*clientSet{},
		clientsMesh: map[key.NodePublic]PacketForwarder{},
		clock:       tstime.StdClock{},
	}
	var dstKeys [4]key.NodePublic
	var dstClients [4]*sclient
	for i := range dstKeys {
		dstKeys[i] = pubAll(byte(i + 2))
		dstClients[i] = &sclient{key: dstKeys[i]}
		cs := &clientSet{}
		cs.activeClient.Store(dstClients[i])
		s.clients[dstKeys[i]] = cs
	}

	b.ReportAllocs()
	b.SetParallelism(32)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		c := &sclient{s: s, key: pubAll(1)}
		var i int
		for pb.Next() {
			idx := i & (len(dstKeys) - 1)
			got, fwd, dstLen := c.lookupDest(dstKeys[idx])
			if got != dstClients[idx] || fwd != nil {
				b.Fatalf("lookupDest = (%v, %v, %d), want (%v, nil, _)", got, fwd, dstLen, dstClients[idx])
			}
			i++
		}
	})
}
