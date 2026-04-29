// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/magicsock"
)

// newCacheTestNetmap returns a minimal valid netmap suitable for testing disk
// cache operations.
func newCacheTestNetmap() *netmap.NetworkMap {
	return &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			Name: "test-node.ts.net",
			User: tailcfg.UserID(1),
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
			},
		}).View(),
		UserProfiles: map[tailcfg.UserID]tailcfg.UserProfileView{
			tailcfg.UserID(1): (&tailcfg.UserProfile{
				LoginName:   "user@example.com",
				DisplayName: "Test User",
			}).View(),
		},
		DERPMap: &tailcfg.DERPMap{
			Regions: map[int]*tailcfg.DERPRegion{
				1:  {},
				2:  {},
				3:  {},
				4:  {},
				5:  {},
				6:  {},
				7:  {},
				8:  {},
				9:  {},
				10: {},
				11: {},
			},
		},
	}
}

func TestWriteAndLoadHomeDERP(t *testing.T) {
	b := newTestBackend(t)

	nm := newCacheTestNetmap()
	b.currentNode().SetNetMap(nm)

	const wantDERP = 7
	b.currentNode().homeDERP.Store(wantDERP)

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.writeNetmapToDiskLocked(nm); err != nil {
		t.Fatalf("writeNetmapToDiskLocked: %v", err)
	}

	loaded, ok := b.loadDiskCacheLocked()
	if !ok {
		t.Fatal("loadDiskCacheLocked returned ok=false")
	}
	if !loaded.SelfNode.Valid() {
		t.Fatal("loaded netmap SelfNode is invalid")
	}
	if got := loaded.SelfNode.HomeDERP(); got != wantDERP {
		t.Errorf("loaded SelfNode.HomeDERP() = %d, want %d", got, wantDERP)
	}
}

func TestOnHomeDERPUpdate(t *testing.T) {
	t.Run("normal_derp_change", func(t *testing.T) {
		b := newTestBackend(t)
		done := make(chan struct{})
		tstest.Replace(t, &testOnlyHomeDERPUpdate, func() { close(done) })

		nm := newCacheTestNetmap()
		b.currentNode().SetNetMap(nm)

		// Publish a HomeDERPChanged event via the backend's event bus.
		bus := b.Sys().Bus.Get()
		ec := bus.Client("test.TestOnHomeDERPUpdate")
		pub := eventbus.Publish[magicsock.HomeDERPChanged](ec)

		const wantDERP = 11
		pub.Publish(magicsock.HomeDERPChanged{Old: 0, New: wantDERP})
		<-done

		if got := b.currentNode().homeDERP.Load(); got != wantDERP {
			t.Errorf("b.homeDERP = %d, want %d", got, wantDERP)
		}

		// Verify the value was persisted to the disk cache.
		b.mu.Lock()
		defer b.mu.Unlock()
		loaded, ok := b.loadDiskCacheLocked()
		if !ok {
			t.Fatal("loadDiskCacheLocked returned ok=false after homeDERP update")
		}
		if got := loaded.SelfNode.HomeDERP(); got != wantDERP {
			t.Errorf("cached SelfNode.HomeDERP() = %d, want %d", got, wantDERP)
		}
	})
	t.Run("old_does_not_match", func(t *testing.T) {
		b := newTestBackend(t)
		done := make(chan struct{})
		tstest.Replace(t, &testOnlyHomeDERPUpdate, func() { close(done) })

		const setDERP = 11
		const wantDERP = 4

		nm := newCacheTestNetmap()
		selfNode := nm.SelfNode.AsStruct()
		selfNode.HomeDERP = wantDERP
		nm.SelfNode = selfNode.View()
		b.currentNode().SetNetMap(nm)
		b.currentNode().homeDERP.Store(wantDERP)

		// Write an initial cache entry so we can verify it is not overwritten.
		b.mu.Lock()
		if err := b.writeNetmapToDiskLocked(nm); err != nil {
			b.mu.Unlock()
			t.Fatalf("setup writeNetmapToDiskLocked: %v", err)
		}
		b.mu.Unlock()

		// Publish a HomeDERPChanged event via the backend's event bus.
		bus := b.Sys().Bus.Get()
		ec := bus.Client("test.TestOnHomeDERPUpdate")
		pub := eventbus.Publish[magicsock.HomeDERPChanged](ec)
		pub.Publish(magicsock.HomeDERPChanged{Old: wantDERP + 1, New: setDERP})
		<-done

		if got := b.currentNode().homeDERP.Load(); got != wantDERP {
			t.Errorf("b.homeDERP = %d, wanted no change %d", got, wantDERP)
		}

		// Verify the cache still exists and still holds the original value.
		b.mu.Lock()
		defer b.mu.Unlock()
		loaded, ok := b.loadDiskCacheLocked()
		if !ok {
			t.Fatal("loadDiskCacheLocked returned ok=false; expected cache to still exist")
		}
		if got := loaded.SelfNode.HomeDERP(); got != wantDERP {
			t.Errorf("cached SelfNode.HomeDERP() = %d after rejected event, want original %d", got, wantDERP)
		}
	})
	t.Run("new_does_not_exist_in_map", func(t *testing.T) {
		b := newTestBackend(t)
		done := make(chan struct{})
		tstest.Replace(t, &testOnlyHomeDERPUpdate, func() { close(done) })

		const setDERP = 111
		const wantDERP = 4

		nm := newCacheTestNetmap()
		selfNode := nm.SelfNode.AsStruct()
		selfNode.HomeDERP = wantDERP
		nm.SelfNode = selfNode.View()
		b.currentNode().SetNetMap(nm)
		b.currentNode().homeDERP.Store(wantDERP)

		// Write an initial cache entry so we can verify it is not overwritten.
		b.mu.Lock()
		if err := b.writeNetmapToDiskLocked(nm); err != nil {
			b.mu.Unlock()
			t.Fatalf("setup writeNetmapToDiskLocked: %v", err)
		}
		b.mu.Unlock()

		// Publish a HomeDERPChanged event via the backend's event bus.
		// Old matches the stored homeDERP so only the "new region not in map"
		// guard is exercised.
		bus := b.Sys().Bus.Get()
		ec := bus.Client("test.TestOnHomeDERPUpdate")
		pub := eventbus.Publish[magicsock.HomeDERPChanged](ec)
		pub.Publish(magicsock.HomeDERPChanged{Old: wantDERP, New: setDERP})
		<-done

		if got := b.currentNode().homeDERP.Load(); got != wantDERP {
			t.Errorf("b.homeDERP = %d, wanted no change %d", got, wantDERP)
		}

		// Verify the cache still exists and still holds the original value.
		b.mu.Lock()
		defer b.mu.Unlock()
		loaded, ok := b.loadDiskCacheLocked()
		if !ok {
			t.Fatal("loadDiskCacheLocked returned ok=false; expected cache to still exist")
		}
		if got := loaded.SelfNode.HomeDERP(); got != wantDERP {
			t.Errorf("cached SelfNode.HomeDERP() = %d after rejected event, want original %d", got, wantDERP)
		}
	})
}

func TestWriteNetmapDoesNotMutateOriginal(t *testing.T) {
	b := newTestBackend(t)

	nm := newCacheTestNetmap()
	b.currentNode().SetNetMap(nm)

	originalDERP := nm.SelfNode.HomeDERP() // expected to be 0 initially

	const storeDERP = 5
	b.currentNode().homeDERP.Store(storeDERP)

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.writeNetmapToDiskLocked(nm); err != nil {
		t.Fatalf("writeNetmapToDiskLocked: %v", err)
	}

	// The original netmap must not have been mutated.
	if got := nm.SelfNode.HomeDERP(); got != originalDERP {
		t.Errorf("original nm.SelfNode.HomeDERP() = %d after write, want %d (original was mutated)", got, originalDERP)
	}
}
