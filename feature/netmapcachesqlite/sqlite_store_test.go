// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netmapcachesqlite && !ts_omit_cachenetmap

package netmapcachesqlite

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"tailscale.com/ipn/ipnlocal/netmapcache"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/netmap"
	"tailscale.com/util/set"
)

func TestStoreContract(t *testing.T) {
	newTestStore := func(t *testing.T) netmapcache.Store {
		t.Helper()
		store, err := newStore(t.Context(), t.TempDir(), t.Logf)
		if err != nil {
			t.Fatalf("create store: %v", err)
		}
		t.Cleanup(func() { store.Close(t.Context()) })
		return store
	}

	t.Run("StoreAndLoad", func(t *testing.T) {
		store := newTestStore(t)
		want := []byte("kind of blue")
		if err := store.Store(t.Context(), "k", want); err != nil {
			t.Fatalf("store value: %v", err)
		}
		got, err := store.Load(t.Context(), "k")
		if err != nil {
			t.Fatalf("load value: %v", err)
		}
		if string(got) != string(want) {
			t.Errorf("Load = %q, want %q", got, want)
		}
	})

	t.Run("LoadMissing", func(t *testing.T) {
		store := newTestStore(t)
		_, err := store.Load(t.Context(), "miles-dovis")
		if !errors.Is(err, netmapcache.ErrKeyNotFound) {
			t.Errorf("Load missing key: got err %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("Overwrite", func(t *testing.T) {
		store := newTestStore(t)
		v1 := []byte("so what")
		v2 := []byte("all blues")
		if err := store.Store(t.Context(), "k", v1); err != nil {
			t.Fatalf("store initial value: %v", err)
		}
		if err := store.Store(t.Context(), "k", v2); err != nil {
			t.Fatalf("store replacement value: %v", err)
		}
		got, err := store.Load(t.Context(), "k")
		if err != nil {
			t.Fatalf("load after overwrite: %v", err)
		}
		if string(got) != string(v2) {
			t.Errorf("Load after overwrite = %q, want %q", got, v2)
		}
	})

	t.Run("OverwriteSameContent", func(t *testing.T) {
		store := newTestStore(t)
		v := []byte("so what")
		if err := store.Store(t.Context(), "k", v); err != nil {
			t.Fatalf("store initial value: %v", err)
		}
		if err := store.Store(t.Context(), "k", v); err != nil {
			t.Fatalf("store same value again: %v", err)
		}
		got, err := store.Load(t.Context(), "k")
		if err != nil {
			t.Fatalf("load after same-content overwrite: %v", err)
		}
		if string(got) != string(v) {
			t.Errorf("Load after same-content overwrite = %q, want %q", got, v)
		}
	})

	t.Run("Remove", func(t *testing.T) {
		store := newTestStore(t)
		v := []byte("all blues")
		if err := store.Store(t.Context(), "k", v); err != nil {
			t.Fatalf("store initial value: %v", err)
		}
		got, err := store.Load(t.Context(), "k")
		if err != nil {
			t.Fatalf("load initial value: %v", err)
		} else if string(got) != string(v) {
			t.Fatalf("load initial value = %q, want %q", got, v)
		}
		if err := store.Remove(t.Context(), "k"); err != nil {
			t.Fatalf("remove key: %v", err)
		}
		_, err = store.Load(t.Context(), "k")
		if !errors.Is(err, netmapcache.ErrKeyNotFound) {
			t.Errorf("Load after Remove: got err %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("RemoveMissing", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Remove(t.Context(), "nonexistent-key"); err != nil {
			t.Errorf("Remove nonexistent key: got %v, want nil", err)
		}
	})

	t.Run("ListEmpty", func(t *testing.T) {
		store := newTestStore(t)
		var got []string
		for key, err := range store.List(t.Context(), "") {
			if err != nil {
				t.Fatalf("list all keys: %v", err)
			}
			got = append(got, key)
		}
		if len(got) != 0 {
			t.Errorf("List empty store: got %v, want nothing", got)
		}
	})

	t.Run("ListPrefix", func(t *testing.T) {
		store := newTestStore(t)
		for _, kv := range []struct{ k, v string }{
			{"peer-a", "va"},
			{"peer-b", "vb"},
			{"user-x", "vx"},
		} {
			if err := store.Store(t.Context(), kv.k, []byte(kv.v)); err != nil {
				t.Fatalf("store %q: %v", kv.k, err)
			}
		}
		var got []string
		for key, err := range store.List(t.Context(), "peer-") {
			if err != nil {
				t.Fatalf("list with prefix: %v", err)
			}
			got = append(got, key)
		}
		want := []string{"peer-a", "peer-b"}
		if !slices.Equal(got, want) {
			t.Errorf("List(peer-) = %v, want %v", got, want)
		}
	})

	t.Run("Clear", func(t *testing.T) {
		store := newTestStore(t)
		for _, k := range []string{"a", "b", "c"} {
			if err := store.Store(t.Context(), k, []byte(k)); err != nil {
				t.Fatalf("store %q: %v", k, err)
			}
		}
		if err := store.Clear(t.Context()); err != nil {
			t.Fatalf("clear store: %v", err)
		}
		var got []string
		for key, err := range store.List(t.Context(), "") {
			if err != nil {
				t.Fatalf("list after clear: %v", err)
			}
			got = append(got, key)
		}
		if len(got) != 0 {
			t.Errorf("List after Clear: got %v, want nothing", got)
		}
		// Store must be usable after Clear.
		v := []byte("all blues")
		if err := store.Store(t.Context(), "k", v); err != nil {
			t.Errorf("store after clear: %v", err)
		}
		got2, err := store.Load(t.Context(), "k")
		if err != nil {
			t.Errorf("load after clear: %v", err)
		}
		if string(got2) != string(v) {
			t.Errorf("Load after Clear+Store = %q, want %q", got2, string(v))
		}
	})
}

func TestNewStore(t *testing.T) {
	t.Run("FreshDirectory", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "netmap-cache.sqlite3")
		v := []byte("all blues")

		if _, err := os.Stat(dbPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected no db file before newStore; stat err: %v", err)
		}
		store, err := newStore(t.Context(), dir, t.Logf)
		if err != nil {
			t.Fatalf("newStore failed: %v", err)
		}
		t.Cleanup(func() { store.Close(t.Context()) })

		if _, err := os.Stat(dbPath); err != nil {
			t.Fatalf("db file not created: %v", err)
		}
		if err := store.Store(t.Context(), "k", v); err != nil {
			t.Fatalf("store value: %v", err)
		}
		got, err := store.Load(t.Context(), "k")
		if err != nil {
			t.Fatalf("load value: %v", err)
		}
		if string(got) != string(v) {
			t.Errorf("Load = %q, want %q", got, string(v))
		}
	})

	t.Run("ExistingValid", func(t *testing.T) {
		dir := t.TempDir()
		v := []byte("all blues")

		s1, err := newStore(t.Context(), dir, t.Logf)
		if err != nil {
			t.Fatalf("newStore failed: %v", err)
		}
		if err := s1.Store(t.Context(), "k", v); err != nil {
			t.Fatalf("store initial value: %v", err)
		}
		if err := s1.Close(t.Context()); err != nil {
			t.Fatalf("close initial store: %v", err)
		}

		s2, err := newStore(t.Context(), dir, t.Logf)
		if err != nil {
			t.Fatalf("reopen store: %v", err)
		}
		t.Cleanup(func() { s2.Close(t.Context()) })

		got, err := s2.Load(t.Context(), "k")
		if err != nil {
			t.Fatalf("load persisted value: %v", err)
		}
		if string(got) != string(v) {
			t.Errorf("Load = %q, want %q", got, string(v))
		}
	})

	t.Run("StaleSchema", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "netmap-cache.sqlite3")
		v := []byte("so what")

		db, err := createDatabase(t.Context(), dbPath)
		if err != nil {
			t.Fatalf("createDatabase: %v", err)
		}
		contentHash := make([]byte, 32)
		if _, err := db.ExecContext(t.Context(), upsertObjectSQL, contentHash, v); err != nil {
			t.Fatalf("seed object: %v", err)
		}
		if _, err := db.ExecContext(t.Context(), upsertItemSQL, "6b" /* hex("k") */, contentHash); err != nil {
			t.Fatalf("seed item: %v", err)
		}
		if _, err := db.ExecContext(t.Context(), "UPDATE schema_version SET version = 0"); err != nil {
			t.Fatalf("downgrade schema version: %v", err)
		}
		db.Close()

		store, err := newStore(t.Context(), dir, t.Logf)
		if err != nil {
			t.Fatalf("newStore on stale db: %v", err)
		}
		t.Cleanup(func() { store.Close(t.Context()) })

		if _, err := store.Load(t.Context(), "k"); !errors.Is(err, netmapcache.ErrKeyNotFound) {
			t.Errorf("load key after stale rebuild: got %v, want ErrKeyNotFound", err)
		}
		if err := store.Store(t.Context(), "k", []byte("kind of blue")); err != nil {
			t.Errorf("store after stale rebuild: %v", err)
		}
	})
}

func TestOpenStore(t *testing.T) {
	t.Run("NonExistent", func(t *testing.T) {
		store, err := openStore(t.Context(), t.TempDir(), t.Logf)
		if err != nil {
			t.Fatalf("openStore on empty dir: %v", err)
		}
		if store != nil {
			store.Close(t.Context())
			t.Errorf("openStore on empty dir: got non-nil store, want nil")
		}
	})

	t.Run("ExistingValid", func(t *testing.T) {
		dir := t.TempDir()
		v := []byte("all blues")

		s1, err := newStore(t.Context(), dir, t.Logf)
		if err != nil {
			t.Fatalf("newStore failed: %v", err)
		}
		if err := s1.Store(t.Context(), "k", v); err != nil {
			t.Fatalf("store initial value: %v", err)
		}
		if err := s1.Close(t.Context()); err != nil {
			t.Fatalf("close initial store: %v", err)
		}

		s2, err := openStore(t.Context(), dir, t.Logf)
		if err != nil {
			t.Fatalf("openStore failed: %v", err)
		}
		if s2 == nil {
			t.Fatal("openStore returned nil, want non-nil store")
		}
		t.Cleanup(func() { s2.Close(t.Context()) })

		got, err := s2.Load(t.Context(), "k")
		if err != nil {
			t.Fatalf("load persisted value: %v", err)
		}
		if string(got) != string(v) {
			t.Errorf("Load = %q, want %q", got, string(v))
		}
	})

	t.Run("StaleSchema", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "netmap-cache.sqlite3")

		db, err := createDatabase(t.Context(), dbPath)
		if err != nil {
			t.Fatalf("createDatabase: %v", err)
		}
		if _, err := db.ExecContext(t.Context(), "UPDATE schema_version SET version = 0"); err != nil {
			t.Fatalf("downgrade schema version: %v", err)
		}
		db.Close()

		store, err := openStore(t.Context(), dir, t.Logf)
		if err != nil {
			t.Fatalf("openStore on stale db: %v", err)
		}
		if store != nil {
			store.Close(t.Context())
			t.Errorf("openStore on stale db: got non-nil store, want nil")
		}
		if _, err := os.Stat(dbPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("stale db file still exists after openStore: stat err %v", err)
		}
	})
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	pairs := []struct{ k, v string }{
		{"miles", "so what"},
		{"dewey", "all blues"},
		{"davis", "kind of blue"},
	}

	s1, err := newStore(t.Context(), dir, t.Logf)
	if err != nil {
		t.Fatalf("newStore failed: %v", err)
	}
	for _, p := range pairs {
		if err := s1.Store(t.Context(), p.k, []byte(p.v)); err != nil {
			t.Fatalf("store %q: %v", p.k, err)
		}
	}
	if err := s1.Close(t.Context()); err != nil {
		t.Fatalf("close store: %v", err)
	}

	s2, err := newStore(t.Context(), dir, t.Logf)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { s2.Close(t.Context()) })

	for _, p := range pairs {
		got, err := s2.Load(t.Context(), p.k)
		if err != nil {
			t.Errorf("load %q after reopen: %v", p.k, err)
			continue
		}
		if string(got) != p.v {
			t.Errorf("Load %q = %q, want %q", p.k, got, p.v)
		}
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "netmap-cache.sqlite3")

	store, err := newStore(t.Context(), dir, t.Logf)
	if err != nil {
		t.Fatalf("newStore failed: %v", err)
	}
	t.Cleanup(func() { store.Close(t.Context()) })

	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if got := fi.Mode() & 0777; got != 0600 {
		t.Errorf("db file mode = %04o, want 0600", got)
	}
}

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	nm := newTestNetmap(t)

	s1, err := newStore(t.Context(), dir, t.Logf)
	if err != nil {
		t.Fatalf("newStore failed: %v", err)
	}
	cache1 := netmapcache.NewCache(s1)
	if err := cache1.Store(t.Context(), nm); err != nil {
		t.Fatalf("store netmap: %v", err)
	}
	loaded, err := cache1.Load(t.Context())
	if err != nil {
		t.Fatalf("load netmap: %v", err)
	}
	if !loaded.Cached {
		t.Error("loaded.Cached = false, want true")
	}
	if !loaded.SelfNode.Valid() {
		t.Error("loaded.SelfNode is invalid")
	}
	if loaded.SelfNode.Name() != nm.SelfNode.Name() {
		t.Errorf("loaded SelfNode.Name = %q, want %q", loaded.SelfNode.Name(), nm.SelfNode.Name())
	}
	if err := s1.Close(t.Context()); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// Reopen and verify data survived.
	s2, err := newStore(t.Context(), dir, t.Logf)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { s2.Close(t.Context()) })

	loaded2, err := netmapcache.NewCache(s2).Load(t.Context())
	if err != nil {
		t.Fatalf("load netmap after reopen: %v", err)
	}
	if !loaded2.Cached {
		t.Error("loaded2.Cached = false, want true")
	}
	if loaded2.SelfNode.Name() != nm.SelfNode.Name() {
		t.Errorf("loaded2 SelfNode.Name = %q, want %q", loaded2.SelfNode.Name(), nm.SelfNode.Name())
	}
}

// newTestNetmap returns a minimal valid netmap for testing.
func newTestNetmap(t *testing.T) *netmap.NetworkMap {
	t.Helper()
	return &netmap.NetworkMap{
		AllCaps: set.Of(nodecap.CacheNetworkMaps),
		SelfNode: (&tailcfg.Node{
			Name: "modal-jazz.ts.net.",
			User: tailcfg.UserID(1),
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
			},
		}).View(),
		UserProfiles: map[tailcfg.UserID]tailcfg.UserProfileView{
			tailcfg.UserID(1): (&tailcfg.UserProfile{
				LoginName:   "miles@ahead.jazz",
				DisplayName: "Miles Dewey Davis III",
			}).View(),
		},
		DERPMap: &tailcfg.DERPMap{
			Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
				1: {},
			},
		},
	}
}
