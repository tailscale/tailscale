// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package netmapcache implements a persistent cache for [netmap.NetworkMap]
// values, allowing a client to start up using stale but previously-valid state
// even if a connection to the control plane is not immediately available.
package netmapcache

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	jsonv1 "encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/filter"
)

var (
	// ErrKeyNotFound is a sentinel error reported by implementations of the [Store]
	// interface when loading a key that is not found in the store.
	ErrKeyNotFound = errors.New("storage key not found")

	// ErrCacheNotAvailable is a sentinel error reported by cache methods when
	// the netmap caching feature is not enabled in the build.
	ErrCacheNotAvailable = errors.New("netmap cache is not available")
)

// A Cache manages a columnar cache of a [netmap.NetworkMap]. Each Cache holds
// a single netmap value; use [Cache.Store] to update or replace the cached
// value and [Cache.Load] to read the cached value.
type Cache struct {
	store Store

	// wantKeys records the cache keys from the last write or load of a cached
	// netmap. This is used to prune keys that are no longer referenced after an
	// update.
	wantKeys set.Set[cacheKey]

	// lastWrote records the last values written to each stored key.
	//
	// TODO(creachadair): This is meant to avoid disk writes, but I'm not
	// convinced we need it. Or maybe just track hashes of the content rather
	// than caching a complete copy.
	lastWrote map[cacheKey]lastWrote
}

// NewCache constructs a new empty [Cache] from the given [Store].
// It will panic if s == nil.
func NewCache(s Store) *Cache {
	if s == nil {
		panic("a non-nil Store is required")
	}
	return &Cache{
		store:     s,
		wantKeys:  make(set.Set[cacheKey]),
		lastWrote: make(map[cacheKey]lastWrote),
	}
}

type lastWrote struct {
	digest string
	at     time.Time
}

func (c *Cache) writeJSON(ctx context.Context, key cacheKey, v any) error {
	j, err := jsonv1.Marshal(v)
	if err != nil {
		return fmt.Errorf("JSON marshalling %q: %w", key, err)
	}

	// TODO(creachadair): Maybe use a hash instead of the contents? Do we need
	// this at all?
	last, ok := c.lastWrote[key]
	if ok && cacheDigest(j) == last.digest {
		c.wantKeys.Add(key)
		return nil
	}

	if err := c.store.Store(ctx, string(key), j); err != nil {
		return err
	}

	// Track the storage keys the current map is using, for storage GC.
	c.wantKeys.Add(key)
	c.lastWrote[key] = lastWrote{
		digest: cacheDigest(j),
		at:     time.Now(),
	}
	return nil
}

func (c *Cache) removeUnwantedKeys(ctx context.Context) error {
	var errs []error
	for key, err := range c.store.List(ctx, "") {
		if err != nil {
			errs = append(errs, err)
			break
		}
		ckey := cacheKey(key)
		if !c.wantKeys.Contains(ckey) {
			if err := c.store.Remove(ctx, key); err != nil {
				errs = append(errs, fmt.Errorf("remove key %q: %w", key, err))
			}
			delete(c.lastWrote, ckey) // even if removal failed, we don't want it
		}
	}
	return errors.Join(errs...)
}

// FileStore implements the [Store] interface using a directory of files, in
// which each key is encoded as a filename in the directory.
// The caller is responsible to ensure the directory path exists before
// using the store methods.
type FileStore string

// List implements part of the [Store] interface.
func (s FileStore) List(ctx context.Context, prefix string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		des, err := os.ReadDir(string(s))
		if os.IsNotExist(err) {
			return // nothing to read
		} else if err != nil {
			yield("", err)
			return
		}

		// os.ReadDir reports entries already sorted, and the encoding preserves that.
		for _, de := range des {
			key, err := hex.DecodeString(de.Name())
			if err != nil {
				yield("", err)
				return
			}
			name := string(key)
			if !strings.HasPrefix(name, prefix) {
				continue
			} else if !yield(name, nil) {
				return
			}
		}
	}
}

// Load implements part of the [Store] interface.
func (s FileStore) Load(ctx context.Context, key string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(string(s), hex.EncodeToString([]byte(key))))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("key %q not found: %w", key, ErrKeyNotFound)
	}
	return data, err
}

// Store implements part of the [Store] interface.
func (s FileStore) Store(ctx context.Context, key string, value []byte) error {
	return os.WriteFile(filepath.Join(string(s), hex.EncodeToString([]byte(key))), value, 0600)
}

// Remove implements part of the [Store] interface.
func (s FileStore) Remove(ctx context.Context, key string) error {
	err := os.Remove(filepath.Join(string(s), hex.EncodeToString([]byte(key))))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// cacheKey is a type wrapper for strings used as cache keys.
type cacheKey string

const (
	selfKey         cacheKey = "self"
	miscKey         cacheKey = "msic"
	dnsKey          cacheKey = "dns"
	derpMapKey      cacheKey = "derpmap"
	peerKeyPrefix   cacheKey = "peer-" // + stable ID
	userKeyPrefix   cacheKey = "user-" // + profile ID
	sshPolicyKey    cacheKey = "ssh"
	packetFilterKey cacheKey = "filter"
)

// Store records nm in the cache, replacing any previously-cached values.
func (c *Cache) Store(ctx context.Context, nm *netmap.NetworkMap) error {
	if !buildfeatures.HasCacheNetMap || nm == nil || nm.Cached {
		return nil
	}
	if selfID := nm.User(); selfID == 0 {
		return errors.New("no user in netmap")
	}

	clear(c.wantKeys)
	if err := c.writeJSON(ctx, miscKey, netmapMisc{
		MachineKey:       &nm.MachineKey,
		CollectServices:  &nm.CollectServices,
		DisplayMessages:  &nm.DisplayMessages,
		TKAEnabled:       &nm.TKAEnabled,
		TKAHead:          &nm.TKAHead,
		Domain:           &nm.Domain,
		DomainAuditLogID: &nm.DomainAuditLogID,
	}); err != nil {
		return err
	}
	if err := c.writeJSON(ctx, dnsKey, netmapDNS{DNS: &nm.DNS}); err != nil {
		return err
	}
	if err := c.writeJSON(ctx, derpMapKey, netmapDERPMap{DERPMap: &nm.DERPMap}); err != nil {
		return err
	}
	if err := c.writeJSON(ctx, selfKey, netmapNode{Node: &nm.SelfNode}); err != nil {
		return err

		// N.B. The NodeKey and AllCaps fields can be recovered from SelfNode on
		// load, and do not need to be stored separately.
	}
	for _, p := range nm.Peers {
		key := peerKeyPrefix + cacheKey(p.StableID())
		if err := c.writeJSON(ctx, key, netmapNode{Node: &p}); err != nil {
			return err
		}
	}
	for uid, u := range nm.UserProfiles {
		key := fmt.Sprintf("%s%d", userKeyPrefix, uid)
		if err := c.writeJSON(ctx, cacheKey(key), netmapUserProfile{UserProfile: &u}); err != nil {
			return err
		}
	}
	if err := c.writeJSON(ctx, packetFilterKey, netmapPacketFilter{Rules: &nm.PacketFilterRules}); err != nil {
		return err
	}

	if buildfeatures.HasSSH && nm.SSHPolicy != nil {
		if err := c.writeJSON(ctx, sshPolicyKey, netmapSSH{SSHPolicy: &nm.SSHPolicy}); err != nil {
			return err
		}
	}

	return c.removeUnwantedKeys(ctx)
}

// Load loads the cached [netmap.NetworkMap] value stored in c, if one is available.
// It reports [ErrCacheNotAvailable] if no cached data are available.
// On success, the Cached field of the returned network map is true.
func (c *Cache) Load(ctx context.Context) (*netmap.NetworkMap, error) {
	if !buildfeatures.HasCacheNetMap {
		return nil, ErrCacheNotAvailable
	}

	nm := netmap.NetworkMap{Cached: true}

	// At minimum, we require that the cache contain a "self" node, or the data
	// are not usable.
	if self, err := c.store.Load(ctx, string(selfKey)); errors.Is(err, ErrKeyNotFound) {
		return nil, ErrCacheNotAvailable
	} else if err := jsonv1.Unmarshal(self, &netmapNode{Node: &nm.SelfNode}); err != nil {
		return nil, err
	}
	c.wantKeys.Add(selfKey)

	// If we successfully recovered a SelfNode, pull out its related fields.
	if s := nm.SelfNode; s.Valid() {
		nm.NodeKey = s.Key()
		nm.AllCaps = make(set.Set[tailcfg.NodeCapability])
		for _, c := range s.Capabilities().All() {
			nm.AllCaps.Add(c)
		}
		for c := range s.CapMap().All() {
			nm.AllCaps.Add(c)
		}
	}

	// Unmarshal the contents of each specified cache entry directly into the
	// fields of the output. See the comment in types.go for more detail.

	if err := c.readJSON(ctx, miscKey, &netmapMisc{
		MachineKey:       &nm.MachineKey,
		CollectServices:  &nm.CollectServices,
		DisplayMessages:  &nm.DisplayMessages,
		TKAEnabled:       &nm.TKAEnabled,
		TKAHead:          &nm.TKAHead,
		Domain:           &nm.Domain,
		DomainAuditLogID: &nm.DomainAuditLogID,
	}); err != nil {
		return nil, err
	}

	if err := c.readJSON(ctx, dnsKey, &netmapDNS{DNS: &nm.DNS}); err != nil {
		return nil, err
	}
	if err := c.readJSON(ctx, derpMapKey, &netmapDERPMap{DERPMap: &nm.DERPMap}); err != nil {
		return nil, err
	}

	for key, err := range c.store.List(ctx, string(peerKeyPrefix)) {
		if err != nil {
			return nil, err
		}
		var peer tailcfg.NodeView
		if err := c.readJSON(ctx, cacheKey(key), &netmapNode{Node: &peer}); err != nil {
			return nil, err
		}
		nm.Peers = append(nm.Peers, peer)
	}
	slices.SortFunc(nm.Peers, func(a, b tailcfg.NodeView) int { return cmp.Compare(a.ID(), b.ID()) })
	for key, err := range c.store.List(ctx, string(userKeyPrefix)) {
		if err != nil {
			return nil, err
		}
		var up tailcfg.UserProfileView
		if err := c.readJSON(ctx, cacheKey(key), &netmapUserProfile{UserProfile: &up}); err != nil {
			return nil, err
		}
		mak.Set(&nm.UserProfiles, up.ID(), up)
	}
	if err := c.readJSON(ctx, sshPolicyKey, &netmapSSH{SSHPolicy: &nm.SSHPolicy}); err != nil {
		return nil, err
	}
	if err := c.readJSON(ctx, packetFilterKey, &netmapPacketFilter{Rules: &nm.PacketFilterRules}); err != nil {
		return nil, err
	} else if r := nm.PacketFilterRules; r.Len() != 0 {
		// Reconstitute packet match expressions from the filter rules,
		nm.PacketFilter, err = filter.MatchesFromFilterRules(r.AsSlice())
		if err != nil {
			return nil, err
		}
	}

	return &nm, nil
}

func (c *Cache) readJSON(ctx context.Context, key cacheKey, value any) error {
	data, err := c.store.Load(ctx, string(key))
	if errors.Is(err, ErrKeyNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if err := jsonv1.Unmarshal(data, value); err != nil {
		return err
	}
	c.wantKeys.Add(key)
	c.lastWrote[key] = lastWrote{digest: cacheDigest(data), at: time.Now()}
	return nil
}

// Store is the interface to persistent key-value storage used by a [Cache].
type Store interface {
	// List lists all the stored keys having the specified prefixes, in
	// lexicographic order.
	//
	// Each pair yielded by the iterator is either a valid storage key and a nil
	// error, or an empty key and a non-nil error. After reporting an error, the
	// iterator must immediately return.
	List(ctx context.Context, prefix string) iter.Seq2[string, error]

	// Load fetches the contents of the specified key.
	// If the key is not found in the store, Load must report [ErrKeyNotFound].
	Load(ctx context.Context, key string) ([]byte, error)

	// Store marshals and stores the contents of the specified value under key.
	// If the key already exists, its contents are replaced.
	Store(ctx context.Context, key string, value []byte) error

	// Remove removes the specified key from the store. If the key does not exist,
	// Remove reports success (nil).
	Remove(ctx context.Context, key string) error
}

// cacheDigest computes a string digest of the specified data, for use in
// detecting cache hits.
func cacheDigest(data []byte) string { h := sha256.Sum256(data); return string(h[:]) }
