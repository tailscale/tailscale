// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmapcache_test

import (
	"context"
	jsonv1 "encoding/json"
	"errors"
	"flag"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/creachadair/mds/mtest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/ipn/ipnlocal/netmapcache"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/filter/filtertype"
)

// Input values for valid-looking placeholder values for keys, hashes, etc.
const (
	testNodeKeyString    = "nodekey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testMachineKeyString = "mkey:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	testAUMHashString    = "APPLEPEARPLUMCHERRYAPPLEPEARPLUMCHERRYAPPLEPEARPLUMA" // base32, no padding
)

var keepTestOutput = flag.String("keep-output", "", "directory to keep test output (if empty, use a test temp)")

var (
	testNode1 = (&tailcfg.Node{
		ID:       99001,
		StableID: "n99001FAKE",
		Name:     "test1.example.com.",
	}).View()
	testNode2 = (&tailcfg.Node{
		ID:       99002,
		StableID: "n99002FAKE",
		Name:     "test2.example.com.",
	}).View()

	// The following fields are set in init.
	testNodeKey    key.NodePublic
	testMachineKey key.MachinePublic
	testAUMHash    tka.AUMHash
	testMap        *netmap.NetworkMap
)

func init() {
	if err := testNodeKey.UnmarshalText([]byte(testNodeKeyString)); err != nil {
		panic(fmt.Sprintf("invalid test nodekey %q: %v", testNodeKeyString, err))
	}
	if err := testMachineKey.UnmarshalText([]byte(testMachineKeyString)); err != nil {
		panic(fmt.Sprintf("invalid test machine key %q: %v", testMachineKeyString, err))
	}
	if err := testAUMHash.UnmarshalText([]byte(testAUMHashString)); err != nil {
		panic(fmt.Sprintf("invalid test AUM hash %q: %v", testAUMHashString, err))
	}

	pfRules := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"192.168.0.0/16"},
			DstPorts: []tailcfg.NetPortRange{{
				IP:    "*",
				Ports: tailcfg.PortRange{First: 2000, Last: 9999},
			}},
			IPProto: []int{1, 6, 17}, // ICMPv4, TCP, UDP
			CapGrant: []tailcfg.CapGrant{{
				Dsts: []netip.Prefix{netip.MustParsePrefix("192.168.4.0/24")},
				CapMap: tailcfg.PeerCapMap{
					"tailscale.com/testcap": []tailcfg.RawMessage{`"apple"`, `"pear"`},
				},
			}},
		},
	}
	pfMatch, err := filter.MatchesFromFilterRules(pfRules)
	if err != nil {
		panic(fmt.Sprintf("invalid packet filter rules: %v", err))
	}

	// The following network map must have a non-zero non-empty value for every
	// field that is to be stored in the cache. The test checks for this using
	// reflection, as a way to ensure that new fields added to the type are
	// covered by a test (see checkFieldCoverage).
	//
	// The exact values are unimportant, except that they should be values that
	// give us confidence that a network map round-tripped through the cache and
	// compared will accurately reflect the information we care about.
	testMap = &netmap.NetworkMap{
		Cached: false, // not cached, this is metadata for the cache machinery

		// These two fields must contain compatible data.
		PacketFilterRules: views.SliceOf(pfRules),
		PacketFilter:      pfMatch,

		// Fields stored under the "self" key.
		// Note that SelfNode must have a valid user in order to be considered
		// cacheable. Moreover, it must mention all the capabilities we expect
		// to see advertised in the AllCaps set, and its public key must match the
		// one advertised in the NodeKey field.
		SelfNode: (&tailcfg.Node{
			ID:           12345,
			StableID:     "n12345FAKE",
			User:         30337,
			Name:         "test.example.com.",
			Key:          testNodeKey,
			Capabilities: []tailcfg.NodeCapability{"cap1"},
			CapMap: map[tailcfg.NodeCapability][]tailcfg.RawMessage{
				"cap2": nil,
			},
		}).View(),
		AllCaps: set.Of[tailcfg.NodeCapability]("cap1", "cap2"),
		NodeKey: testNodeKey,

		DNS: tailcfg.DNSConfig{Domains: []string{"example1.com", "example2.ac.uk"}}, // "dns"

		SSHPolicy: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{{ // "ssh"
			SSHUsers:  map[string]string{"amelie": "ubuntu"},
			Action:    &tailcfg.SSHAction{Message: "hello", Accept: true},
			AcceptEnv: []string{"MAGIC_SSH_*"},
		}}},

		DERPMap: &tailcfg.DERPMap{ // "derp"
			HomeParams: &tailcfg.DERPHomeParams{
				RegionScore: map[int]float64{10: 0.31, 20: 0.141, 30: 0.592},
			},
			OmitDefaultRegions: true,
		},

		// Peers stored under "peer-<stableID>" keys.
		Peers: []tailcfg.NodeView{testNode1, testNode2},

		// Profiles stored under "user-<id>" keys.
		UserProfiles: map[tailcfg.UserID]tailcfg.UserProfileView{
			12345: (&tailcfg.UserProfile{ID: 12345, DisplayName: "me"}).View(),
			67890: (&tailcfg.UserProfile{ID: 67890, DisplayName: "you"}).View(),
		},

		// Fields stored under "misc"
		MachineKey:      testMachineKey,
		CollectServices: true,
		DisplayMessages: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
			"test-message-1": {Title: "hello", Text: "this is your wakeup call"},
			"test-message-2": {Title: "goodbye", Text: "good night", ImpactsConnectivity: true},
		},
		TKAEnabled:       true,
		TKAHead:          testAUMHash,
		Domain:           "example.com",
		DomainAuditLogID: "0f1e2d3c4b5a67890f1e2d3c4b5a67890f1e2d3c4b5a67890f1e2d3c4b5a6789",
	}
}

func TestNewStore(t *testing.T) {
	mtest.MustPanicf(t, func() { netmapcache.NewCache(nil) }, "NewCache should panic for a nil store")
}

func TestRoundTrip(t *testing.T) {
	checkFieldCoverage(t, testMap)

	dir := *keepTestOutput
	if dir == "" {
		dir = t.TempDir()
	} else if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("Create --keep-output directory: %v", err)
	}

	tests := []struct {
		name  string
		store netmapcache.Store
	}{
		{"MemStore", make(testStore)},
		{"FileStore", netmapcache.FileStore(dir)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := netmapcache.NewCache(tt.store)
			if err := c.Store(t.Context(), testMap); err != nil {
				t.Fatalf("Store netmap failed; %v", err)
			}

			cmap, err := c.Load(t.Context())
			if err != nil {
				t.Fatalf("Load netmap failed: %v", err)
			}

			if !cmap.Cached {
				t.Error("Cached map is not marked as such")
			}

			if diff := diffNetMaps(cmap, testMap); diff != "" {
				t.Fatalf("Cached map differs (-got, +want):\n%s", diff)
			}

		})
	}

	t.Run("Twice", func(t *testing.T) {
		// Verify that storing the same network map twice results in no change.

		s := make(testStore)
		c := netmapcache.NewCache(s)
		if err := c.Store(t.Context(), testMap); err != nil {
			t.Fatalf("Store 1 netmap failed: %v", err)
		}
		scp := maps.Clone(s) // for comparison, see below

		if err := c.Store(t.Context(), testMap); err != nil {
			t.Fatalf("Store 2 netmap failed; %v", err)
		}
		if diff := cmp.Diff(s, scp); diff != "" {
			t.Errorf("Updated store (-got, +want):\n%s", diff)
		}
	})
}

func TestInvalidCache(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		c := netmapcache.NewCache(make(testStore))
		got, err := c.Load(t.Context())
		if !errors.Is(err, netmapcache.ErrCacheNotAvailable) {
			t.Errorf("Load from empty cache: got %+v, %v; want nil, %v", got, err, netmapcache.ErrCacheNotAvailable)
		}
	})

	t.Run("Incomplete", func(t *testing.T) {
		s := make(testStore)
		c := netmapcache.NewCache(s)

		if err := c.Store(t.Context(), testMap); err != nil {
			t.Fatalf("Store initial netmap: %v", err)
		}

		// Drop the "self" node from the cache, and verify it makes the results
		// unloadable.
		if err := s.Remove(t.Context(), "self"); err != nil {
			t.Fatalf("Remove self: %v", err)
		}

		got, err := c.Load(t.Context())
		if !errors.Is(err, netmapcache.ErrCacheNotAvailable) {
			t.Errorf("Load from invalid cache: got %+v, %v; want nil, %v", got, err, netmapcache.ErrCacheNotAvailable)
		}
	})
}

// skippedMapFields are the names of fields that should not be considered by
// network map caching, and thus skipped when comparing test results.
var skippedMapFields = []string{
	"Cached",
}

// checkFieldCoverage logs an error in t if any of the fields of nm are zero
// valued, except those listed in skippedMapFields.
//
// This ensures if any new fields are added to the [netmap.NetworkMap] type in
// the future, the test will fail until non-trivial test data are added to this
// test, or the fields are recorded as skipped.  It also helps ensure that
// changing the field types or deleting fields will make compilation fail, so
// the tests get updated.
func checkFieldCoverage(t *testing.T, nm *netmap.NetworkMap) {
	t.Helper()

	mt := reflect.TypeOf(nm).Elem()
	mv := reflect.ValueOf(nm).Elem()
	for i := 0; i < mt.NumField(); i++ {
		f := mt.Field(i)
		if slices.Contains(skippedMapFields, f.Name) {
			continue
		}
		fv := mv.Field(i)
		if fv.IsZero() {
			t.Errorf("Field %d (%q) of test value is zero (%+v). "+
				"A non-zero value is required for each cached field in the test value.",
				i, f.Name, fv.Interface())
		}
	}

	// Verify that skip-listed fields exist on the type. FieldByName thwarts the
	// linker, but it's OK in a test.
	for _, skip := range skippedMapFields {
		if _, ok := mt.FieldByName(skip); !ok {
			t.Errorf("Skipped field %q not found on type %T. "+
				"If a field was deleted from the type, you may need to update skippedMapFields.",
				skip, nm)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
}

func TestPartial(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		c := netmapcache.NewCache(make(testStore)) // empty
		nm, err := c.Load(t.Context())
		if !errors.Is(err, netmapcache.ErrCacheNotAvailable) {
			t.Errorf("Load empty cache: got %+v, %v; want %v", nm, err, netmapcache.ErrCacheNotAvailable)
		}
	})

	t.Run("SelfOnly", func(t *testing.T) {
		self := (&tailcfg.Node{
			ID:       24680,
			StableID: "u24680FAKE",
			User:     6174,
			Name:     "test.example.com.",
			Key:      testNodeKey,
		}).View()

		// A cached netmap must at least have a self node to be loaded without error,
		// but other parts can be omitted without error.
		//
		// Set up a cache store with only the self node populated, and verify we
		// can load that back into something with the right shape.
		data, err := jsonv1.Marshal(struct {
			Node tailcfg.NodeView
		}{Node: self})
		if err != nil {
			t.Fatalf("Marshal test node: %v", err)
		}

		s := netmapcache.FileStore(t.TempDir())
		if err := s.Store(t.Context(), "self", data); err != nil {
			t.Fatalf("Write test cache: %v", err)
		}

		c := netmapcache.NewCache(s)
		got, err := c.Load(t.Context())
		if err != nil {
			t.Fatalf("Load cached netmap: %v", err)
		}
		if diff := diffNetMaps(got, &netmap.NetworkMap{
			Cached:   true,        // because we loaded it
			SelfNode: self,        // what we originally stored
			NodeKey:  testNodeKey, // the self-related field is populated
		}); diff != "" {
			t.Errorf("Cached map differs (-got, +want):\n%s", diff)
		}
	})
}

// testStore is an in-memory implementation of the [netmapcache.Store] interface.
type testStore map[string][]byte

func (t testStore) List(_ context.Context, prefix string) iter.Seq2[string, error] {
	var matching []string
	for key := range t {
		if strings.HasPrefix(key, prefix) {
			matching = append(matching, key)
		}
	}
	slices.Sort(matching)
	return func(yield func(string, error) bool) {
		for _, key := range matching {
			if !yield(key, nil) {
				return
			}
		}
	}
}

func (t testStore) Load(_ context.Context, key string) ([]byte, error) {
	val, ok := t[key]
	if !ok {
		return nil, netmapcache.ErrKeyNotFound
	}
	return val, nil
}

func (t testStore) Store(_ context.Context, key string, value []byte) error {
	t[key] = value
	return nil
}

func (t testStore) Remove(_ context.Context, key string) error { delete(t, key); return nil }

func diffNetMaps(got, want *netmap.NetworkMap) string {
	return cmp.Diff(got, want,
		cmpopts.IgnoreFields(netmap.NetworkMap{}, skippedMapFields...),
		cmpopts.IgnoreFields(filtertype.Match{}, "SrcsContains"), // function pointer
		cmpopts.EquateComparable(key.NodePublic{}, key.MachinePublic{}, netip.Prefix{}),
		cmp.Comparer(eqViewsSlice(eqFilterRules)),
		cmp.Comparer(eqViewsSlice(func(a, b ipproto.Proto) bool { return a == b })),
	)
}

func eqViewsSlice[T any](eqVal func(x, y T) bool) func(a, b views.Slice[T]) bool {
	return func(a, b views.Slice[T]) bool {
		if a.Len() != b.Len() {
			return false
		}
		for i := range a.Len() {
			if !eqVal(a.At(i), b.At(i)) {
				return false
			}
		}
		return true
	}
}

func eqFilterRules(a, b tailcfg.FilterRule) bool {
	return cmp.Equal(a, b, cmpopts.EquateComparable(netip.Prefix{}))
}
