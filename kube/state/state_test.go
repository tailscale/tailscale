// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package state

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store"
	klc "tailscale.com/kube/localclient"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func TestSetInitialStateKeys(t *testing.T) {
	var (
		podUID         = []byte("test-pod-uid")
		expectedCapVer = fmt.Appendf(nil, "%d", tailcfg.CurrentCapabilityVersion)
	)
	for name, tc := range map[string]struct {
		initial  map[ipn.StateKey][]byte
		expected map[ipn.StateKey][]byte
	}{
		"empty_initial": {
			initial: map[ipn.StateKey][]byte{},
			expected: map[ipn.StateKey][]byte{
				keyPodUID: podUID,
				keyCapVer: expectedCapVer,
			},
		},
		"existing_pod_uid_and_capver": {
			initial: map[ipn.StateKey][]byte{
				keyPodUID: podUID,
				keyCapVer: expectedCapVer,
			},
			expected: map[ipn.StateKey][]byte{
				keyPodUID: podUID,
				keyCapVer: expectedCapVer,
			},
		},
		"all_keys_preexisting": {
			initial: map[ipn.StateKey][]byte{
				keyPodUID:     podUID,
				keyCapVer:     expectedCapVer,
				keyDeviceID:   []byte("existing-device-id"),
				keyDeviceFQDN: []byte("existing-device-fqdn"),
				keyDeviceIPs:  []byte(`["1.2.3.4"]`),
			},
			expected: map[ipn.StateKey][]byte{
				keyPodUID:     podUID,
				keyCapVer:     expectedCapVer,
				keyDeviceID:   []byte("existing-device-id"),
				keyDeviceFQDN: []byte("existing-device-fqdn"),
				keyDeviceIPs:  []byte(`["1.2.3.4"]`),
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := store.New(logger.Discard, "mem:")
			if err != nil {
				t.Fatalf("error creating in-memory store: %v", err)
			}

			for key, value := range tc.initial {
				if err := store.WriteState(key, value); err != nil {
					t.Fatalf("error writing initial state key %q: %v", key, err)
				}
			}

			if err := SetInitialKeys(store, string(podUID)); err != nil {
				t.Fatalf("setInitialStateKeys failed: %v", err)
			}

			actual := make(map[ipn.StateKey][]byte)
			for expectedKey, expectedValue := range tc.expected {
				actualValue, err := store.ReadState(expectedKey)
				if err != nil {
					t.Errorf("error reading state key %q: %v", expectedKey, err)
					continue
				}

				actual[expectedKey] = actualValue
				if !bytes.Equal(actualValue, expectedValue) {
					t.Errorf("state key %q mismatch: expected %q, got %q", expectedKey, expectedValue, actualValue)
				}
			}
			if diff := cmp.Diff(actual, tc.expected); diff != "" {
				t.Errorf("state keys mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func TestKeepStateKeysUpdated(t *testing.T) {
	store := fakeStore{
		writeChan: make(chan string),
	}

	// Control's view of the node key differs from tailscaled's reported key.
	// Only the local key will be written to state.
	var (
		controlNodeKey  = key.NewNode().Public()
		localNodeKey    = key.NewNode().Public()
		rotatedCtrlKey  = key.NewNode().Public()
		rotatedLocalKey = key.NewNode().Public()
	)

	errs := make(chan error)
	notifyChan := make(chan ipn.Notify)
	lc := &klc.FakeLocalClient{
		FakeIPNBusWatcher: klc.FakeIPNBusWatcher{
			NotifyChan: notifyChan,
		},
		TailnetLockStatusResult: &ipnstate.TailnetLockStatus{NodeKey: &localNodeKey},
	}

	go func() {
		err := KeepKeysUpdated(t.Context(), t.Logf, store, lc)
		if err != nil {
			errs <- fmt.Errorf("keepStateKeysUpdated returned with error: %w", err)
		}
	}()

	for _, tc := range []struct {
		name     string
		setup    func()
		notify   ipn.Notify
		expected []string
	}{
		{
			name:     "initial_not_authed",
			notify:   ipn.Notify{},
			expected: nil,
		},
		{
			name: "authed",
			notify: ipn.Notify{
				SelfChange: &tailcfg.Node{
					StableID:  "TESTCTRL00000001",
					Key:       controlNodeKey,
					Name:      "test-node.test.ts.net",
					Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a:115c:a1e0:ab12:4843:cd96:0:1/128")},
				},
			},
			expected: []string{
				fmt.Sprintf("%s=%s", keyDeviceID, "TESTCTRL00000001"),
				fmt.Sprintf("%s=%s", keyNodeKey, localNodeKey.String()),
				fmt.Sprintf("%s=%s", keyDeviceFQDN, "test-node.test.ts.net"),
				fmt.Sprintf("%s=%s", keyDeviceIPs, `["100.64.0.1","fd7a:115c:a1e0:ab12:4843:cd96:0:1"]`),
			},
		},
		{
			name: "updated_fields",
			notify: ipn.Notify{
				SelfChange: &tailcfg.Node{
					StableID:  "TESTCTRL00000001",
					Key:       controlNodeKey, // unchanged; node key will not be updated
					Name:      "updated.test.ts.net",
					Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.250/32")},
				},
			},
			expected: []string{
				fmt.Sprintf("%s=%s", keyDeviceFQDN, "updated.test.ts.net"),
				fmt.Sprintf("%s=%s", keyDeviceIPs, `["100.64.0.250"]`),
			},
		},
		{
			name: "node_key_status_error",
			setup: func() {
				lc.TailnetLockStatusErr = errors.New("tailnet lock status unavailable")
				lc.TailnetLockStatusResult = &ipnstate.TailnetLockStatus{NodeKey: &rotatedLocalKey}
			},
			notify: ipn.Notify{
				SelfChange: &tailcfg.Node{
					StableID:  "TESTCTRL00000001",
					Key:       rotatedCtrlKey,
					Name:      "rotated.test.ts.net",
					Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.250/32")},
				},
			},
			// The node key is skipped and the remaining keys are still written.
			expected: []string{
				fmt.Sprintf("%s=%s", keyDeviceFQDN, "rotated.test.ts.net"),
			},
		},
		{
			// After `node_key_status_error`, ensure the node key still gets written
			// even though control's key hasn't changed.
			name: "node_key_retried_on_next_update",
			setup: func() {
				lc.TailnetLockStatusErr = nil
			},
			notify: ipn.Notify{
				SelfChange: &tailcfg.Node{
					StableID:  "TESTCTRL00000001",
					Key:       rotatedCtrlKey,
					Name:      "rotated.test.ts.net",
					Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.250/32")},
				},
			},
			expected: []string{
				fmt.Sprintf("%s=%s", keyNodeKey, rotatedLocalKey.String()),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
			}
			notifyChan <- tc.notify
			for _, expected := range tc.expected {
				select {
				case got := <-store.writeChan:
					if got != expected {
						t.Errorf("expected %q, got %q", expected, got)
					}
				case err := <-errs:
					t.Fatalf("unexpected error: %v", err)
				case <-time.After(5 * time.Second):
					t.Fatalf("timed out waiting for expected write %q", expected)
				}
			}
		})
	}
}

type fakeStore struct {
	writeChan chan string
}

func (f fakeStore) ReadState(key ipn.StateKey) ([]byte, error) {
	return nil, fmt.Errorf("ReadState not implemented")
}

func (f fakeStore) WriteState(key ipn.StateKey, value []byte) error {
	f.writeChan <- fmt.Sprintf("%s=%s", key, value)
	return nil
}

func TestSelfNodeFromPeerStatus(t *testing.T) {
	nodeKey := key.NewNode().Public()
	ps := &ipnstate.PeerStatus{
		ID:           "TESTCTRL00000001",
		DNSName:      "test-node.test.ts.net",
		PublicKey:    nodeKey,
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:cd96:0:1")},
	}
	want := &tailcfg.Node{
		StableID:  "TESTCTRL00000001",
		Name:      "test-node.test.ts.net",
		Key:       nodeKey,
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a:115c:a1e0:ab12:4843:cd96:0:1/128")},
	}
	if got := selfNodeFromPeerStatus(ps).AsStruct(); !reflect.DeepEqual(got, want) {
		t.Errorf("selfNodeFromPeerStatus() = %+v, want %+v", got, want)
	}
}
