// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package state

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
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
				keyDeviceID:   nil,
				keyDeviceFQDN: nil,
				keyDeviceIPs:  nil,
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
	store, err := store.New(logger.Discard, "mem:")
	if err != nil {
		t.Fatalf("error creating in-memory store: %v", err)
	}

	nextWaiting := make(chan struct{})
	go func() {
		<-nextWaiting // Acknowledge the initial signal.
	}()
	notifyCh := make(chan ipn.Notify)
	next := func() (ipn.Notify, error) {
		nextWaiting <- struct{}{} // Send signal to test that state is consistent.
		return <-notifyCh, nil    // Wait for test input.
	}

	errs := make(chan error, 1)
	go func() {
		err := KeepKeysUpdated(store, next)
		if err != nil {
			errs <- fmt.Errorf("keepStateKeysUpdated returned with error: %w", err)
		}
	}()

	for _, tc := range []struct {
		name     string
		notify   ipn.Notify
		expected map[ipn.StateKey][]byte
	}{
		{
			name:   "initial_not_authed",
			notify: ipn.Notify{},
			expected: map[ipn.StateKey][]byte{
				keyDeviceID:   nil,
				keyDeviceFQDN: nil,
				keyDeviceIPs:  nil,
			},
		},
		{
			name: "authed",
			notify: ipn.Notify{
				NetMap: &netmap.NetworkMap{
					SelfNode: (&tailcfg.Node{
						StableID:  "TESTCTRL00000001",
						Name:      "test-node.test.ts.net",
						Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a:115c:a1e0:ab12:4843:cd96:0:1/128")},
					}).View(),
				},
			},
			expected: map[ipn.StateKey][]byte{
				keyDeviceID:   []byte("TESTCTRL00000001"),
				keyDeviceFQDN: []byte("test-node.test.ts.net"),
				keyDeviceIPs:  []byte(`["100.64.0.1","fd7a:115c:a1e0:ab12:4843:cd96:0:1"]`),
			},
		},
		{
			name: "updated_fields",
			notify: ipn.Notify{
				NetMap: &netmap.NetworkMap{
					SelfNode: (&tailcfg.Node{
						StableID:  "TESTCTRL00000001",
						Name:      "updated.test.ts.net",
						Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.250/32")},
					}).View(),
				},
			},
			expected: map[ipn.StateKey][]byte{
				keyDeviceID:   []byte("TESTCTRL00000001"),
				keyDeviceFQDN: []byte("updated.test.ts.net"),
				keyDeviceIPs:  []byte(`["100.64.0.250"]`),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Send test input.
			select {
			case notifyCh <- tc.notify:
			case <-errs:
				t.Fatal("keepStateKeysUpdated returned before test input")
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for next() to be called again")
			}

			// Wait for next() to be called again so we know the goroutine has
			// processed the event.
			select {
			case <-nextWaiting:
			case <-errs:
				t.Fatal("keepStateKeysUpdated returned before test input")
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for next() to be called again")
			}

			for key, value := range tc.expected {
				got, _ := store.ReadState(key)
				if !bytes.Equal(got, value) {
					t.Errorf("state key %q mismatch: expected %q, got %q", key, value, got)
				}
			}
		})
	}
}
