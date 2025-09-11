// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"cmp"
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	deepcmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/lazy"
	"tailscale.com/types/logger"
	"tailscale.com/types/persist"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/must"
)

// defaultCmpOpts are the default options used for deepcmp comparisons in tests.
var defaultCmpOpts = []deepcmp.Option{
	cmpopts.EquateComparable(key.NodePublic{}, netip.Addr{}, netip.Prefix{}),
}

// TestExtensionInitShutdown tests that [ExtensionHost] correctly initializes
// and shuts down extensions.
func TestExtensionInitShutdown(t *testing.T) {
	t.Parallel()

	// As of 2025-04-08, [ipn.Host.Init] and [ipn.Host.Shutdown] do not return errors
	// as extension initialization and shutdown errors are not fatal.
	// If these methods are updated to return errors, this test should also be updated.
	// The conversions below will fail to compile if their signatures change, reminding us to update the test.
	_ = (func(*ExtensionHost))((*ExtensionHost).Init)
	_ = (func(*ExtensionHost))((*ExtensionHost).Shutdown)

	tests := []struct {
		name         string
		nilHost      bool
		exts         []*testExtension
		wantInit     []string
		wantShutdown []string
		skipInit     bool
	}{
		{
			name:         "nil-host",
			nilHost:      true,
			exts:         []*testExtension{},
			wantInit:     []string{},
			wantShutdown: []string{},
		},
		{
			name:         "empty-extensions",
			exts:         []*testExtension{},
			wantInit:     []string{},
			wantShutdown: []string{},
		},
		{
			name:         "single-extension",
			exts:         []*testExtension{{name: "A"}},
			wantInit:     []string{"A"},
			wantShutdown: []string{"A"},
		},
		{
			name:         "multiple-extensions/all-ok",
			exts:         []*testExtension{{name: "A"}, {name: "B"}, {name: "C"}},
			wantInit:     []string{"A", "B", "C"},
			wantShutdown: []string{"C", "B", "A"},
		},
		{
			name:         "multiple-extensions/no-init-no-shutdown",
			exts:         []*testExtension{{name: "A"}, {name: "B"}, {name: "C"}},
			wantInit:     []string{},
			wantShutdown: []string{},
			skipInit:     true,
		},
		{
			name: "multiple-extensions/init-failed/first",
			exts: []*testExtension{{
				name:     "A",
				InitHook: func(*testExtension) error { return errors.New("init failed") },
			}, {
				name:     "B",
				InitHook: func(*testExtension) error { return nil },
			}, {
				name:     "C",
				InitHook: func(*testExtension) error { return nil },
			}},
			wantInit:     []string{"A", "B", "C"},
			wantShutdown: []string{"C", "B"},
		},
		{
			name: "multiple-extensions/init-failed/second",
			exts: []*testExtension{{
				name:     "A",
				InitHook: func(*testExtension) error { return nil },
			}, {
				name:     "B",
				InitHook: func(*testExtension) error { return errors.New("init failed") },
			}, {
				name:     "C",
				InitHook: func(*testExtension) error { return nil },
			}},
			wantInit:     []string{"A", "B", "C"},
			wantShutdown: []string{"C", "A"},
		},
		{
			name: "multiple-extensions/init-failed/third",
			exts: []*testExtension{{
				name:     "A",
				InitHook: func(*testExtension) error { return nil },
			}, {
				name:     "B",
				InitHook: func(*testExtension) error { return nil },
			}, {
				name:     "C",
				InitHook: func(*testExtension) error { return errors.New("init failed") },
			}},
			wantInit:     []string{"A", "B", "C"},
			wantShutdown: []string{"B", "A"},
		},
		{
			name: "multiple-extensions/init-failed/all",
			exts: []*testExtension{{
				name:     "A",
				InitHook: func(*testExtension) error { return errors.New("init failed") },
			}, {
				name:     "B",
				InitHook: func(*testExtension) error { return errors.New("init failed") },
			}, {
				name:     "C",
				InitHook: func(*testExtension) error { return errors.New("init failed") },
			}},
			wantInit:     []string{"A", "B", "C"},
			wantShutdown: []string{},
		},
		{
			name: "multiple-extensions/init-skipped",
			exts: []*testExtension{{
				name:     "A",
				InitHook: func(*testExtension) error { return nil },
			}, {
				name:     "B",
				InitHook: func(*testExtension) error { return ipnext.SkipExtension },
			}, {
				name:     "C",
				InitHook: func(*testExtension) error { return nil },
			}},
			wantInit:     []string{"A", "B", "C"},
			wantShutdown: []string{"C", "A"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Configure all extensions to append their names
			// to the gotInit and gotShutdown slices
			// during initialization and shutdown,
			// so we can check that they are called in the right order
			// and that shutdown is not unless init succeeded.
			var gotInit, gotShutdown []string
			for _, ext := range tt.exts {
				oldInitHook := ext.InitHook
				ext.InitHook = func(e *testExtension) error {
					gotInit = append(gotInit, e.name)
					if oldInitHook == nil {
						return nil
					}
					return oldInitHook(e)
				}
				ext.ShutdownHook = func(e *testExtension) error {
					gotShutdown = append(gotShutdown, e.name)
					return nil
				}
			}

			var h *ExtensionHost
			if !tt.nilHost {
				h = newExtensionHostForTest(t, &testBackend{}, false, tt.exts...)
			}

			if !tt.skipInit {
				h.Init()
			}

			// Check that the extensions were initialized in the right order.
			if !slices.Equal(gotInit, tt.wantInit) {
				t.Errorf("Init extensions: got %v; want %v", gotInit, tt.wantInit)
			}

			// Calling Init again on the host should be a no-op.
			// The [testExtension.Init] method fails the test if called more than once,
			// regardless of which test is running, so we don't need to check it here.
			// Similarly, calling Shutdown again on the host should be a no-op as well.
			// It is verified by the [testExtension.Shutdown] method itself.
			if !tt.skipInit {
				h.Init()
			}

			// Extensions should not be shut down before the host is shut down,
			// even if they are not initialized successfully.
			for _, ext := range tt.exts {
				if gotShutdown := ext.ShutdownCalled(); gotShutdown {
					t.Errorf("%q: Extension shutdown called before host shutdown", ext.name)
				}
			}

			h.Shutdown()
			// Check that the extensions were shut down in the right order,
			// and that they were not shut down if they were not initialized successfully.
			if !slices.Equal(gotShutdown, tt.wantShutdown) {
				t.Errorf("Shutdown extensions: got %v; want %v", gotShutdown, tt.wantShutdown)
			}

		})
	}
}

// TestNewExtensionHost tests that [NewExtensionHost] correctly creates
// an [ExtensionHost], instantiates the extensions and handles errors
// if an extension cannot be created.
func TestNewExtensionHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		defs     []*ipnext.Definition
		wantErr  bool
		wantExts []string
	}{
		{
			name:     "no-exts",
			defs:     []*ipnext.Definition{},
			wantErr:  false,
			wantExts: []string{},
		},
		{
			name: "exts-ok",
			defs: []*ipnext.Definition{
				ipnext.DefinitionForTest(&testExtension{name: "A"}),
				ipnext.DefinitionForTest(&testExtension{name: "B"}),
				ipnext.DefinitionForTest(&testExtension{name: "C"}),
			},
			wantErr:  false,
			wantExts: []string{"A", "B", "C"},
		},
		{
			name: "exts-skipped",
			defs: []*ipnext.Definition{
				ipnext.DefinitionForTest(&testExtension{name: "A"}),
				ipnext.DefinitionWithErrForTest("B", ipnext.SkipExtension),
				ipnext.DefinitionForTest(&testExtension{name: "C"}),
			},
			wantErr:  false, // extension B is skipped, that's ok
			wantExts: []string{"A", "C"},
		},
		{
			name: "exts-fail",
			defs: []*ipnext.Definition{
				ipnext.DefinitionForTest(&testExtension{name: "A"}),
				ipnext.DefinitionWithErrForTest("B", errors.New("failed creating Ext-2")),
				ipnext.DefinitionForTest(&testExtension{name: "C"}),
			},
			wantErr:  true, // extension B failed to create, that's not ok
			wantExts: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logf := tstest.WhileTestRunningLogger(t)
			h, err := NewExtensionHostForTest(logf, &testBackend{}, tt.defs...)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Errorf("NewExtensionHost: gotErr %v(%v); wantErr %v", gotErr, err, tt.wantErr)
			}
			if err != nil {
				return
			}

			var gotExts []string
			for _, ext := range h.allExtensions {
				gotExts = append(gotExts, ext.Name())
			}

			if !slices.Equal(gotExts, tt.wantExts) {
				t.Errorf("Shutdown extensions: got %v; want %v", gotExts, tt.wantExts)
			}
		})
	}
}

// TestFindMatchingExtension tests that [ExtensionHost.FindMatchingExtension] correctly
// finds extensions by their type or interface.
func TestFindMatchingExtension(t *testing.T) {
	t.Parallel()

	// Define test extension types and a couple of interfaces
	type (
		extensionA struct {
			testExtension
		}
		extensionB struct {
			testExtension
		}
		extensionC struct {
			testExtension
		}
		supportedIface interface {
			Name() string
		}
		unsupportedIface interface {
			Unsupported()
		}
	)

	// Register extensions A and B, but not C.
	extA := &extensionA{testExtension: testExtension{name: "A"}}
	extB := &extensionB{testExtension: testExtension{name: "B"}}
	h := newExtensionHostForTest[ipnext.Extension](t, &testBackend{}, true, extA, extB)

	var gotA *extensionA
	if !h.FindMatchingExtension(&gotA) {
		t.Errorf("LookupExtension(%T): not found", gotA)
	} else if gotA != extA {
		t.Errorf("LookupExtension(%T): got %v; want %v", gotA, gotA, extA)
	}

	var gotB *extensionB
	if !h.FindMatchingExtension(&gotB) {
		t.Errorf("LookupExtension(%T): extension B not found", gotB)
	} else if gotB != extB {
		t.Errorf("LookupExtension(%T): got %v; want %v", gotB, gotB, extB)
	}

	var gotC *extensionC
	if h.FindMatchingExtension(&gotC) {
		t.Errorf("LookupExtension(%T): found, but it should not exist", gotC)
	}

	// All extensions implement the supportedIface interface,
	// but LookupExtension should only return the first one found,
	// which is extA.
	var gotSupportedIface supportedIface
	if !h.FindMatchingExtension(&gotSupportedIface) {
		t.Errorf("LookupExtension(%T): not found", gotSupportedIface)
	} else if gotName, wantName := gotSupportedIface.Name(), extA.Name(); gotName != wantName {
		t.Errorf("LookupExtension(%T): name: got %v; want %v", gotSupportedIface, gotName, wantName)
	} else if gotSupportedIface != extA {
		t.Errorf("LookupExtension(%T): got %v; want %v", gotSupportedIface, gotSupportedIface, extA)
	}

	var gotUnsupportedIface unsupportedIface
	if h.FindMatchingExtension(&gotUnsupportedIface) {
		t.Errorf("LookupExtension(%T): found, but it should not exist", gotUnsupportedIface)
	}
}

// TestFindExtensionByName tests that [ExtensionHost.FindExtensionByName] correctly
// finds extensions by their name.
func TestFindExtensionByName(t *testing.T) {
	// Register extensions A and B, but not C.
	extA := &testExtension{name: "A"}
	extB := &testExtension{name: "B"}
	h := newExtensionHostForTest(t, &testBackend{}, true, extA, extB)

	gotA, ok := h.FindExtensionByName(extA.Name()).(*testExtension)
	if !ok {
		t.Errorf("FindExtensionByName(%q): not found", extA.Name())
	} else if gotA != extA {
		t.Errorf(`FindExtensionByName(%q): got %v; want %v`, extA.Name(), gotA, extA)
	}

	gotB, ok := h.FindExtensionByName(extB.Name()).(*testExtension)
	if !ok {
		t.Errorf("FindExtensionByName(%q): not found", extB.Name())
	} else if gotB != extB {
		t.Errorf(`FindExtensionByName(%q): got %v; want %v`, extB.Name(), gotB, extB)
	}

	gotC, ok := h.FindExtensionByName("C").(*testExtension)
	if ok {
		t.Errorf(`FindExtensionByName("C"): found, but it should not exist: %v`, gotC)
	}
}

// TestExtensionHostEnqueueBackendOperation verifies that [ExtensionHost] enqueues
// backend operations and executes them asynchronously in the order they were received.
// It also checks that operations requested before the host and all extensions are initialized
// are not executed immediately but rather after the host and extensions are initialized.
func TestExtensionHostEnqueueBackendOperation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		preInitCalls  []string // before host init
		extInitCalls  []string // from [Extension.Init]; "" means no call
		wantInitCalls []string // what we expect to be called after host init
		postInitCalls []string // after host init
	}{
		{
			name:          "no-calls",
			preInitCalls:  []string{},
			extInitCalls:  []string{},
			wantInitCalls: []string{},
			postInitCalls: []string{},
		},
		{
			name:          "pre-init-calls",
			preInitCalls:  []string{"pre-init-1", "pre-init-2"},
			extInitCalls:  []string{},
			wantInitCalls: []string{"pre-init-1", "pre-init-2"},
			postInitCalls: []string{},
		},
		{
			name:          "init-calls",
			preInitCalls:  []string{},
			extInitCalls:  []string{"init-1", "init-2"},
			wantInitCalls: []string{"init-1", "init-2"},
			postInitCalls: []string{},
		},
		{
			name:          "post-init-calls",
			preInitCalls:  []string{},
			extInitCalls:  []string{},
			wantInitCalls: []string{},
			postInitCalls: []string{"post-init-1", "post-init-2"},
		},
		{
			name:          "mixed-calls",
			preInitCalls:  []string{"pre-init-1", "pre-init-2"},
			extInitCalls:  []string{"init-1", "", "init-2"},
			wantInitCalls: []string{"pre-init-1", "pre-init-2", "init-1", "init-2"},
			postInitCalls: []string{"post-init-1", "post-init-2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gotCalls []string
			var h *ExtensionHost
			b := &testBackend{
				switchToBestProfileHook: func(reason string) {
					gotCalls = append(gotCalls, reason)
				},
			}

			exts := make([]*testExtension, len(tt.extInitCalls))
			for i, reason := range tt.extInitCalls {
				exts[i] = &testExtension{}
				if reason != "" {
					exts[i].InitHook = func(e *testExtension) error {
						e.host.Profiles().SwitchToBestProfileAsync(reason)
						return nil
					}
				}
			}

			h = newExtensionHostForTest(t, b, false, exts...)
			wq := h.SetWorkQueueForTest(t) // use a test queue instead of [execqueue.ExecQueue].

			// Issue some pre-init calls. They should be deferred and not
			// added to the queue until the host is initialized.
			for _, call := range tt.preInitCalls {
				h.Profiles().SwitchToBestProfileAsync(call)
			}

			// The queue should be empty before the host is initialized.
			wq.Drain()
			if len(gotCalls) != 0 {
				t.Errorf("Pre-init calls: got %v; want (none)", gotCalls)
			}
			gotCalls = nil

			// Initialize the host and all extensions.
			// The extensions will make their calls during initialization.
			h.Init()

			// Calls made before or during initialization should now be enqueued and running.
			wq.Drain()
			if diff := deepcmp.Diff(tt.wantInitCalls, gotCalls, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Init calls: (+got -want): %v", diff)
			}
			gotCalls = nil

			// Let's make some more calls, as if extensions were making them in a response
			// to external events.
			for _, call := range tt.postInitCalls {
				h.Profiles().SwitchToBestProfileAsync(call)
			}

			// Any calls made after initialization should be enqueued and running.
			wq.Drain()
			if diff := deepcmp.Diff(tt.postInitCalls, gotCalls, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Init calls: (+got -want): %v", diff)
			}
			gotCalls = nil
		})
	}
}

// TestExtensionHostProfileStateChangeCallback verifies that [ExtensionHost] correctly handles the registration,
// invocation, and unregistration of profile state change callbacks. This includes callbacks triggered by profile changes
// and by changes to the profile's [ipn.Prefs]. It also checks that the callbacks are called with the correct arguments
// and that any private keys are stripped from [ipn.Prefs] before being passed to the callback.
func TestExtensionHostProfileStateChangeCallback(t *testing.T) {
	t.Parallel()

	type stateChange struct {
		Profile  *ipn.LoginProfile
		Prefs    *ipn.Prefs
		SameNode bool
	}
	type prefsChange struct {
		Profile  *ipn.LoginProfile
		Old, New *ipn.Prefs
	}

	// newStateChange creates a new [stateChange] with deep copies of the profile and prefs.
	newStateChange := func(profile ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) stateChange {
		return stateChange{
			Profile:  profile.AsStruct(),
			Prefs:    prefs.AsStruct(),
			SameNode: sameNode,
		}
	}
	// makeStateChangeAppender returns a callback that appends profile state changes to the extension's state.
	makeStateChangeAppender := func(e *testExtension) ipnext.ProfileStateChangeCallback {
		return func(profile ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
			UpdateExtState(e, "changes", func(changes []stateChange) []stateChange {
				return append(changes, newStateChange(profile, prefs, sameNode))
			})
		}
	}
	// getStateChanges returns the profile state changes stored in the extension's state.
	getStateChanges := func(e *testExtension) []stateChange {
		changes, _ := GetExtStateOk[[]stateChange](e, "changes")
		return changes
	}

	tests := []struct {
		name        string
		ext         *testExtension
		stateCalls  []stateChange
		prefsCalls  []prefsChange
		wantChanges []stateChange
	}{
		{
			// Register the callback for the lifetime of the extension.
			name: "Register/Lifetime",
			ext:  &testExtension{},
			stateCalls: []stateChange{
				{Profile: &ipn.LoginProfile{ID: "profile-1"}},
				{Profile: &ipn.LoginProfile{ID: "profile-2"}},
				{Profile: &ipn.LoginProfile{ID: "profile-3"}},
				{Profile: &ipn.LoginProfile{ID: "profile-3"}, SameNode: true},
			},
			wantChanges: []stateChange{ // all calls are received by the callback
				{Profile: &ipn.LoginProfile{ID: "profile-1"}},
				{Profile: &ipn.LoginProfile{ID: "profile-2"}},
				{Profile: &ipn.LoginProfile{ID: "profile-3"}},
				{Profile: &ipn.LoginProfile{ID: "profile-3"}, SameNode: true},
			},
		},
		{
			// Ensure that ipn.Prefs are passed to the callback.
			name: "CheckPrefs",
			ext:  &testExtension{},
			stateCalls: []stateChange{{
				Profile: &ipn.LoginProfile{ID: "profile-1"},
				Prefs: &ipn.Prefs{
					WantRunning: true,
					LoggedOut:   false,
					AdvertiseRoutes: []netip.Prefix{
						netip.MustParsePrefix("192.168.1.0/24"),
						netip.MustParsePrefix("192.168.2.0/24"),
					},
				},
			}},
			wantChanges: []stateChange{{
				Profile: &ipn.LoginProfile{ID: "profile-1"},
				Prefs: &ipn.Prefs{
					WantRunning: true,
					LoggedOut:   false,
					AdvertiseRoutes: []netip.Prefix{
						netip.MustParsePrefix("192.168.1.0/24"),
						netip.MustParsePrefix("192.168.2.0/24"),
					},
				},
			}},
		},
		{
			// Ensure that private keys are stripped from persist.Persist shared with extensions.
			name: "StripPrivateKeys",
			ext:  &testExtension{},
			stateCalls: []stateChange{{
				Profile: &ipn.LoginProfile{ID: "profile-1"},
				Prefs: &ipn.Prefs{
					Persist: &persist.Persist{
						NodeID:            "12345",
						PrivateNodeKey:    key.NewNode(),
						OldPrivateNodeKey: key.NewNode(),
						NetworkLockKey:    key.NewNLPrivate(),
						UserProfile: tailcfg.UserProfile{
							ID:            12345,
							LoginName:     "test@example.com",
							DisplayName:   "Test User",
							ProfilePicURL: "https://example.com/profile.png",
						},
					},
				},
			}},
			wantChanges: []stateChange{{
				Profile: &ipn.LoginProfile{ID: "profile-1"},
				Prefs: &ipn.Prefs{
					Persist: &persist.Persist{
						NodeID:            "12345",
						PrivateNodeKey:    key.NodePrivate{}, // stripped
						OldPrivateNodeKey: key.NodePrivate{}, // stripped
						NetworkLockKey:    key.NLPrivate{},   // stripped
						UserProfile: tailcfg.UserProfile{
							ID:            12345,
							LoginName:     "test@example.com",
							DisplayName:   "Test User",
							ProfilePicURL: "https://example.com/profile.png",
						},
					},
				},
			}},
		},
		{
			// Ensure that profile state callbacks are also invoked when prefs (rather than profile) change.
			name: "PrefsChange",
			ext:  &testExtension{},
			prefsCalls: []prefsChange{
				{
					Profile: &ipn.LoginProfile{ID: "profile-1"},
					Old:     &ipn.Prefs{WantRunning: false, LoggedOut: true},
					New:     &ipn.Prefs{WantRunning: true, LoggedOut: false},
				},
				{
					Profile: &ipn.LoginProfile{ID: "profile-1"},
					Old:     &ipn.Prefs{AdvertiseRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}},
					New:     &ipn.Prefs{AdvertiseRoutes: []netip.Prefix{netip.MustParsePrefix("10.10.10.0/24")}},
				},
			},
			wantChanges: []stateChange{
				{
					Profile:  &ipn.LoginProfile{ID: "profile-1"},
					Prefs:    &ipn.Prefs{WantRunning: true, LoggedOut: false},
					SameNode: true, // must be true for prefs changes
				},
				{
					Profile:  &ipn.LoginProfile{ID: "profile-1"},
					Prefs:    &ipn.Prefs{AdvertiseRoutes: []netip.Prefix{netip.MustParsePrefix("10.10.10.0/24")}},
					SameNode: true, // must be true for prefs changes
				},
			},
		},
		{
			// Ensure that private keys are stripped from prefs when state change callback
			// is invoked by prefs change.
			name: "PrefsChange/StripPrivateKeys",
			ext:  &testExtension{},
			prefsCalls: []prefsChange{
				{
					Profile: &ipn.LoginProfile{ID: "profile-1"},
					Old: &ipn.Prefs{
						WantRunning: false,
						LoggedOut:   true,
						Persist: &persist.Persist{
							NodeID:            "12345",
							PrivateNodeKey:    key.NewNode(),
							OldPrivateNodeKey: key.NewNode(),
							NetworkLockKey:    key.NewNLPrivate(),
							UserProfile: tailcfg.UserProfile{
								ID:            12345,
								LoginName:     "test@example.com",
								DisplayName:   "Test User",
								ProfilePicURL: "https://example.com/profile.png",
							},
						},
					},
					New: &ipn.Prefs{
						WantRunning: true,
						LoggedOut:   false,
						Persist: &persist.Persist{
							NodeID:            "12345",
							PrivateNodeKey:    key.NewNode(),
							OldPrivateNodeKey: key.NewNode(),
							NetworkLockKey:    key.NewNLPrivate(),
							UserProfile: tailcfg.UserProfile{
								ID:            12345,
								LoginName:     "test@example.com",
								DisplayName:   "Test User",
								ProfilePicURL: "https://example.com/profile.png",
							},
						},
					},
				},
			},
			wantChanges: []stateChange{
				{
					Profile: &ipn.LoginProfile{ID: "profile-1"},
					Prefs: &ipn.Prefs{
						WantRunning: true,
						LoggedOut:   false,
						Persist: &persist.Persist{
							NodeID:            "12345",
							PrivateNodeKey:    key.NodePrivate{}, // stripped
							OldPrivateNodeKey: key.NodePrivate{}, // stripped
							NetworkLockKey:    key.NLPrivate{},   // stripped
							UserProfile: tailcfg.UserProfile{
								ID:            12345,
								LoginName:     "test@example.com",
								DisplayName:   "Test User",
								ProfilePicURL: "https://example.com/profile.png",
							},
						},
					},
					SameNode: true, // must be true for prefs changes
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Use the default InitHook if not provided by the test.
			if tt.ext.InitHook == nil {
				tt.ext.InitHook = func(e *testExtension) error {
					// Create and register the callback on init.
					handler := makeStateChangeAppender(e)
					e.host.Hooks().ProfileStateChange.Add(handler)
					return nil
				}
			}

			h := newExtensionHostForTest(t, &testBackend{}, true, tt.ext)
			for _, call := range tt.stateCalls {
				h.NotifyProfileChange(call.Profile.View(), call.Prefs.View(), call.SameNode)
			}
			for _, call := range tt.prefsCalls {
				h.NotifyProfilePrefsChanged(call.Profile.View(), call.Old.View(), call.New.View())
			}
			if diff := deepcmp.Diff(tt.wantChanges, getStateChanges(tt.ext), defaultCmpOpts...); diff != "" {
				t.Errorf("StateChange callbacks: (-want +got): %v", diff)
			}
		})
	}
}

// TestCurrentProfileState tests that the current profile and prefs are correctly
// initialized and updated when the host is notified of changes.
func TestCurrentProfileState(t *testing.T) {
	h := newExtensionHostForTest[ipnext.Extension](t, &testBackend{}, false)

	// The initial profile and prefs should be valid and set to the default values.
	gotProfile, gotPrefs := h.Profiles().CurrentProfileState()
	checkViewsEqual(t, "Initial profile (from state)", gotProfile, zeroProfile)
	checkViewsEqual(t, "Initial prefs (from state)", gotPrefs, defaultPrefs)
	gotPrefs = h.Profiles().CurrentPrefs() // same when we only ask for prefs
	checkViewsEqual(t, "Initial prefs (direct)", gotPrefs, defaultPrefs)

	// Create a new profile and prefs, and notify the host of the change.
	profile := &ipn.LoginProfile{ID: "profile-A"}
	prefsV1 := &ipn.Prefs{ProfileName: "Prefs V1", WantRunning: true}
	h.NotifyProfileChange(profile.View(), prefsV1.View(), false)
	// The current profile and prefs should be updated.
	gotProfile, gotPrefs = h.Profiles().CurrentProfileState()
	checkViewsEqual(t, "Changed profile (from state)", gotProfile, profile.View())
	checkViewsEqual(t, "New prefs (from state)", gotPrefs, prefsV1.View())
	gotPrefs = h.Profiles().CurrentPrefs()
	checkViewsEqual(t, "New prefs (direct)", gotPrefs, prefsV1.View())

	// Notify the host of a change to the profile's prefs.
	prefsV2 := &ipn.Prefs{ProfileName: "Prefs V2", WantRunning: false}
	h.NotifyProfilePrefsChanged(profile.View(), prefsV1.View(), prefsV2.View())
	// The current prefs should be updated.
	gotProfile, gotPrefs = h.Profiles().CurrentProfileState()
	checkViewsEqual(t, "Unchanged profile (from state)", gotProfile, profile.View())
	checkViewsEqual(t, "Changed (from state)", gotPrefs, prefsV2.View())
	gotPrefs = h.Profiles().CurrentPrefs()
	checkViewsEqual(t, "Changed prefs (direct)", gotPrefs, prefsV2.View())
}

// TestBackgroundProfileResolver tests that the background profile resolvers
// are correctly registered, unregistered and invoked by the [ExtensionHost].
func TestBackgroundProfileResolver(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		profiles    []ipn.LoginProfile // the first one is the current profile
		resolvers   []ipnext.ProfileResolver
		wantProfile *ipn.LoginProfile
	}{
		{
			name:        "No-Profiles/No-Resolvers",
			profiles:    nil,
			resolvers:   nil,
			wantProfile: nil,
		},
		{
			// TODO(nickkhyl): update this test as we change "background profile resolvers"
			// to just "profile resolvers". The wantProfile should be the current profile by default.
			name:        "Has-Profiles/No-Resolvers",
			profiles:    []ipn.LoginProfile{{ID: "profile-1"}},
			resolvers:   nil,
			wantProfile: nil,
		},
		{
			name:     "Has-Profiles/Single-Resolver",
			profiles: []ipn.LoginProfile{{ID: "profile-1"}},
			resolvers: []ipnext.ProfileResolver{
				func(ps ipnext.ProfileStore) ipn.LoginProfileView {
					return ps.CurrentProfile()
				},
			},
			wantProfile: &ipn.LoginProfile{ID: "profile-1"},
		},
		// TODO(nickkhyl): add more tests for multiple resolvers and different profiles
		// once we change "background profile resolvers" to just "profile resolvers"
		// and add proper conflict resolution logic.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create a new profile manager and add the profiles to it.
			// We expose the profile manager to the extensions via the read-only [ipnext.ProfileStore] interface.
			pm := must.Get(newProfileManager(new(mem.Store), t.Logf, health.NewTracker(eventbustest.NewBus(t))))
			for i, p := range tt.profiles {
				// Generate a unique ID and key for each profile,
				// unless the profile already has them set
				// or is an empty, unnamed profile.
				if p.Name != "" {
					if p.ID == "" {
						p.ID = ipn.ProfileID("profile-" + strconv.Itoa(i))
					}
					if p.Key == "" {
						p.Key = "key-" + ipn.StateKey(p.ID)
					}
				}
				pv := p.View()
				pm.knownProfiles[p.ID] = pv
				if i == 0 {
					// Set the first profile as the current one.
					// A profileManager starts with an empty profile,
					// so it's okay if the list of profiles is empty.
					pm.SwitchToProfile(pv)
				}
			}

			h := newExtensionHostForTest[ipnext.Extension](t, &testBackend{}, false)

			// Register the resolvers with the host.
			// This is typically done by the extensions themselves,
			// but we do it here for testing purposes.
			for _, r := range tt.resolvers {
				h.Hooks().BackgroundProfileResolvers.Add(r)
			}
			h.Init()

			// Call the resolver to get the profile.
			gotProfile := h.DetermineBackgroundProfile(pm)
			if !gotProfile.Equals(tt.wantProfile.View()) {
				t.Errorf("Resolved profile: got %v; want %v", gotProfile, tt.wantProfile)
			}
		})
	}
}

// TestAuditLogProviders tests that the [ExtensionHost] correctly handles
// the registration and invocation of audit log providers. It verifies that
// the audit loggers are called with the correct actions and details,
// and that any errors returned by the providers are properly propagated.
func TestAuditLogProviders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		auditLoggers []ipnauth.AuditLogFunc // each represents an extension
		actions      []tailcfg.ClientAuditAction
		wantErr      bool
	}{
		{
			name:         "No-Providers",
			auditLoggers: nil,
			actions:      []tailcfg.ClientAuditAction{"TestAction-1", "TestAction-2"},
			wantErr:      false,
		},
		{
			name: "Single-Provider/Ok",
			auditLoggers: []ipnauth.AuditLogFunc{
				func(tailcfg.ClientAuditAction, string) error { return nil },
			},
			actions: []tailcfg.ClientAuditAction{"TestAction-1", "TestAction-2"},
			wantErr: false,
		},
		{
			name: "Single-Provider/Err",
			auditLoggers: []ipnauth.AuditLogFunc{
				func(tailcfg.ClientAuditAction, string) error {
					return errors.New("failed to log")
				},
			},
			actions: []tailcfg.ClientAuditAction{"TestAction-1", "TestAction-2"},
			wantErr: true,
		},
		{
			name: "Many-Providers/Ok",
			auditLoggers: []ipnauth.AuditLogFunc{
				func(tailcfg.ClientAuditAction, string) error { return nil },
				func(tailcfg.ClientAuditAction, string) error { return nil },
			},
			actions: []tailcfg.ClientAuditAction{"TestAction-1", "TestAction-2"},
			wantErr: false,
		},
		{
			name: "Many-Providers/Err",
			auditLoggers: []ipnauth.AuditLogFunc{
				func(tailcfg.ClientAuditAction, string) error {
					return errors.New("failed to log")
				},
				func(tailcfg.ClientAuditAction, string) error {
					return nil // all good
				},
				func(tailcfg.ClientAuditAction, string) error {
					return errors.New("also failed to log")
				},
			},
			actions: []tailcfg.ClientAuditAction{"TestAction-1", "TestAction-2"},
			wantErr: true, // some providers failed to log, so that's an error
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create extensions that register the audit log providers.
			// Each extension/provider will append auditable actions to its state,
			// then call the test's auditLogger function.
			var exts []*testExtension
			for _, auditLogger := range tt.auditLoggers {
				ext := &testExtension{}
				provider := func() ipnauth.AuditLogFunc {
					return func(action tailcfg.ClientAuditAction, details string) error {
						UpdateExtState(ext, "actions", func(actions []tailcfg.ClientAuditAction) []tailcfg.ClientAuditAction {
							return append(actions, action)
						})
						return auditLogger(action, details)
					}
				}
				ext.InitHook = func(e *testExtension) error {
					e.host.Hooks().AuditLoggers.Add(provider)
					return nil
				}
				exts = append(exts, ext)
			}

			// Initialize the host and the extensions.
			h := newExtensionHostForTest(t, &testBackend{}, true, exts...)

			// Use [ExtensionHost.AuditLogger] to log actions.
			for _, action := range tt.actions {
				err := h.AuditLogger()(action, "Test details")
				if gotErr := err != nil; gotErr != tt.wantErr {
					t.Errorf("AuditLogger: gotErr %v (%v); wantErr %v", gotErr, err, tt.wantErr)
				}
			}

			// Check that the actions were logged correctly by each provider.
			for _, ext := range exts {
				gotActions := GetExtState[[]tailcfg.ClientAuditAction](ext, "actions")
				if !slices.Equal(gotActions, tt.actions) {
					t.Errorf("Actions: got %v; want %v", gotActions, tt.actions)
				}
			}
		})
	}
}

// TestNilExtensionHostMethodCall tests that calling exported methods
// on a nil [ExtensionHost] does not panic. We should treat it as a valid
// value since it's used in various tests that instantiate [LocalBackend]
// manually without calling [NewLocalBackend]. It also verifies that if
// a method returns a single func value (e.g., a cleanup function),
// it should not be nil. This is a basic sanity check to ensure that
// typical method calls on a nil receiver work as expected.
// It does not replace the need for more thorough testing of specific methods.
func TestNilExtensionHostMethodCall(t *testing.T) {
	t.Parallel()

	var h *ExtensionHost
	typ := reflect.TypeOf(h)
	for i := range typ.NumMethod() {
		m := typ.Method(i)
		if strings.HasSuffix(m.Name, "ForTest") {
			// Skip methods that are only for testing.
			continue
		}

		t.Run(m.Name, func(t *testing.T) {
			t.Parallel()
			// Calling the method on the nil receiver should not panic.
			ret := checkMethodCallWithZeroArgs(t, m, h)
			if len(ret) == 1 && ret[0].Kind() == reflect.Func {
				// If the method returns a single func, such as a cleanup function,
				// it should not be nil.
				fn := ret[0]
				if fn.IsNil() {
					t.Fatalf("(%T).%s returned a nil func", h, m.Name)
				}
				// We expect it to be a no-op and calling it should not panic.
				args := makeZeroArgsFor(fn)
				func() {
					defer func() {
						if e := recover(); e != nil {
							t.Fatalf("panic calling the func returned by (%T).%s: %v", e, m.Name, e)
						}
					}()
					fn.Call(args)
				}()
			}
		})
	}
}

// extBeforeStartExtension is a test extension used by TestGetExtBeforeStart.
// It is registered with the [ipnext.RegisterExtension].
type extBeforeStartExtension struct{}

func init() {
	ipnext.RegisterExtension("ext-before-start", mkExtBeforeStartExtension)
}

func mkExtBeforeStartExtension(logger.Logf, ipnext.SafeBackend) (ipnext.Extension, error) {
	return extBeforeStartExtension{}, nil
}

func (extBeforeStartExtension) Name() string { return "ext-before-start" }
func (extBeforeStartExtension) Init(ipnext.Host) error {
	return nil
}
func (extBeforeStartExtension) Shutdown() error {
	return nil
}

// TestGetExtBeforeStart verifies that an extension registered via
// RegisterExtension can be retrieved with GetExt before the host is started
// (via LocalBackend.Start)
func TestGetExtBeforeStart(t *testing.T) {
	lb := newTestBackend(t)
	// Now call GetExt without calling Start on the LocalBackend.
	_, ok := GetExt[extBeforeStartExtension](lb)
	if !ok {
		t.Fatal("didn't find extension")
	}
}

// checkMethodCallWithZeroArgs calls the method m on the receiver r
// with zero values for all its arguments, except the receiver itself.
// It returns the result of the method call, or fails the test if the call panics.
func checkMethodCallWithZeroArgs[T any](t *testing.T, m reflect.Method, r T) []reflect.Value {
	t.Helper()
	args := makeZeroArgsFor(m.Func)
	// The first arg is the receiver.
	args[0] = reflect.ValueOf(r)
	// Calling the method should not panic.
	defer func() {
		if e := recover(); e != nil {
			t.Fatalf("panic calling (%T).%s: %v", r, m.Name, e)
		}
	}()
	return m.Func.Call(args)
}

func makeZeroArgsFor(fn reflect.Value) []reflect.Value {
	args := make([]reflect.Value, fn.Type().NumIn())
	for i := range args {
		args[i] = reflect.Zero(fn.Type().In(i))
	}
	return args
}

// newExtensionHostForTest creates an [ExtensionHost] with the given backend and extensions.
// It associates each extension that either is or embeds a [testExtension] with the test
// and assigns a name if one isn’t already set.
//
// If the host cannot be created, it fails the test.
//
// The host is initialized if the initialize parameter is true.
// It is shut down automatically when the test ends.
func newExtensionHostForTest[T ipnext.Extension](t *testing.T, b Backend, initialize bool, exts ...T) *ExtensionHost {
	t.Helper()

	// testExtensionIface is a subset of the methods implemented by [testExtension] that are used here.
	// We use testExtensionIface in type assertions instead of using the [testExtension] type directly,
	// which supports scenarios where an extension type embeds a [testExtension].
	type testExtensionIface interface {
		Name() string
		setName(string)
		setT(*testing.T)
		checkShutdown()
	}

	logf := tstest.WhileTestRunningLogger(t)
	defs := make([]*ipnext.Definition, len(exts))
	for i, ext := range exts {
		if ext, ok := any(ext).(testExtensionIface); ok {
			ext.setName(cmp.Or(ext.Name(), "Ext-"+strconv.Itoa(i)))
			ext.setT(t)
		}
		defs[i] = ipnext.DefinitionForTest(ext)
	}
	h, err := NewExtensionHostForTest(logf, b, defs...)
	if err != nil {
		t.Fatalf("NewExtensionHost: %v", err)
	}
	// Replace doEnqueueBackendOperation with the one that's marked as a helper,
	// so that we'll have better output if [testExecQueue.Add] fails a test.
	h.doEnqueueBackendOperation = func(f func(Backend)) {
		t.Helper()
		h.workQueue.Add(func() { f(b) })
	}
	for _, ext := range exts {
		if ext, ok := any(ext).(testExtensionIface); ok {
			t.Cleanup(ext.checkShutdown)
		}
	}
	t.Cleanup(h.Shutdown)
	if initialize {
		h.Init()
	}
	return h
}

// testExtension is an [ipnext.Extension] that:
//   - Calls the provided init and shutdown callbacks
//     when [Init] and [Shutdown] are called.
//   - Ensures that [Init] and [Shutdown] are called at most once,
//     that [Shutdown] is called after [Init], but is not called if [Init] fails
//     and is called before the test ends if [Init] succeeds.
//
// Typically, [testExtension]s are created and passed to [newExtensionHostForTest]
// when creating an [ExtensionHost] for testing.
type testExtension struct {
	t    *testing.T // test that created the extension
	name string     // name of the extension, used for logging

	host ipnext.Host // or nil if not initialized

	// InitHook and ShutdownHook are optional hooks that can be set by tests.
	InitHook, ShutdownHook func(*testExtension) error

	// initCnt, initOkCnt and shutdownCnt are used to verify that Init and Shutdown
	// are called at most once and in the correct order.
	initCnt, initOkCnt, shutdownCnt atomic.Int32

	// mu protects the following fields.
	mu sync.Mutex
	// state is the optional state used by tests.
	// It can be accessed by tests using [setTestExtensionState],
	// [getTestExtensionStateOk] and [getTestExtensionState].
	state map[string]any
}

var _ ipnext.Extension = (*testExtension)(nil)

// PermitDoubleRegister is a sentinel method whose existence tells the
// ExtensionHost to permit it to be registered multiple times.
func (*testExtension) PermitDoubleRegister() {}

func (e *testExtension) setT(t *testing.T) {
	e.t = t
}

func (e *testExtension) setName(name string) {
	e.name = name
}

// Name implements [ipnext.Extension].
func (e *testExtension) Name() string {
	return e.name
}

// Init implements [ipnext.Extension].
func (e *testExtension) Init(host ipnext.Host) (err error) {
	e.t.Helper()
	e.host = host
	if e.initCnt.Add(1) == 1 {
		e.mu.Lock()
		e.state = make(map[string]any)
		e.mu.Unlock()
	} else {
		e.t.Errorf("%q: Init called more than once", e.name)
	}
	if e.InitHook != nil {
		err = e.InitHook(e)
	}
	if err == nil {
		e.initOkCnt.Add(1)
	}
	return err // may be nil or non-nil
}

// InitCalled reports whether the Init method was called on the receiver.
func (e *testExtension) InitCalled() bool {
	return e.initCnt.Load() != 0
}

// Shutdown implements [ipnext.Extension].
func (e *testExtension) Shutdown() (err error) {
	e.t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ShutdownHook != nil {
		err = e.ShutdownHook(e)
	}
	if e.shutdownCnt.Add(1) != 1 {
		e.t.Errorf("%q: Shutdown called more than once", e.name)
	}
	if e.initCnt.Load() == 0 {
		e.t.Errorf("%q: Shutdown called without Init", e.name)
	} else if e.initOkCnt.Load() == 0 {
		e.t.Errorf("%q: Shutdown called despite failed Init", e.name)
	}
	e.host = nil
	return err // may be nil or non-nil
}

func (e *testExtension) checkShutdown() {
	e.t.Helper()
	if e.initOkCnt.Load() != 0 && e.shutdownCnt.Load() == 0 {
		e.t.Errorf("%q: Shutdown has not been called before test end", e.name)
	}
}

// ShutdownCalled reports whether the Shutdown method was called on the receiver.
func (e *testExtension) ShutdownCalled() bool {
	return e.shutdownCnt.Load() != 0
}

// SetExtState sets a keyed state on [testExtension] to the given value.
// Tests use it to propagate test-specific state throughout the extension lifecycle
// (e.g., between [testExtension.Init], [testExtension.Shutdown], and registered callbacks)
func SetExtState[T any](e *testExtension, key string, value T) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state[key] = value
}

// UpdateExtState updates a keyed state of the extension using the provided update function.
func UpdateExtState[T any](e *testExtension, key string, update func(T) T) {
	e.mu.Lock()
	defer e.mu.Unlock()
	old, _ := e.state[key].(T)
	new := update(old)
	e.state[key] = new
}

// GetExtState returns the value of the keyed state of the extension.
// It returns a zero value of T if the state is not set or is of a different type.
func GetExtState[T any](e *testExtension, key string) T {
	v, _ := GetExtStateOk[T](e, key)
	return v
}

// GetExtStateOk is like [getExtState], but also reports whether the state
// with the given key exists and is of the expected type.
func GetExtStateOk[T any](e *testExtension, key string) (_ T, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.state[key].(T)
	return v, ok
}

// testExecQueue is a test implementation of [execQueue]
// that defers execution of the enqueued funcs until
// [testExecQueue.Drain] is called, and fails the test if
// if [execQueue.Add] is called before the host is initialized.
//
// It is typically used by calling [ExtensionHost.SetWorkQueueForTest].
type testExecQueue struct {
	t *testing.T     // test that created the queue
	h *ExtensionHost // host to own the queue

	mu    sync.Mutex
	queue []func()
}

var _ execQueue = (*testExecQueue)(nil)

// SetWorkQueueForTest is a helper function that creates a new [testExecQueue]
// and sets it as the work queue for the specified [ExtensionHost],
// returning the new queue.
//
// It fails the test if the host is already initialized.
func (h *ExtensionHost) SetWorkQueueForTest(t *testing.T) *testExecQueue {
	t.Helper()
	if h.initialized.Load() {
		t.Fatalf("UseTestWorkQueue: host is already initialized")
		return nil
	}
	q := &testExecQueue{t: t, h: h}
	h.workQueue = q
	return q
}

// Add implements [execQueue].
func (q *testExecQueue) Add(f func()) {
	q.t.Helper()

	if !q.h.initialized.Load() {
		q.t.Fatal("ExecQueue.Add must not be called until the host is initialized")
		return
	}

	q.mu.Lock()
	q.queue = append(q.queue, f)
	q.mu.Unlock()
}

// Drain executes all queued functions in the order they were added.
func (q *testExecQueue) Drain() {
	q.mu.Lock()
	queue := q.queue
	q.queue = nil
	q.mu.Unlock()

	for _, f := range queue {
		f()
	}
}

// Shutdown implements [execQueue].
func (q *testExecQueue) Shutdown() {}

// Wait implements [execQueue].
func (q *testExecQueue) Wait(context.Context) error { return nil }

// testBackend implements [ipnext.Backend] for testing purposes
// by calling the provided hooks when its methods are called.
type testBackend struct {
	lazySys                 lazy.SyncValue[*tsd.System]
	switchToBestProfileHook func(reason string)

	// mu protects the backend state.
	// It is acquired on entry to the exported methods of the backend
	// and released on exit, mimicking the behavior of the [LocalBackend].
	mu sync.Mutex
}

func (b *testBackend) Clock() tstime.Clock { return tstime.StdClock{} }
func (b *testBackend) Sys() *tsd.System {
	return b.lazySys.Get(tsd.NewSystem)
}
func (b *testBackend) SendNotify(ipn.Notify)           { panic("not implemented") }
func (b *testBackend) NodeBackend() ipnext.NodeBackend { panic("not implemented") }
func (b *testBackend) TailscaleVarRoot() string        { panic("not implemented") }

func (b *testBackend) SwitchToBestProfile(reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.switchToBestProfileHook != nil {
		b.switchToBestProfileHook(reason)
	}
}

// equatableView is an interface implemented by views
// that can be compared for equality.
type equatableView[T any] interface {
	Valid() bool
	Equals(other T) bool
}

// checkViewsEqual checks that the two views are equal
// and fails the test if they are not. The prefix is used
// to format the error message.
func checkViewsEqual[T equatableView[T]](t *testing.T, prefix string, got, want T) {
	t.Helper()
	switch {
	case got.Equals(want):
		return
	case got.Valid() && want.Valid():
		t.Errorf("%s: got %v; want %v", prefix, got, want)
	case got.Valid() && !want.Valid():
		t.Errorf("%s: got %v; want invalid", prefix, got)
	case !got.Valid() && want.Valid():
		t.Errorf("%s: got invalid; want %v", prefix, want)
	default:
		panic("unreachable")
	}
}
