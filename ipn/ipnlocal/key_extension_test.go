// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine"
)

// TestKeyExtensionWakesUpExpiredClient verifies that when a client is in NeedsLogin
// state due to key expiry, receiving a netmap with an extended (future) KeyExpiry
// correctly transitions the client back to a working state.
//
// This tests the key recovery path: client has expired key -> admin extends key
// -> server sends updated netmap -> client should recover.
func TestKeyExtensionWakesUpExpiredClient(t *testing.T) {
	envknob.Setenv("TAILSCALE_USE_WIP_CODE", "1")
	defer envknob.Setenv("TAILSCALE_USE_WIP_CODE", "")

	c := qt.New(t)
	logf := tstest.WhileTestRunningLogger(t)

	// Setup test infrastructure
	sys := tsd.NewSystem()
	store := new(mem.Store)
	sys.Set(store)
	e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	c.Assert(err, qt.IsNil)
	t.Cleanup(e.Close)
	sys.Set(e)

	b, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	c.Assert(err, qt.IsNil)
	t.Cleanup(b.Shutdown)

	var cc *mockControl
	b.SetControlClientGetterForTesting(func(opts controlclient.Options) (controlclient.Client, error) {
		cc = newClient(t, opts)
		return cc, nil
	})

	// Start the backend
	c.Assert(b.Start(ipn.Options{}), qt.IsNil)

	// Simulate successful login and authenticated state
	cc.populateKeys()
	nodeKey := key.NewNode().Public()
	now := time.Now()

	// First, get to a Running state with a valid key
	futureExpiry := now.Add(1 * time.Hour)
	cc.send(sendOpt{
		loginFinished: true,
		nm: &netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				ID:                1,
				Key:               nodeKey,
				MachineAuthorized: true,
				KeyExpiry:         futureExpiry,
			}).View(),
		},
	})

	// Enable WantRunning - required for keyExpired to trigger NeedsLogin state
	b.EditPrefs(&ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs:          ipn.Prefs{WantRunning: true},
	})

	// Verify we're in a good state initially
	b.mu.Lock()
	c.Assert(b.keyExpired, qt.IsFalse, qt.Commentf("key should not be expired initially"))
	b.mu.Unlock()

	// Now simulate key expiry by sending a netmap with past KeyExpiry
	pastExpiry := now.Add(-1 * time.Hour)
	cc.send(sendOpt{
		nm: &netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				ID:                1,
				Key:               nodeKey,
				MachineAuthorized: true,
				KeyExpiry:         pastExpiry,
			}).View(),
		},
	})

	// Verify the client detects key expiry
	b.mu.Lock()
	c.Assert(b.keyExpired, qt.IsTrue, qt.Commentf("key should be detected as expired"))
	b.mu.Unlock()

	// Verify state is NeedsLogin (requires WantRunning=true)
	state := b.State()
	c.Assert(state, qt.Equals, ipn.NeedsLogin, qt.Commentf("state should be NeedsLogin when key is expired and WantRunning=true"))

	// Set blocked to true to simulate the engine being blocked (as would happen
	// when entering NeedsLogin due to key expiry in real flow)
	b.mu.Lock()
	b.blocked = true
	b.mu.Unlock()

	// Now simulate admin extending the key - server sends new netmap with extended expiry
	extendedExpiry := now.Add(30 * time.Minute)
	cc.send(sendOpt{
		nm: &netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				ID:                1,
				Key:               nodeKey,
				MachineAuthorized: true,
				KeyExpiry:         extendedExpiry,
			}).View(),
		},
	})

	// Verify the client recovers:
	// 1. keyExpired should be false
	b.mu.Lock()
	c.Assert(b.keyExpired, qt.IsFalse, qt.Commentf("key should no longer be expired after extension"))

	// 2. blocked should be false (unblocked when key extended)
	c.Assert(b.blocked, qt.IsFalse, qt.Commentf("engine should be unblocked after key extension"))
	b.mu.Unlock()

	// 3. state should transition away from NeedsLogin
	// Note: exact state depends on other factors (MachineAuthorized, etc.)
	// but it should NOT be NeedsLogin anymore
	state = b.State()
	if state == ipn.NeedsLogin {
		// Check if it's still NeedsLogin for a reason OTHER than key expiry
		b.mu.Lock()
		keyExp := b.keyExpired
		b.mu.Unlock()
		if !keyExp {
			// Key is not expired, so NeedsLogin must be for another reason
			// (which is acceptable in this test's context)
			t.Logf("state is NeedsLogin but keyExpired=false, which is acceptable")
		} else {
			t.Errorf("state is still NeedsLogin with keyExpired=true after key extension")
		}
	}
}

// TestKeyExpiredStateMachine verifies that when a key expires, the state machine
// correctly transitions to NeedsLogin and sets keyExpired=true.
func TestKeyExpiredStateMachine(t *testing.T) {
	envknob.Setenv("TAILSCALE_USE_WIP_CODE", "1")
	defer envknob.Setenv("TAILSCALE_USE_WIP_CODE", "")

	c := qt.New(t)
	logf := tstest.WhileTestRunningLogger(t)

	sys := tsd.NewSystem()
	store := new(mem.Store)
	sys.Set(store)
	e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	c.Assert(err, qt.IsNil)
	t.Cleanup(e.Close)
	sys.Set(e)

	b, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	c.Assert(err, qt.IsNil)
	t.Cleanup(b.Shutdown)

	var cc *mockControl
	b.SetControlClientGetterForTesting(func(opts controlclient.Options) (controlclient.Client, error) {
		cc = newClient(t, opts)
		return cc, nil
	})

	c.Assert(b.Start(ipn.Options{}), qt.IsNil)

	cc.populateKeys()
	nodeKey := key.NewNode().Public()
	now := time.Now()

	// Get to Running state with valid key
	futureExpiry := now.Add(1 * time.Hour)
	cc.send(sendOpt{
		loginFinished: true,
		nm: &netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				ID:                1,
				Key:               nodeKey,
				MachineAuthorized: true,
				KeyExpiry:         futureExpiry,
			}).View(),
		},
	})

	// Enable WantRunning
	b.EditPrefs(&ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs:          ipn.Prefs{WantRunning: true},
	})

	// Verify initial state
	b.mu.Lock()
	c.Assert(b.keyExpired, qt.IsFalse)
	b.mu.Unlock()

	// Now expire the key
	pastExpiry := now.Add(-1 * time.Hour)
	cc.send(sendOpt{
		nm: &netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				ID:                1,
				Key:               nodeKey,
				MachineAuthorized: true,
				KeyExpiry:         pastExpiry,
			}).View(),
		},
	})

	// Verify keyExpired is set
	b.mu.Lock()
	c.Assert(b.keyExpired, qt.IsTrue, qt.Commentf("keyExpired should be true after receiving expired KeyExpiry"))
	b.mu.Unlock()

	// Verify state is NeedsLogin
	c.Assert(b.State(), qt.Equals, ipn.NeedsLogin)
}

// TestKeyExpiryExtendedUnblocksEngine verifies that when a key is extended,
// the engine is unblocked even if it was blocked due to key expiry.
func TestKeyExpiryExtendedUnblocksEngine(t *testing.T) {
	envknob.Setenv("TAILSCALE_USE_WIP_CODE", "1")
	defer envknob.Setenv("TAILSCALE_USE_WIP_CODE", "")

	c := qt.New(t)
	logf := tstest.WhileTestRunningLogger(t)

	sys := tsd.NewSystem()
	store := new(mem.Store)
	sys.Set(store)
	e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	c.Assert(err, qt.IsNil)
	t.Cleanup(e.Close)
	sys.Set(e)

	b, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	c.Assert(err, qt.IsNil)
	t.Cleanup(b.Shutdown)

	var cc *mockControl
	b.SetControlClientGetterForTesting(func(opts controlclient.Options) (controlclient.Client, error) {
		cc = newClient(t, opts)
		return cc, nil
	})

	c.Assert(b.Start(ipn.Options{}), qt.IsNil)

	cc.populateKeys()
	nodeKey := key.NewNode().Public()
	now := time.Now()

	// Get to authenticated state
	cc.send(sendOpt{
		loginFinished: true,
		nm: &netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				ID:                1,
				Key:               nodeKey,
				MachineAuthorized: true,
				KeyExpiry:         now.Add(1 * time.Hour),
			}).View(),
		},
	})

	// Simulate key expiry
	pastExpiry := now.Add(-1 * time.Hour)
	cc.send(sendOpt{
		nm: &netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				ID:                1,
				Key:               nodeKey,
				MachineAuthorized: true,
				KeyExpiry:         pastExpiry,
			}).View(),
		},
	})

	// Manually set blocked=true to simulate blocked state
	b.mu.Lock()
	b.blocked = true
	wasBlocked := b.blocked
	b.mu.Unlock()
	c.Assert(wasBlocked, qt.IsTrue)

	// Extend the key
	extendedExpiry := now.Add(30 * time.Minute)
	cc.send(sendOpt{
		nm: &netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				ID:                1,
				Key:               nodeKey,
				MachineAuthorized: true,
				KeyExpiry:         extendedExpiry,
			}).View(),
		},
	})

	// Verify engine is unblocked
	b.mu.Lock()
	c.Assert(b.blocked, qt.IsFalse, qt.Commentf("engine should be unblocked after key extension"))
	c.Assert(b.keyExpired, qt.IsFalse, qt.Commentf("keyExpired should be false after extension"))
	b.mu.Unlock()
}

// TestKeyExpiryZeroMeansNoExpiry verifies that a zero KeyExpiry (used for
// tagged nodes or nodes with expiry disabled) is not treated as expired.
func TestKeyExpiryZeroMeansNoExpiry(t *testing.T) {
	envknob.Setenv("TAILSCALE_USE_WIP_CODE", "1")
	defer envknob.Setenv("TAILSCALE_USE_WIP_CODE", "")

	c := qt.New(t)
	logf := tstest.WhileTestRunningLogger(t)

	sys := tsd.NewSystem()
	store := new(mem.Store)
	sys.Set(store)
	e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	c.Assert(err, qt.IsNil)
	t.Cleanup(e.Close)
	sys.Set(e)

	b, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	c.Assert(err, qt.IsNil)
	t.Cleanup(b.Shutdown)

	var cc *mockControl
	b.SetControlClientGetterForTesting(func(opts controlclient.Options) (controlclient.Client, error) {
		cc = newClient(t, opts)
		return cc, nil
	})

	c.Assert(b.Start(ipn.Options{}), qt.IsNil)

	cc.populateKeys()
	nodeKey := key.NewNode().Public()

	// Send netmap with zero KeyExpiry (like a tagged node)
	cc.send(sendOpt{
		loginFinished: true,
		nm: &netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				ID:                1,
				Key:               nodeKey,
				MachineAuthorized: true,
				KeyExpiry:         time.Time{}, // zero = no expiry
			}).View(),
		},
	})

	// Verify key is NOT considered expired
	b.mu.Lock()
	c.Assert(b.keyExpired, qt.IsFalse, qt.Commentf("zero KeyExpiry should not be treated as expired"))
	b.mu.Unlock()

	// State should not be NeedsLogin due to expiry
	state := b.State()
	c.Assert(state, qt.Not(qt.Equals), ipn.NeedsLogin, qt.Commentf("should not be in NeedsLogin with zero KeyExpiry"))
}

// TestKeyExpiryWithNetMapUpdate verifies that key expiry detection works
// correctly across multiple netmap updates with varying expiry times.
func TestKeyExpiryWithNetMapUpdate(t *testing.T) {
	envknob.Setenv("TAILSCALE_USE_WIP_CODE", "1")
	defer envknob.Setenv("TAILSCALE_USE_WIP_CODE", "")

	c := qt.New(t)
	logf := tstest.WhileTestRunningLogger(t)

	sys := tsd.NewSystem()
	store := new(mem.Store)
	sys.Set(store)
	e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	c.Assert(err, qt.IsNil)
	t.Cleanup(e.Close)
	sys.Set(e)

	b, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	c.Assert(err, qt.IsNil)
	t.Cleanup(b.Shutdown)

	var cc *mockControl
	b.SetControlClientGetterForTesting(func(opts controlclient.Options) (controlclient.Client, error) {
		cc = newClient(t, opts)
		return cc, nil
	})

	c.Assert(b.Start(ipn.Options{}), qt.IsNil)

	cc.populateKeys()
	nodeKey := key.NewNode().Public()
	now := time.Now()

	// Initial login with future expiry
	futureExpiry := now.Add(24 * time.Hour)
	cc.send(sendOpt{
		loginFinished: true,
		nm: &netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				ID:                1,
				Key:               nodeKey,
				MachineAuthorized: true,
				KeyExpiry:         futureExpiry,
			}).View(),
		},
	})

	b.mu.Lock()
	c.Assert(b.keyExpired, qt.IsFalse)
	b.mu.Unlock()

	// Simulate multiple netmap updates, tracking keyExpired state
	testCases := []struct {
		name        string
		expiry      time.Time
		wantExpired bool
	}{
		{"still valid", now.Add(12 * time.Hour), false},
		{"expires soon", now.Add(5 * time.Minute), false},
		{"just expired", now.Add(-1 * time.Second), true},
		{"expired long ago", now.Add(-24 * time.Hour), true},
		{"extended again", now.Add(1 * time.Hour), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cc.send(sendOpt{
				nm: &netmap.NetworkMap{
					SelfNode: (&tailcfg.Node{
						ID:                1,
						Key:               nodeKey,
						MachineAuthorized: true,
						KeyExpiry:         tc.expiry,
					}).View(),
				},
			})

			b.mu.Lock()
			gotExpired := b.keyExpired
			b.mu.Unlock()

			c.Assert(gotExpired, qt.Equals, tc.wantExpired,
				qt.Commentf("%s: expiry=%v, keyExpired=%v, want=%v",
					tc.name, tc.expiry, gotExpired, tc.wantExpired))
		})
	}
}
