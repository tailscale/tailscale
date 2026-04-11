// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"testing"

	"tailscale.com/types/key"
	"tailscale.com/types/persist"
)

// TestLoginPreservesMapPollWhenLoggedIn tests the fix for the key extension bug.
//
// When a client has valid credentials (loggedIn=true) but needs to re-authenticate
// due to key expiry, calling Login() should NOT cancel the map poll. This allows
// the client to continue receiving key extension notifications from the server
// while the auth flow proceeds in parallel.
func TestLoginPreservesMapPollWhenLoggedIn(t *testing.T) {
	// Create an Auto client that is already logged in
	// This simulates a client with valid credentials but expired key
	auto := &Auto{
		logf:     t.Logf,
		loggedIn: true, // Already authenticated (key expired, but creds valid)
		closed:   false,
	}
	auto.mapCtx, auto.mapCancel = context.WithCancel(context.Background())
	auto.authCtx, auto.authCancel = context.WithCancel(context.Background())

	originalMapCtx := auto.mapCtx

	// Call Login() - this is what happens when user clicks "Login" after key expiry
	auto.Login(LoginInteractive)

	// The fix: when loggedIn=true, mapCtx should NOT be cancelled
	// This allows the map poll to continue receiving key extension notifications
	select {
	case <-originalMapCtx.Done():
		t.Error("Login() cancelled mapCtx even though loggedIn=true; key extension notifications would be lost")
	default:
		// Good - map context still active
	}

	// Verify loginGoal was set (auth flow can proceed in parallel)
	auto.mu.Lock()
	hasLoginGoal := auto.loginGoal != nil
	auto.mu.Unlock()

	if !hasLoginGoal {
		t.Error("loginGoal should be set even though mapCtx wasn't cancelled")
	}
}

// TestLoginPreservesMapPollWithNodeKey tests the tsnet restart scenario.
//
// When a tsnet server restarts with an expired key:
// 1. The server has a valid node key stored in persist
// 2. Control returns an AuthURL (for interactive login)
// 3. loggedIn is false (because TryLogin returned a URL, not success)
// 4. But we should NOT cancel the map poll, because the server might send
//    a key extension notification via the existing node key
//
// This test verifies that Login() preserves the map poll when we have a
// valid node key, even if loggedIn=false.
func TestLoginPreservesMapPollWithNodeKey(t *testing.T) {
	// Create persist data with a valid node key (simulating stored credentials)
	nodeKey := key.NewNode()
	p := &persist.Persist{
		PrivateNodeKey: nodeKey,
	}

	// Create a Direct client with the persist data
	direct := &Direct{
		persist: p.View(),
	}

	// Create an Auto client that is NOT logged in but HAS a valid node key
	// This simulates a tsnet server restart with expired key:
	// - loggedIn=false because control returned an AuthURL
	// - but we have a valid node key that can receive map updates
	auto := &Auto{
		logf:     t.Logf,
		loggedIn: false, // Control returned AuthURL, so not "logged in" yet
		closed:   false,
		direct:   direct,
	}
	auto.mapCtx, auto.mapCancel = context.WithCancel(context.Background())
	auto.authCtx, auto.authCancel = context.WithCancel(context.Background())

	originalMapCtx := auto.mapCtx

	// Call Login() - this is what tsnet's StartLoginInteractive does
	auto.Login(LoginInteractive)

	// The fix: even though loggedIn=false, we have a valid node key,
	// so mapCtx should NOT be cancelled. This allows us to receive
	// key extension notifications from the server.
	select {
	case <-originalMapCtx.Done():
		t.Error("Login() cancelled mapCtx even though we have a valid node key; " +
			"key extension notifications would be lost in tsnet restart scenario")
	default:
		// Good - map context still active, can receive key extensions
	}

	// Verify loginGoal was set (auth flow can proceed in parallel)
	auto.mu.Lock()
	hasLoginGoal := auto.loginGoal != nil
	auto.mu.Unlock()

	if !hasLoginGoal {
		t.Error("loginGoal should be set for the auth flow to proceed")
	}
}

// TestLoginCancelsMapPollWhenNoNodeKey verifies that when there's no node key
// at all (fresh install, never authenticated), Login() should cancel the map poll.
func TestLoginCancelsMapPollWhenNoNodeKey(t *testing.T) {
	// Create a Direct client with empty persist (no node key)
	direct := &Direct{
		persist: new(persist.Persist).View(),
	}

	auto := &Auto{
		logf:     t.Logf,
		loggedIn: false,
		closed:   false,
		direct:   direct,
	}
	auto.mapCtx, auto.mapCancel = context.WithCancel(context.Background())
	auto.authCtx, auto.authCancel = context.WithCancel(context.Background())

	originalMapCtx := auto.mapCtx

	// Call Login()
	auto.Login(LoginInteractive)

	// When loggedIn=false AND no node key, mapCtx SHOULD be cancelled
	select {
	case <-originalMapCtx.Done():
		// Good - cancelled as expected for fresh login with no credentials
	default:
		t.Error("mapCtx should be cancelled when loggedIn=false and no node key")
	}
}
