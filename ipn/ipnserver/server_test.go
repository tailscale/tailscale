// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnserver_test

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"sync"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/lapitest"
	"tailscale.com/tsd"
	"tailscale.com/types/ptr"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policytest"
)

func TestUserConnectDisconnectNonWindows(t *testing.T) {
	enableLogging := false
	if runtime.GOOS == "windows" {
		setGOOSForTest(t, "linux")
	}

	ctx := context.Background()
	server := lapitest.NewServer(t, lapitest.WithLogging(enableLogging))

	// UserA connects and starts watching the IPN bus.
	clientA := server.ClientWithName("UserA")
	watcherA, _ := clientA.WatchIPNBus(ctx, 0)

	// The concept of "current user" is only relevant on Windows
	// and it should not be set on non-Windows platforms.
	server.CheckCurrentUser(nil)

	// Additionally, a different user should be able to connect and use the LocalAPI.
	clientB := server.ClientWithName("UserB")
	if _, gotErr := clientB.Status(ctx); gotErr != nil {
		t.Fatalf("Status(%q): want nil; got %v", clientB.Username(), gotErr)
	}

	// Watching the IPN bus should also work for UserB.
	watcherB, _ := clientB.WatchIPNBus(ctx, 0)

	// And if we send a notification, both users should receive it.
	wantErrMessage := "test error"
	testNotify := ipn.Notify{ErrMessage: ptr.To(wantErrMessage)}
	server.Backend().DebugNotify(testNotify)

	if n, err := watcherA.Next(); err != nil {
		t.Fatalf("IPNBusWatcher.Next(%q): %v", clientA.Username(), err)
	} else if gotErrMessage := n.ErrMessage; gotErrMessage == nil || *gotErrMessage != wantErrMessage {
		t.Fatalf("IPNBusWatcher.Next(%q): want %v; got %v", clientA.Username(), wantErrMessage, gotErrMessage)
	}

	if n, err := watcherB.Next(); err != nil {
		t.Fatalf("IPNBusWatcher.Next(%q): %v", clientB.Username(), err)
	} else if gotErrMessage := n.ErrMessage; gotErrMessage == nil || *gotErrMessage != wantErrMessage {
		t.Fatalf("IPNBusWatcher.Next(%q): want %v; got %v", clientB.Username(), wantErrMessage, gotErrMessage)
	}
}

func TestUserConnectDisconnectOnWindows(t *testing.T) {
	enableLogging := false
	setGOOSForTest(t, "windows")

	ctx := context.Background()
	server := lapitest.NewServer(t, lapitest.WithLogging(enableLogging))

	client := server.ClientWithName("User")
	_, cancelWatcher := client.WatchIPNBus(ctx, 0)

	// On Windows, however, the current user should be set to the user that connected.
	server.CheckCurrentUser(client.Actor)

	// Cancel the IPN bus watcher request and wait for the server to unblock.
	cancelWatcher()
	server.BlockWhileInUse(ctx)

	// The current user should not be set after a disconnect, as no one is
	// currently using the server.
	server.CheckCurrentUser(nil)
}

func TestIPNAlreadyInUseOnWindows(t *testing.T) {
	enableLogging := false
	setGOOSForTest(t, "windows")

	ctx := context.Background()
	server := lapitest.NewServer(t, lapitest.WithLogging(enableLogging))

	// UserA connects and starts watching the IPN bus.
	clientA := server.ClientWithName("UserA")
	clientA.WatchIPNBus(ctx, 0)

	// While UserA is connected, UserB should not be able to connect.
	clientB := server.ClientWithName("UserB")
	if _, gotErr := clientB.Status(ctx); gotErr == nil {
		t.Fatalf("Status(%q): want error; got nil", clientB.Username())
	} else if wantError := "401 Unauthorized: Tailscale already in use by UserA"; gotErr.Error() != wantError {
		t.Fatalf("Status(%q): want %q; got %q", clientB.Username(), wantError, gotErr.Error())
	}

	// Current user should still be UserA.
	server.CheckCurrentUser(clientA.Actor)
}

func TestSequentialOSUserSwitchingOnWindows(t *testing.T) {
	enableLogging := false
	setGOOSForTest(t, "windows")

	ctx := context.Background()
	server := lapitest.NewServer(t, lapitest.WithLogging(enableLogging))

	connectDisconnectAsUser := func(name string) {
		// User connects and starts watching the IPN bus.
		client := server.ClientWithName(name)
		watcher, cancelWatcher := client.WatchIPNBus(ctx, 0)
		defer cancelWatcher()
		go pumpIPNBus(watcher)

		// It should be the current user from the LocalBackend's perspective...
		server.CheckCurrentUser(client.Actor)
		// until it disconnects.
		cancelWatcher()
		server.BlockWhileInUse(ctx)
		// Now, the current user should be unset.
		server.CheckCurrentUser(nil)
	}

	// UserA logs in, uses Tailscale for a bit, then logs out.
	connectDisconnectAsUser("UserA")
	// Same for UserB.
	connectDisconnectAsUser("UserB")
}

func TestConcurrentOSUserSwitchingOnWindows(t *testing.T) {
	enableLogging := false
	setGOOSForTest(t, "windows")

	ctx := context.Background()
	server := lapitest.NewServer(t, lapitest.WithLogging(enableLogging))

	connectDisconnectAsUser := func(name string) {
		// User connects and starts watching the IPN bus.
		client := server.ClientWithName(name)
		watcher, cancelWatcher := client.WatchIPNBus(ctx, ipn.NotifyInitialState)
		defer cancelWatcher()

		runtime.Gosched()

		// Get the current user from the LocalBackend's perspective
		// as soon as we're connected.
		gotUID, gotActor := server.Backend().CurrentUserForTest()

		// Wait for the first notification to arrive.
		// It will either be the initial state we've requested via [ipn.NotifyInitialState],
		// returned by an actual handler, or a "fake" notification sent by the server
		// itself to indicate that it is being used by someone else.
		n, err := watcher.Next()
		if err != nil {
			t.Fatal(err)
		}

		// If our user lost the race and the IPN is in use by another user,
		// we should just return. For the sake of this test, we're not
		// interested in waiting for the server to become idle.
		if n.State != nil && *n.State == ipn.InUseOtherUser {
			return
		}

		// Otherwise, our user should have been the current user since the time we connected.
		if gotUID != client.Actor.UserID() {
			t.Errorf("CurrentUser(Initial): got UID %q; want %q", gotUID, client.Actor.UserID())
			return
		}
		if hasActor := gotActor != nil; !hasActor || gotActor != client.Actor {
			t.Errorf("CurrentUser(Initial): got %v; want %v", gotActor, client.Actor)
			return
		}

		// And should still be the current user (as they're still connected)...
		server.CheckCurrentUser(client.Actor)
	}

	numIterations := 10
	for range numIterations {
		numGoRoutines := 100
		var wg sync.WaitGroup
		wg.Add(numGoRoutines)
		for i := range numGoRoutines {
			// User logs in, uses Tailscale for a bit, then logs out
			// in parallel with other users doing the same.
			go func() {
				defer wg.Done()
				connectDisconnectAsUser("User-" + strconv.Itoa(i))
			}()
		}
		wg.Wait()

		if err := server.BlockWhileInUse(ctx); err != nil {
			t.Fatalf("BlockUntilIdle: %v", err)
		}

		server.CheckCurrentUser(nil)
	}
}

func TestBlockWhileIdentityInUse(t *testing.T) {
	enableLogging := false
	setGOOSForTest(t, "windows")

	ctx := context.Background()
	server := lapitest.NewServer(t, lapitest.WithLogging(enableLogging))

	// connectWaitDisconnectAsUser connects as a user with the specified name
	// and keeps the IPN bus watcher alive until the context is canceled.
	// It returns a channel that is closed when done.
	connectWaitDisconnectAsUser := func(ctx context.Context, name string) <-chan struct{} {
		client := server.ClientWithName(name)
		watcher, cancelWatcher := client.WatchIPNBus(ctx, 0)

		done := make(chan struct{})
		go func() {
			defer cancelWatcher()
			defer close(done)
			for {
				_, err := watcher.Next()
				if err != nil {
					// There's either an error or the request has been canceled.
					break
				}
			}
		}()
		return done
	}

	for range 100 {
		// Connect as UserA, and keep the connection alive
		// until disconnectUserA is called.
		userAContext, disconnectUserA := context.WithCancel(ctx)
		userADone := connectWaitDisconnectAsUser(userAContext, "UserA")
		disconnectUserA()
		// Check if userB can connect. Calling it directly increases
		// the likelihood of triggering a deadlock due to a race condition
		// in blockWhileIdentityInUse. But the issue also occurs during
		// the normal execution path when UserB connects to the IPN server
		// while UserA is disconnecting.
		userB := server.MakeTestActor("UserB", "ClientB")
		server.BlockWhileInUseByOther(ctx, userB)
		<-userADone
	}
}

func TestShutdownViaLocalAPI(t *testing.T) {
	t.Parallel()

	errAccessDeniedByPolicy := errors.New("Access denied: shutdown access denied by policy")

	tests := []struct {
		name                   string
		allowTailscaledRestart *bool
		wantErr                error
	}{
		{
			name:                   "AllowTailscaledRestart/NotConfigured",
			allowTailscaledRestart: nil,
			wantErr:                errAccessDeniedByPolicy,
		},
		{
			name:                   "AllowTailscaledRestart/False",
			allowTailscaledRestart: ptr.To(false),
			wantErr:                errAccessDeniedByPolicy,
		},
		{
			name:                   "AllowTailscaledRestart/True",
			allowTailscaledRestart: ptr.To(true),
			wantErr:                nil, // shutdown should be allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sys := tsd.NewSystem()

			var pol policytest.Config
			if tt.allowTailscaledRestart != nil {
				pol.Set(pkey.AllowTailscaledRestart, *tt.allowTailscaledRestart)
			}
			sys.Set(pol)

			server := lapitest.NewServer(t, lapitest.WithSys(sys))
			lc := server.ClientWithName("User")

			err := lc.ShutdownTailscaled(t.Context())
			checkError(t, err, tt.wantErr)
		})
	}
}

func checkError(tb testing.TB, got, want error) {
	tb.Helper()
	if (want == nil) != (got == nil) ||
		(want != nil && got != nil && want.Error() != got.Error() && !errors.Is(got, want)) {
		tb.Fatalf("gotErr: %v; wantErr: %v", got, want)
	}
}

func setGOOSForTest(tb testing.TB, goos string) {
	tb.Helper()
	envknob.Setenv("TS_DEBUG_FAKE_GOOS", goos)
	tb.Cleanup(func() { envknob.Setenv("TS_DEBUG_FAKE_GOOS", "") })
}

func pumpIPNBus(watcher *local.IPNBusWatcher) {
	for {
		_, err := watcher.Next()
		if err != nil {
			break
		}
	}
}
