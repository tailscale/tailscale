// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/tailcfg"
)

func TestMapRoutineBackoffCanBePaused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		c := &Auto{
			logf:      t.Logf,
			direct:    &Direct{hostinfo: new(tailcfg.Hostinfo)},
			loggedIn:  true,
			mapCtx:    ctx,
			mapCancel: cancel,
			mapDone:   make(chan struct{}),
		}
		defer func() {
			// Cancel directly so cleanup can acquire c.mu even if the
			// backoff incorrectly holds it.
			cancel()
			c.mu.Lock()
			c.closed = true
			c.cancelMapCtxLocked()
			c.cancelAuthCtxLocked()
			for _, ch := range c.unpauseWaiters {
				ch <- false
			}
			c.mu.Unlock()
			<-c.mapDone
		}()

		// The missing server noise key makes PollNetMap fail before any
		// network I/O. Wait until mapRoutine is sleeping in backoff.
		go c.mapRoutine()
		synctest.Wait()

		// A blocked Mutex.Lock is not durably blocked in synctest, so
		// check availability before calling SetPaused.
		if !c.mu.TryLock() {
			t.Fatal("mapRoutine holds the client mutex during backoff")
		}
		c.mu.Unlock()

		start := time.Now()
		c.SetPaused(true)
		synctest.Wait()
		if elapsed := time.Since(start); elapsed != 0 {
			t.Fatalf("pausing during backoff advanced time by %v", elapsed)
		}
		c.mu.Lock()
		numWaiters := len(c.unpauseWaiters)
		c.mu.Unlock()
		if numWaiters != 1 {
			t.Fatalf("got %d unpause waiters; want mapRoutine waiting to unpause", numWaiters)
		}
	})
}

type userProfileUpdateObserver struct{}

func (userProfileUpdateObserver) SetControlClientStatus(Client, Status) {}

func (userProfileUpdateObserver) UpdateUserProfiles(map[tailcfg.UserID]tailcfg.UserProfileView) bool {
	return true
}

func TestMapRoutineStateUpdateUserProfilesConcurrentCancelMapCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Auto{
		logf:      func(string, ...any) {},
		observer:  userProfileUpdateObserver{},
		mapCtx:    ctx,
		mapCancel: cancel,
		loggedIn:  true,
		inMapPoll: true,
	}
	mrs := mapRoutineState{c: c}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			<-start
			for range 2000 {
				c.mu.Lock()
				c.cancelMapCtxLocked()
				c.mu.Unlock()
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			<-start
			for range 2000 {
				mrs.UpdateUserProfiles(nil)
			}
		})
	}

	close(start)
	wg.Wait()

	waitCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := c.observerQueue.Wait(waitCtx); err != nil {
		t.Fatal(err)
	}
	c.observerQueue.Shutdown()
	c.mapCancel()
}
