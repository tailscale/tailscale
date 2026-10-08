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
	"tailscale.com/tstime"
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

func TestWaitRetryAfter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		retryAfter  time.Duration
		cancelAfter time.Duration
		want        time.Duration
	}{
		{
			name:        "returns_on_context_cancellation",
			retryAfter:  time.Minute,
			cancelAfter: time.Second,
			want:        time.Second,
		},
		{
			name:       "returns_on_specified_retry_time",
			retryAfter: time.Minute,
			want:       time.Minute,
		},
		{
			name:       "does_not_exceed_max_wait_time",
			retryAfter: maxRetryWindow + 1,
			want:       maxRetryWindow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				if tt.cancelAfter != 0 {
					time.AfterFunc(tt.cancelAfter, cancel)
				}

				c := &Auto{
					clock: tstime.StdClock{},
					logf:  t.Logf,
				}
				start := time.Now()
				c.waitRetryAfter(ctx, "test", &rateLimitError{retryAfter: tt.retryAfter})
				if got := time.Since(start); got != tt.want {
					t.Errorf("waitRetryAfter; got = %v, want %v", got, tt.want)
				}
			})
		})
	}
}
