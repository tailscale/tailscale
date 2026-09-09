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
