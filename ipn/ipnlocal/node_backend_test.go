// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"testing"
	"time"

	"tailscale.com/util/eventbus"
)

func TestNodeBackendReadiness(t *testing.T) {
	nb := newNodeBackend(t.Context(), eventbus.New())

	// The node backend is not ready until [nodeBackend.ready] is called,
	// and [nodeBackend.Wait] should fail with [context.DeadlineExceeded].
	ctx, cancelCtx := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelCtx()
	if err := nb.Wait(ctx); err != ctx.Err() {
		t.Fatalf("Wait: got %v; want %v", err, ctx.Err())
	}

	// Start a goroutine to wait for the node backend to become ready.
	waitDone := make(chan struct{})
	go func() {
		if err := nb.Wait(context.Background()); err != nil {
			t.Errorf("Wait: got %v; want nil", err)
		}
		close(waitDone)
	}()

	// Call [nodeBackend.ready] to indicate that the node backend is now ready.
	go nb.ready()

	// Once the backend is called, [nodeBackend.Wait] should return immediately without error.
	if err := nb.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: got %v; want nil", err)
	}
	// And any pending waiters should also be unblocked.
	<-waitDone
}

func TestNodeBackendShutdown(t *testing.T) {
	nb := newNodeBackend(t.Context(), eventbus.New())

	shutdownCause := errors.New("test shutdown")

	// Start a goroutine to wait for the node backend to become ready.
	// This test expects it to block until the node backend shuts down
	// and then return the specified shutdown cause.
	waitDone := make(chan struct{})
	go func() {
		if err := nb.Wait(context.Background()); err != shutdownCause {
			t.Errorf("Wait: got %v; want %v", err, shutdownCause)
		}
		close(waitDone)
	}()

	// Call [nodeBackend.shutdown] to indicate that the node backend is shutting down.
	nb.shutdown(shutdownCause)

	// Calling it again is fine, but should not change the shutdown cause.
	nb.shutdown(errors.New("test shutdown again"))

	// After shutdown, [nodeBackend.Wait] should return with the specified shutdown cause.
	if err := nb.Wait(context.Background()); err != shutdownCause {
		t.Fatalf("Wait: got %v; want %v", err, shutdownCause)
	}
	// The context associated with the node backend should also be cancelled
	// and its cancellation cause should match the shutdown cause.
	if err := nb.Context().Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Context.Err: got %v; want %v", err, context.Canceled)
	}
	if cause := context.Cause(nb.Context()); cause != shutdownCause {
		t.Fatalf("Cause: got %v; want %v", cause, shutdownCause)
	}
	// And any pending waiters should also be unblocked.
	<-waitDone
}

func TestNodeBackendReadyAfterShutdown(t *testing.T) {
	nb := newNodeBackend(t.Context(), eventbus.New())

	shutdownCause := errors.New("test shutdown")
	nb.shutdown(shutdownCause)
	nb.ready() // Calling ready after shutdown is a no-op, but should not panic, etc.
	if err := nb.Wait(context.Background()); err != shutdownCause {
		t.Fatalf("Wait: got %v; want %v", err, shutdownCause)
	}
}

func TestNodeBackendParentContextCancellation(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	nb := newNodeBackend(ctx, eventbus.New())

	cancelCtx()

	// Cancelling the parent context should cause [nodeBackend.Wait]
	// to return with [context.Canceled].
	if err := nb.Wait(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait: got %v; want %v", err, context.Canceled)
	}

	// And the node backend's context should also be cancelled.
	if err := nb.Context().Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Context.Err: got %v; want %v", err, context.Canceled)
	}
}

func TestNodeBackendConcurrentReadyAndShutdown(t *testing.T) {
	nb := newNodeBackend(t.Context(), eventbus.New())

	// Calling [nodeBackend.ready] and [nodeBackend.shutdown] concurrently
	// should not cause issues, and [nodeBackend.Wait] should unblock,
	// but the result of [nodeBackend.Wait] is intentionally undefined.
	go nb.ready()
	go nb.shutdown(errors.New("test shutdown"))

	nb.Wait(context.Background())
}
