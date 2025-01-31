// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

var testLogger = func(format string, args ...interface{}) {}

func TestAuditLogQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var logsSent int32
	sendFunc := func(ctx context.Context, log tailcfg.ClientAuditLog) (error, bool) {
		atomic.AddInt32(&logsSent, 1)
		return nil, false
	}

	opts := queuedAuditLoggerOpts{
		RetryDelay: 10 * time.Millisecond,
		RetryCount: 5,
		SendFunc:   sendFunc,
		Logf:       testLogger,
		Ctx:        ctx,
	}

	al := newQueuedAuditLogger(opts)

	al.start()

	testLog := tailcfg.ClientAuditLog{
		Action:  tailcfg.AuditNodeDisconnect,
		Details: "test details",
	}
	al.enqueue(testLog)

	// Wait for log to be sent
	for i := 0; i < 50; i++ {
		if atomic.LoadInt32(&logsSent) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("log was not sent within timeout")
}

func TestAuditLogQueueRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var attempts int32
	sendFunc := func(ctx context.Context, log tailcfg.ClientAuditLog) (error, bool) {
		attempt := atomic.AddInt32(&attempts, 1)
		if attempt == 1 {
			return fmt.Errorf("first attempt failed"), true
		}
		return nil, false
	}

	opts := queuedAuditLoggerOpts{
		RetryDelay: 10 * time.Millisecond,
		RetryCount: 5,
		SendFunc:   sendFunc,
		Logf:       testLogger,
		Ctx:        ctx,
	}

	al := newQueuedAuditLogger(opts)
	al.start()

	testLog := tailcfg.ClientAuditLog{
		Action:  tailcfg.AuditNodeDisconnect,
		Details: "test details",
	}
	al.enqueue(testLog)

	// Wait for second attempt
	for i := 0; i < 50; i++ {
		if atomic.LoadInt32(&attempts) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	got := atomic.LoadInt32(&attempts)
	if got != 2 {
		t.Errorf("got %d attempts, want exactly 2", got)
	}

	al.stopAndFlush()
}

// TestAuditLogQueueCancel tests that the queue can cancel pending logs and
// that said logs are not sent.
func TestAuditLogQueueCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var attempts int32
	sendFunc := func(ctx context.Context, log tailcfg.ClientAuditLog) (error, bool) {
		atomic.AddInt32(&attempts, 1)
		return fmt.Errorf("intentional failure"), true
	}

	opts := queuedAuditLoggerOpts{
		RetryDelay: 1 * time.Microsecond,
		RetryCount: 50000,
		SendFunc:   sendFunc,
		Logf:       testLogger,
		Ctx:        ctx,
	}

	al := newQueuedAuditLogger(opts)
	al.start()

	batchSize := 50

	for i := 0; i < batchSize; i++ {
		al.enqueue(tailcfg.ClientAuditLog{
			Action:  tailcfg.AuditNodeDisconnect,
			Details: "test details",
		})
	}

	al.stopAndFlush()
	al.start()
	time.Sleep(10 * time.Millisecond)

	for i := 0; i < batchSize; i++ {
		al.enqueue(tailcfg.ClientAuditLog{
			Action:  tailcfg.AuditNodeDisconnect,
			Details: "test details",
		})
	}

	al.stopAndFlush()
	pendingCount := len(al.pending)

	if pendingCount != batchSize*2 {
		t.Errorf("got %d pending logs after cancel, want 100", pendingCount)
	}

	al.start()
	// Let some drain work happen
	time.Sleep(100 * time.Millisecond)

	// Cancel pending logs
	al.cancelPending()

	// Verify no pending logs
	pendingCount = len(al.pending)

	if pendingCount != 0 {
		t.Errorf("got %d pending logs after cancel, want 0", pendingCount)
	}

	if attempts == 0 {
		t.Errorf("got %d attempts, want somthing north of 100000", attempts)
	}
}

// TestAuditLogQueuePauseRestart tests that the audit log queue can be
// paused and restarted, and that logs are sent after restarting.
func TestAuditLogQueuePauseRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var attempts int32
	sendFunc := func(ctx context.Context, log tailcfg.ClientAuditLog) (error, bool) {
		atomic.AddInt32(&attempts, 1)
		return fmt.Errorf("intentional failure"), true
	}

	var logs []string
	testLogger := func(format string, args ...interface{}) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}

	opts := queuedAuditLoggerOpts{
		RetryDelay: 1 * time.Microsecond,
		RetryCount: 50000,
		SendFunc:   sendFunc,
		Logf:       testLogger,
		Ctx:        ctx,
	}

	al := newQueuedAuditLogger(opts)
	al.start()

	// Enqueue 50 logs
	for i := 0; i < 50; i++ {
		al.enqueue(tailcfg.ClientAuditLog{
			Action:  tailcfg.AuditNodeDisconnect,
			Details: "test details",
		})
	}

	// Try draining for a while
	time.Sleep(10 * time.Millisecond)
	al.stopAndFlush()

	pendingCount := len(al.pending)
	if pendingCount != 50 {
		t.Errorf("got %d pending logs, want 50", pendingCount)
	}

	sendFunc = func(ctx context.Context, log tailcfg.ClientAuditLog) (error, bool) {
		atomic.AddInt32(&attempts, 1)
		return nil, false
	}
	//We're paused so mutating this is safe
	al.sendFunc = sendFunc

	al.start()

	// Cycle for a bit, waiting for the queue to fully drain.
	for i := 0; i < 50; i++ {
		al.mu.Lock()
		l := len(al.pending)
		al.mu.Unlock()
		if l == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	al.stopAndFlush()
	pendingCount = len(al.pending)
	if pendingCount != 0 {
		t.Errorf("got %d pending logs, want 0", pendingCount)
	}
}

// TestAuditLogQueueMaxRetries tests that the queue will stop retrying when
// the max number of retries is reached.
func TestAuditLogQueueMaxRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var attempts int32
	sendFunc := func(ctx context.Context, log tailcfg.ClientAuditLog) (error, bool) {
		atomic.AddInt32(&attempts, 1)
		return fmt.Errorf("intentional failure"), true
	}

	var logMessages []string
	l := func(format string, args ...interface{}) {
		logMessages = append(logMessages, fmt.Sprintf(format, args...))
	}

	maxRetries := 5
	opts := queuedAuditLoggerOpts{
		RetryDelay: 1 * time.Microsecond,
		RetryCount: maxRetries,
		SendFunc:   sendFunc,
		Logf:       l,
		Ctx:        ctx,
	}

	al := newQueuedAuditLogger(opts)
	al.start()
	defer al.stopAndFlush()

	al.enqueue(tailcfg.ClientAuditLog{
		Action:  "test-action",
		Details: "test details",
	})

	// Wait for all retries
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&attempts) >= int32(maxRetries) {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}

	got := atomic.LoadInt32(&attempts)
	if got != int32(maxRetries) {
		t.Errorf("got %d attempts, want exactly %d", got, maxRetries)
	}

	// Verify no pending logs after max retries
	al.mu.Lock()
	pendingCount := len(al.pending)
	al.mu.Unlock()
	if pendingCount != 0 {
		t.Errorf("got %d pending logs after max retries, want 0", pendingCount)
	}

	// Verify log message about max retries
	wantLogMessage := fmt.Sprintf("after %d retries", maxRetries)
	var foundMessage bool
	for _, msg := range logMessages {
		if strings.Contains(msg, wantLogMessage) {
			foundMessage = true
			break
		}
	}
	if !foundMessage {
		t.Errorf("did not find expected log message containing %q", wantLogMessage)
	}
}
