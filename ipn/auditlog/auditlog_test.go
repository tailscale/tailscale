// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package auditlog

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

func TestErrorEvaluator(t *testing.T) {
	errors := []struct {
		err  error
		want bool
	}{
		{controlclient.ErrHTTPFailure, false},
		{controlclient.ErrNoNoiseClient, true},
		{fmt.Errorf("%w: %w", controlclient.ErrNoNoiseClient, errors.New("boom")), true},
		{fmt.Errorf("%w: %w", controlclient.ErrHTTPPostFailure, errors.New("boom")), true},
		{controlclient.ErrNoNodeKey, true},
		{context.Canceled, true},
		{fmt.Errorf("%w: %w", context.Canceled, errors.New("boom")), true},
		{context.DeadlineExceeded, true},
		{controlclient.ErrBadHTTPResponseWithDetails(500, []byte("server melted")), false},
	}

	for _, e := range errors {
		if errorEvaluator(e.err) != e.want {
			t.Fatalf("error evaluator failed for %v", e.err)
		}
	}
}

// TestEnqueueAndFlush enqueues n logs and flushes them.
// We expect all logs to be flushed and for no
// logs to remain in the persitent store.g
func TestEnqueueAndFlush(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 200,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	al.errorEvaluator = testErrorEvaluator

	t.Cleanup(func() {
		al.FlushAndStop(1 * time.Second)
	})
	tstest.ResourceCheck(t)

	al.SetTransport(mockTransport, "test")
	mockTransport.fail = false
	mockTransport.err = retriableError

	wantSent := 16

	var err error
	for i := 0; i < wantSent; i++ {
		err = al.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log %d", i))
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	al.FlushAndStop(1 * time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()

	gotPersisted, wantPersisted := al.storedCountLocked(), 0
	if wantPersisted != gotPersisted {
		t.Fatalf("want %d persisted, got %d", wantPersisted, gotPersisted)
	}

	gotSent, wantSent := mockTransport.sendCount, wantSent
	if wantSent != gotSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}
}

// TestSendOnRestore pushes a pair of logs to the persistent store, and ensures they
// are sent as soon as SetTransport is called then checks to ensure the sent logs no
// longer exist in the store.
func TestSendOnRestore(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	al.errorEvaluator = testErrorEvaluator
	t.Cleanup(func() {
		al.FlushAndStop(1 * time.Second)
	})
	tstest.ResourceCheck(t)

	mockStore.Save("test", []auditLogTxn{
		{Details: "log 1", EventID: "1"},
		{Details: "log 2", EventID: "2"}})

	al.SetTransport(mockTransport, "test")
	al.SetTransport(mockTransport, "test")

	al.FlushAndStop(1 * time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()

	gotPersisted, wantPersisted := al.storedCountLocked(), 0
	if wantPersisted != gotPersisted {
		t.Fatalf("want %d persisted, got %d", wantPersisted, gotPersisted)
	}

	gotSent, wantSent := mockTransport.sendCount, 2
	if wantSent != gotSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}
}

// TestFailureExhaustion enqueues 3 logs, all of which will fail to flush. We then call Flush
// several times to exhaust the retries and expect and expect permanent failure.
func TestFailureExhaustion(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 10 * time.Millisecond,
		err:   retriableError,
		fail:  true,
	}
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 2,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	al.errorEvaluator = testErrorEvaluator
	t.Cleanup(func() {
		al.FlushAndStop(1 * time.Second)
	})
	tstest.ResourceCheck(t)

	al.SetTransport(mockTransport, "test")

	for i := 0; i < 5; i++ {
		log := auditLogTxn{
			Retries:   1,
			Details:   fmt.Sprintf("log %d", i),
			TimeStamp: time.Now(),
			EventID:   fmt.Sprintf("%d", i),
		}
		err := al.enqueue(log, true)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	for i := 0; i < 8; i++ {
		// Flush a 8 times to exhaust all of the retries on all of the the queued logs.
		al.scheduleFlush(5*time.Second, mockTransport)
	}

	al.FlushAndStop(1 * time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()

	wantRequeued, gotRequeued := 0, al.storedCountLocked()

	if wantRequeued != gotRequeued {
		t.Fatalf("want %d failed, got %d", wantRequeued, gotRequeued)
	}

	gotSent, wantSent := mockTransport.sendCount, 0
	if wantSent != gotSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}
}

// TestEnqueueAndFailNoRetry enqueues a set of logs , both of which will fail and are not
// retriable. We then call Flush and expect all to be unsent.
func TestEnqueueAndFailNoRetry(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 10 * time.Millisecond,
		fail:  true,
		err:   nonRetriableError,
	}
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	al.errorEvaluator = testErrorEvaluator
	t.Cleanup(func() {
		al.FlushAndStop(1 * time.Second)
	})
	tstest.ResourceCheck(t)

	al.SetTransport(mockTransport, "test")

	for i := 0; i < 2; i++ {
		log := auditLogTxn{
			Details:   fmt.Sprintf("log %d", i),
			TimeStamp: time.Now(),
			EventID:   fmt.Sprintf("%d", i),
		}
		err := al.enqueue(log, true)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	al.FlushAndStop(1 * time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()

	gotUnsent, wantUnsent := al.storedCountLocked(), 0

	if wantUnsent != gotUnsent {
		t.Fatalf("want %d unsent, got %d", wantUnsent, gotUnsent)
	}

	gotSent, wantSent := mockTransport.sendCount, 0
	if wantSent != gotSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}
}

func TestEnqueueAndRetry(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 0 * time.Millisecond,
		fail:  true,
		err:   retriableError,
	}
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	al.errorEvaluator = testErrorEvaluator
	t.Cleanup(func() {
		al.FlushAndStop(1 * time.Second)
	})
	tstest.ResourceCheck(t)

	al.SetTransport(mockTransport, "test")

	for i := 0; i < 2; i++ {
		log := auditLogTxn{
			Details:   fmt.Sprintf("log %d", i),
			TimeStamp: time.Now(),
			EventID:   fmt.Sprintf("%d", i),
		}
		err := al.enqueue(log, true)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	// Wait slightly less than our retry interval, and set the transport
	// to stop failing.
	time.Sleep(minBackoff - 50*time.Millisecond)
	mockTransport.mu.Lock()
	mockTransport.fail = false
	mockTransport.mu.Unlock()

	// Now wait until after the retry
	time.Sleep(100 * time.Millisecond)

	// And make sure the retry happened
	al.mu.Lock()
	gotUnsent, wantUnsent := al.storedCountLocked(), 0
	al.mu.Unlock()

	if wantUnsent != gotUnsent {
		t.Fatalf("want %d unsent, got %d", wantUnsent, gotUnsent)
	}

	gotSent, wantSent := mockTransport.sendCount, 2
	if wantSent != gotSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}

	al.FlushAndStop(1 * time.Second)
}

// TestEnqueueAndFailTimeout enqueues a set of logs, all of which will fail to flush due to context
// timeouts. With the retry limit set to zero, we expect 0 to be sent to the result
// channel.
func TestEnqueueAndFailTimeout(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 2 * time.Second,
		fail:  true,
		err:   retriableError,
	}
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 10,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	al.errorEvaluator = testErrorEvaluator
	t.Cleanup(func() {
		al.FlushAndStop(1 * time.Second)
	})
	tstest.ResourceCheck(t)

	// Set the default timeout on the queue to a single millisecond, much less
	// than the 2 second delay on the transport.
	al.timeout = time.Millisecond
	al.SetTransport(mockTransport, "test")

	for i := 0; i < 2; i++ {
		log := auditLogTxn{
			Details:   fmt.Sprintf("log %d", i),
			TimeStamp: time.Now(),
			EventID:   fmt.Sprintf("%d", i),
		}
		err := al.enqueue(log, true)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	al.FlushAndStop(1 * time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()

	gotFailed, wantUnsent := al.storedCountLocked(), 2

	if wantUnsent != gotFailed {
		t.Fatalf("want %d unsent, got %d", wantUnsent, gotFailed)
	}
}

// TestStart enqueues a set of logs while the queue is stopped. We then start the queue and expect
// all logs to be flushed.

func TestStart(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:    t,
		fail: true,
		err:  retriableError,
	}
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	al.errorEvaluator = testErrorEvaluator
	t.Cleanup(func() {
		al.FlushAndStop(1 * time.Second)
	})
	tstest.ResourceCheck(t)

	log := auditLogTxn{
		Details:   "log",
		EventID:   "1",
		TimeStamp: time.Now(),
	}
	err := al.enqueue(log, true)
	if err == nil {
		t.Fatalf("enqueue should have failed")
	}

	al.FlushAndStop(time.Second)
	al.mu.Lock()

	// We have not started the transport, so we have no way to persist the logs.
	wantPending, gotPending := 0, al.storedCountLocked()
	if wantPending != gotPending {
		t.Fatalf("want %d pending, got %d", wantPending, gotPending)
	}
	al.mu.Unlock()

	// This second stop should no-op
	al.FlushAndStop(time.Second)

	mockTransport.fail = false
	al.SetTransport(mockTransport, "valid")

	err = al.enqueue(log, true)
	if err != nil {
		t.Fatalf("enqueue should not have failed %v", err)
	}

	al.FlushAndStop(time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()

	gotFailed, wantFailed := al.storedCountLocked(), 0
	if wantFailed != gotFailed {
		t.Fatalf("want %d failed, got %d", wantFailed, gotFailed)
	}
}

// TestLogStoring tests that audit logs are persisted sorted by timestamp, oldest to newest
func TestLogSorting(t *testing.T) {
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	logs := []auditLogTxn{
		{EventID: "1", Details: "log 3", TimeStamp: time.Now().Add(-time.Minute * 1)},
		{EventID: "1", Details: "log 3", TimeStamp: time.Now().Add(-time.Minute * 2)},
		{EventID: "2", Details: "log 2", TimeStamp: time.Now().Add(-time.Minute * 3)},
		{EventID: "3", Details: "log 1", TimeStamp: time.Now().Add(-time.Minute * 4)},
	}

	wantLogs := []auditLogTxn{
		{Details: "log 1"},
		{Details: "log 2"},
		{Details: "log 3"},
	}

	t.Logf("logs: %v", logs)

	mockStore.Save("test", logs)

	gotLogs, err := mockStore.Load("test")
	if err != nil {
		t.Fatalf("failed to restore logs: %v", err)
	}
	gotLogs = deduplicateAndSort(gotLogs)

	for i := range gotLogs {
		if gotLogs[i].Details != wantLogs[i].Details {
			t.Fatalf("want %v, got %v", wantLogs, gotLogs)
		}
	}
}

// mock implementations for testing

type mockAuditLogTransport struct {
	t *testing.T

	mu        sync.Mutex
	sendCount int           // number of logs sent by the transport
	delay     time.Duration // artificial delay before sending
	fail      bool          // true if the transport should fail
	err       error         // error to return when sending logs
}

func (m *mockAuditLogTransport) SendAuditLog(ctx context.Context, _ tailcfg.AuditLogRequest) (err error) {
	m.t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-ctx.Done():
		return m.err
	case <-time.After(m.delay):
	}

	if m.fail {
		return m.err
	} else {
		m.sendCount += 1
		return nil
	}
}

var retriableError = errors.New("retriable error")
var nonRetriableError = errors.New("permenent failure error")

func testErrorEvaluator(err error) bool {
	return errors.Is(err, retriableError)
}
