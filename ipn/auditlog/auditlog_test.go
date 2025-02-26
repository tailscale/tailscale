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

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
)

// TestEnqueueAndFlush enqueues n logs and flushes them.
// We start with a failing transport to ensure we excersize the re-queuing and
// retry logic.  In the end, We expect all logs to be flushed and for no
// logs to remain in the persitent store.
func TestEnqueueAndFlush(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 200,
		Logf:       t.Logf,
		Store:      mockStore,
	})

	t.Cleanup(func() {
		al.stop()
	})
	al.SetTransport(mockTransport, "test")
	mockTransport.fail = true
	mockTransport.retry = true

	wantSent := 16

	var result <-chan FlushResult
	var err error
	for i := 0; i < wantSent; i++ {
		log := AuditLogTxn{
			Details: fmt.Sprintf("log %d", i),
		}
		result, err = al.Enqueue(log)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	// Some stuff is probably still sending at this point.  Great, some will send,
	// there should be some failures in the queue.
	mockTransport.mu.Lock()
	mockTransport.fail = false
	mockTransport.mu.Unlock()

	pendingCount := <-result

	// Make sure the internal queue count matches the number of logs we sent
	al.mu.Lock()
	gotPendingCount, wantPendingCount := FlushResult(len(al.pending)), pendingCount
	al.mu.Unlock()

	if gotPendingCount != wantPendingCount {
		t.Fatalf("want %d pending, got %d", wantPendingCount, gotPendingCount)
	}

	// Now, the transport won't fail.  Flushing here should clear the queue.
	result = al.Flush(5*time.Second, nil)
	gotRequeued, wantRequeued := <-result, FlushResult(0)

	if gotRequeued != wantRequeued {
		t.Fatalf("want %d requeued, got %d", wantRequeued, gotRequeued)
	}

	gotPersisted, wantPersisted := al.persistedCountLocked(), 0
	if wantPersisted != gotPersisted {
		t.Fatalf("want %d persisted, got %d", wantPersisted, gotPersisted)
	}

}

// TestSendOnRestore pushes a pair of logs to the persistent store, and ensures they
// are sent as soon as SetTranport is called then checks to ensure the sent logs no
// longer exist in the store.
func TestSendOnRestore(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})

	// audit-logs is prepended to the key and we need an EventID here since
	// we're writing directly to the mockStore (rather than via enqueue)
	mockStore.Persist("audit-logs-test", []AuditLogTxn{
		{Details: "log 1", EventID: "1"},
		{Details: "log 2", EventID: "2"}})

	t.Cleanup(func() {
		al.stop()
	})

	c := al.SetTransport(mockTransport, "test")
	gotUnsent, wantUnsent := <-c, FlushResult(0)

	if wantUnsent != gotUnsent {
		t.Fatalf("want %d unsent, got %d", wantUnsent, gotUnsent)
	}

	gotPersisted, wantPersisted := al.persistedCountLocked(), 0
	if wantPersisted != gotPersisted {
		t.Fatalf("want %d persisted, got %d", wantPersisted, gotPersisted)
	}
}

// TestFailureExhaustion enqueues 3 logs, all of which will fail to flush. We then call Flush
// several times to exhaust the retries and expect and expect permanent failure.
func TestFailureExhaustion(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 10 * time.Millisecond,
		retry: true,
		fail:  true,
	}
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 2,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	al.SetTransport(mockTransport, "test")

	t.Cleanup(func() {
		al.stop()
	})

	for i := 0; i < 5; i++ {
		log := AuditLogTxn{
			Retries: 1,
			Details: fmt.Sprintf("log %d", i),
		}
		_, err := al.Enqueue(log)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	wantRequeued, gotRequeued := FlushResult(0), FlushResult(0)

	for i := 0; i < 8; i++ {
		// Flush a 3 times to exhaust all of the retries on all of the the queued logs.
		flushed := al.Flush(5*time.Second, mockTransport)
		gotRequeued = <-flushed
	}

	if wantRequeued != gotRequeued {
		t.Fatalf("want %d failed, got %d", wantRequeued, gotRequeued)
	}
}

// TestEnqueueAndFail enqueues a set of logs logs, both of which will fail and are not
// retriable. We then call Flush and expect all to be unsent.
func TestEnqueueAndFail(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 10 * time.Millisecond,
		fail:  true,
		retry: false,
	}
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	al.SetTransport(mockTransport, "test")

	t.Cleanup(func() {
		al.stop()
	})

	unsentCount := FlushResult(0)
	for i := 0; i < 2; i++ {
		log := AuditLogTxn{
			Details: fmt.Sprintf("log %d", i),
		}
		result, err := al.Enqueue(log)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
		select {
		case unsentCount = <-result:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for logs to be flushed")
		}
	}

	gotUnsent, wantUnsent := int(unsentCount), 0

	if wantUnsent != gotUnsent {
		t.Fatalf("want %d unsent, got %d", wantUnsent, gotUnsent)
	}
}

// TestEnqueueAndFailTimeout enqueues a set of logs, all of which will fail to flush due to context
// timeouts. With the retry limit set to zero, we expect 0 to be sent to the result
// channel.
func TestEnqueueAndFailTimeout(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 2 * time.Second,
		fail:  true,
		retry: false,
	}
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 0,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	al.SetTransport(mockTransport, "test")

	t.Cleanup(func() {
		al.stop()
	})

	al.timeout = time.Millisecond

	unsentCount := FlushResult(0)
	for i := 0; i < 2; i++ {
		log := AuditLogTxn{
			Details: fmt.Sprintf("log %d", i),
		}
		result, err := al.Enqueue(log)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
		select {
		case unsentCount = <-result:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for logs to be flushed")
		}
	}

	gotFailed, wantUnsent := unsentCount, FlushResult(0)

	if wantUnsent != gotFailed {
		t.Fatalf("want %d unsent, got %d", wantUnsent, gotFailed)
	}
}

// TestStart enqueues a set of logs while the queue is stopped. We then start the queue and expect
// all logs to be flushed.
func TestStart(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})

	t.Cleanup(func() {
		al.stop()
	})

	log := AuditLogTxn{
		Details: "log",
	}

	// Toss a couple of logs at the stopped queue.  These should get
	// persisted
	for i := 0; i < 2; i++ {
		result, err := al.Enqueue(log)
		if err != nil {
			t.Fatalf("enqueue failed %v", err)
		}

		wantPending, gotPending := FlushResult(i+1), <-result
		if wantPending != gotPending {
			t.Fatalf("want %d pending, got %d", wantPending, gotPending)
		}
	}

	al.SetTransport(mockTransport, "test")

	// Submit another one after starting
	result, err := al.Enqueue(log)
	if err != nil {
		t.Fatalf("enqueue failed %v", err)
	}

	gotPending, wantPending := <-result, FlushResult(0)

	if wantPending != gotPending {
		t.Fatalf("want %d pending, got %d", wantPending, wantPending)
	}
}

func TestStop(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		fail:  true,
		retry: true,
	}
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	al.SetTransport(mockTransport, "test")

	t.Cleanup(func() {
		al.stop()
	})

	log := AuditLogTxn{
		Details: "log",
	}
	result, err := al.Enqueue(log)
	if err != nil {
		t.Fatalf("enqueue failed %v", err)
	}

	wantPending, gotPending := FlushResult(1), <-result
	if wantPending != gotPending {
		t.Fatalf("want %d pending, got %d", wantPending, gotPending)
	}

	al.stop()
	// This second stop should no-op
	al.stop()

	mockTransport.fail = false
	result = al.SetTransport(mockTransport, "")

	gotFailed, wantFailed := <-result, FlushResult(0)
	if wantFailed != gotFailed {
		t.Fatalf("want %d failed, got %d", wantFailed, gotFailed)
	}
}

// TestFlushInAllStates tests that Flush writes a value to the returned channel
// regardless of what state the logger is in.
func TestFlushInAllStates(t *testing.T) {
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	al.SetTransport(&mockAuditLogTransport{t: t}, "test")

	c := al.Flush(time.Second, nil)
	<-c
	al.stop()

	al = NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})

	// Flush  write a value to the returned channel even in the
	// case of a stopped queue
	c = al.Flush(time.Second, nil)
	<-c
	al.stop()

	// Nothing to check, but we have to get here...
}

// TestLogStoring tests that audit logs are persisted sorted by timestamp, oldest to newest
func TestLogSorting(t *testing.T) {
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	logs := []AuditLogTxn{
		{Details: "log 3", TimeStamp: time.Now().Add(-time.Minute * 1)},
		{Details: "log 2", TimeStamp: time.Now().Add(-time.Minute * 2)},
		{Details: "log 1", TimeStamp: time.Now().Add(-time.Minute * 3)},
	}

	wantLogs := []AuditLogTxn{
		{Details: "log 1"},
		{Details: "log 2"},
		{Details: "log 3"},
	}

	mockStore.Persist("test", logs)

	gotLogs, err := mockStore.Restore("test")
	if err != nil {
		t.Fatalf("failed to restore logs: %v", err)
	}

	for i := range gotLogs {
		if gotLogs[i].Details != wantLogs[i].Details {
			t.Fatalf("want %s, got %s", wantLogs[i].Details, gotLogs[i].Details)
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
	retry     bool          // if true, retr
}

func (m *mockAuditLogTransport) SendAuditLog(ctx context.Context, _ tailcfg.AuditLogRequest) (err error, retriable bool) {
	m.t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-ctx.Done():
		m.t.Logf("test flush context cancelled")
		return errors.New("Context Cancelled"), m.retry
	case <-time.After(m.delay):
	}

	if m.fail {
		return errors.New("Failed"), m.retry
	} else {
		m.sendCount += 1
		return nil, false
	}
}
