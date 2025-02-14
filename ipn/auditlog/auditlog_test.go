// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package auditlog

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
)

// TestEnqueueAndFlush enqueues n logs and flushes them.
// We expect all logs to be flushed.
func TestEnqueueAndFlush(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	q := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	q.SetTransport(mockTransport, "test")

	t.Cleanup(func() {
		q.stop()
	})

	wantSent := 5
	wantFailed, gotFailed := FlushResult(0), FlushResult(0)

	for i := 0; i < wantSent; i++ {
		log := PendingAuditLog{
			Details: fmt.Sprintf("log %d", i),
		}
		result, err := q.Enqueue(log)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
		select {
		case gotFailed = <-result:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for logs to be flushed")
		}
	}

	gotSent := mockTransport.sendCount
	if wantSent != gotSent {
		t.Fatalf("want %d flushed, got %d", wantSent, gotSent)
	}

	if wantFailed != gotFailed {
		t.Fatalf("want %d failed, got %d", wantFailed, gotFailed)
	}
}

// TestFailuresFlushLater enqueues a set of logs, all of which will fail to flush.
// We then set the transport to not-fail, call Flush and expect all transactions to
// complete successfully.
func TestFailuresFlushLater(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 10 * time.Millisecond,
		retry: true,
		fail:  true,
	}
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	q := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	q.SetTransport(mockTransport, "test")

	t.Cleanup(func() {
		q.stop()
	})

	for i := 0; i < 5; i++ {
		log := PendingAuditLog{
			Details: fmt.Sprintf("log %d", i),
		}
		result, err := q.Enqueue(log)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
		<-result
	}

	mockTransport.mu.Lock()
	mockTransport.fail = false
	mockTransport.mu.Unlock()

	result := q.Flush(5*time.Second, nil)

	wantFailed, gotFailed := FlushResult(0), FlushResult(0)

	select {
	case gotFailed = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for logs to be flushed")
	}

	wantSent, gotSent := 5, mockTransport.sendCount

	if wantSent != gotSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}

	if wantFailed != gotFailed {
		t.Fatalf("want %d failed, got %d", wantFailed, gotFailed)
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

	q := NewAuditLogger(Opts{
		RetryLimit: 3,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	q.SetTransport(mockTransport, "test")

	t.Cleanup(func() {
		q.stop()
	})

	for i := 0; i < 3; i++ {
		log := PendingAuditLog{
			Details: fmt.Sprintf("log %d", i),
		}
		_, err := q.Enqueue(log)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	wantFailed, gotFailed := FlushResult(0), FlushResult(0)
	for i := 0; i < 3; i++ {
		flushed := q.Flush(5*time.Second, mockTransport)
		gotFailed = <-flushed
	}

	wantSent, gotSent := 0, mockTransport.sendCount

	if wantSent != gotSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}

	if wantFailed != gotFailed {
		t.Fatalf("want %d failed, got %d", wantFailed, gotFailed)
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

	q := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	q.SetTransport(mockTransport, "test")

	t.Cleanup(func() {
		q.stop()
	})

	unsentCount := FlushResult(0)
	for i := 0; i < 2; i++ {
		log := PendingAuditLog{
			Details: fmt.Sprintf("log %d", i),
		}
		result, err := q.Enqueue(log)
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

	q := NewAuditLogger(Opts{
		RetryLimit: 0,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	q.SetTransport(mockTransport, "test")

	t.Cleanup(func() {
		q.stop()
	})

	q.timeout = time.Millisecond

	unsentCount := FlushResult(0)
	for i := 0; i < 2; i++ {
		log := PendingAuditLog{
			Details: fmt.Sprintf("log %d", i),
		}
		result, err := q.Enqueue(log)
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

	q := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})

	t.Cleanup(func() {
		q.stop()
	})

	log := PendingAuditLog{
		Details: "log",
	}

	// Toss a couple of logs at the stopped queue.  These should get
	// persisted
	for i := 0; i < 2; i++ {
		result, err := q.Enqueue(log)
		if err != nil {
			t.Fatalf("enqueue failed %v", err)
		}

		wantPending, gotPending := FlushResult(i+1), <-result
		if wantPending != gotPending {
			t.Fatalf("want %d pending, got %d", wantPending, gotPending)
		}
	}

	q.SetTransport(mockTransport, "test")

	// Submit another one after starting
	result, err := q.Enqueue(log)
	if err != nil {
		t.Fatalf("enqueue failed %v", err)
	}

	gotPending, wantPending := <-result, FlushResult(0)
	// 3 - two while stopped, one after starting
	wantSent, gotSent := 3, mockTransport.sendCount

	if gotSent != wantSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}

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

	q := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	q.SetTransport(mockTransport, "test")

	t.Cleanup(func() {
		q.stop()
	})

	log := PendingAuditLog{
		Details: "log",
	}
	result, err := q.Enqueue(log)
	if err != nil {
		t.Fatalf("enqueue failed %v", err)
	}

	wantPending, gotPending := FlushResult(1), <-result
	if wantPending != gotPending {
		t.Fatalf("want %d pending, got %d", wantPending, gotPending)
	}

	q.stop()
	// This second stop should no-op
	q.stop()

	wantSent, gotSent := 0, mockTransport.sendCount
	if wantSent != gotSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}

	mockTransport.fail = false
	result = q.SetTransport(mockTransport, "")

	gotFailed, wantFailed := <-result, FlushResult(0)
	if wantFailed != gotFailed {
		t.Fatalf("want %d failed, got %d", wantFailed, gotFailed)
	}
}

// TestFlushInAllStates tests that Flush writes a value to the returned channel
// regardless of what state the logger is in.
func TestFlushInAllStates(t *testing.T) {
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	q1 := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	q1.SetTransport(&mockAuditLogTransport{t: t}, "test")

	c := q1.Flush(time.Second, nil)
	<-c
	q1.stop()

	q1 = NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})

	// Flush  write a value to the returned channel even in the
	// case of a stopped queue
	c = q1.Flush(time.Second, nil)
	<-c
	q1.stop()

	// Nothing to check, but we have to get here...
}

// TestLogStoring tests that audit logs are persisted sorted by timestamp, oldest to newest
func TestLogSorting(t *testing.T) {
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	logs := []PendingAuditLog{
		{Details: "log 3", TimeStamp: time.Now().Add(-time.Minute * 1)},
		{Details: "log 2", TimeStamp: time.Now().Add(-time.Minute * 2)},
		{Details: "log 1", TimeStamp: time.Now().Add(-time.Minute * 3)},
	}

	wantLogs := []PendingAuditLog{
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

// TestLogSizeLimit tests that logs are trimmed to fit within the size limit
func TestLogSizeLimit(t *testing.T) {
	sizeLimit := 1024
	longDetails := string(repeatedBytes(sizeLimit, t))
	mockStore := NewStateStore(&mem.Store{}, t.Logf)

	logs := []PendingAuditLog{
		{Details: longDetails},
		{Details: "log 2"},
		{Details: "log 3"},
	}

	wantLogs := []PendingAuditLog{
		{Details: "log 2"},
		{Details: "log 3"},
	}

	// Cast mockStore to AuditLogPersistentStore
	store := mockStore.(*StateStore)

	gotLogs, err := store.truncateLogs(logs, sizeLimit)
	if err != nil {
		t.Fatalf("failed to limit log size: %v", err)
	}

	if !reflect.DeepEqual(gotLogs, wantLogs) {
		t.Fatalf("want %v, got %v", wantLogs, gotLogs)
	}
}

func repeatedBytes(n int, t *testing.T) []byte {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return b
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
