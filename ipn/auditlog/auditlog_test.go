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

func TestRestartAndRestart(t *testing.T) {
	mockStore := NewAuditLogStateStore(&mem.Store{}, t.Logf)

	q1 := NewAuditLoggerStarted(AuditLoggerOpts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
		ProfileID:  "test",
	})

	c := q1.Flush(time.Second, nil)
	<-c
	q1.Stop()

	q1 = NewAuditLoggerStarted(AuditLoggerOpts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
		ProfileID:  "test2",
	})

	c = q1.Flush(time.Second, nil)
	<-c
	q1.Stop()

	q1 = NewAuditLoggerStarted(AuditLoggerOpts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
		ProfileID:  "test2",
	})

	c = q1.Flush(time.Second, nil)
	<-c
	q1.Stop()
}

// TestEnqueueAndFlushAuditLogs enqueues n logs and flushes them. We expect both logs to be flushed.
func TestEnqueueAndFlushAuditLogs(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	mockStore := NewAuditLogStateStore(&mem.Store{}, t.Logf)

	q := NewAuditLoggerStarted(AuditLoggerOpts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Transport:  mockTransport,
		Store:      mockStore,
		ProfileID:  "test",
	})

	t.Cleanup(func() {
		q.Stop()
	})

	wantSent := 2
	wantFailed, gotFailed := 0, 0

	for i := 0; i < wantSent; i++ {
		log := PendingAuditLog{
			ProfileID: "test",
			Details:   fmt.Sprintf("log %d", i),
		}
		result, err := q.EnqueueAuditLog(log)
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

// TestFailuresFlushLater enqueues 5 logs, all of which will fail to flush. We then call Flush and expect
// all transactions to complete successfully.
func TestFailuresFlushLater(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 10 * time.Millisecond,
		retry: true,
		fail:  true,
	}
	mockStore := NewAuditLogStateStore(&mem.Store{}, t.Logf)

	q := NewAuditLoggerStarted(AuditLoggerOpts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Transport:  mockTransport,
		Store:      mockStore,
		ProfileID:  "test",
	})

	t.Cleanup(func() {
		q.Stop()
	})

	for i := 0; i < 5; i++ {
		log := PendingAuditLog{
			ProfileID: "test",
			Details:   fmt.Sprintf("log %d", i),
		}
		result, err := q.EnqueueAuditLog(log)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
		<-result
	}

	mockTransport.mu.Lock()
	mockTransport.fail = false
	mockTransport.mu.Unlock()

	result := q.Flush(5*time.Second, mockTransport)

	gotFailed, wantFailed := 0, 0

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

// TestFailureExhaustion enqueues 3 logs, all of which will fail to flush. We then call Flush 3 times and expect
// exhausting the retries and expect permanent failure.
func TestFailureExhaustion(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 10 * time.Millisecond,
		retry: true,
		fail:  true,
	}
	mockStore := NewAuditLogStateStore(&mem.Store{}, t.Logf)

	q := NewAuditLoggerStarted(AuditLoggerOpts{
		RetryLimit: 3,
		Logf:       t.Logf,
		Transport:  mockTransport,
		Store:      mockStore,
		ProfileID:  "test",
	})

	t.Cleanup(func() {
		q.Stop()
	})

	for i := 0; i < 3; i++ {
		log := PendingAuditLog{
			ProfileID: "test",
			Details:   fmt.Sprintf("log %d", i),
		}
		_, err := q.EnqueueAuditLog(log)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	wantFailed, gotFailed := 0, 0
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

// TestEnqueueAndFail enqueues 2 logs, both of which will fail to flush. We then call Flush and expect
// 2 unsent logs.
func TestEnqueueAndFail(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 10 * time.Millisecond,
		fail:  true,
		retry: false,
	}
	mockStore := NewAuditLogStateStore(&mem.Store{}, t.Logf)

	q := NewAuditLoggerStarted(AuditLoggerOpts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Transport:  mockTransport,
		Store:      mockStore,
		ProfileID:  "test",
	})

	t.Cleanup(func() {
		q.Stop()
	})

	unsentCount := 0
	for i := 0; i < 2; i++ {
		log := PendingAuditLog{
			ProfileID: "test",
			Details:   fmt.Sprintf("log %d", i),
		}
		result, err := q.EnqueueAuditLog(log)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
		select {
		case unsentCount = <-result:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for logs to be flushed")
		}
	}

	gotUnsent, wantUnsent := unsentCount, 0

	if wantUnsent != gotUnsent {
		t.Fatalf("want %d unsent, got %d", wantUnsent, gotUnsent)
	}
}

// TestEnqueueAndFailTimeout enqueues 2 logs, both of which will fail to flush due to context
// timeouts. With the retry count set to zero, we expect 0 to be sent to the unsent
// channel.
func TestEnqueueAndFailTimeout(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 2 * time.Second,
		fail:  true,
		retry: false,
	}
	mockStore := NewAuditLogStateStore(&mem.Store{}, t.Logf)

	q := NewAuditLoggerStarted(AuditLoggerOpts{
		RetryLimit: 0,
		Logf:       t.Logf,
		Transport:  mockTransport,
		Store:      mockStore,
		ProfileID:  "test",
	})

	t.Cleanup(func() {
		q.Stop()
	})

	q.timeout = time.Millisecond

	unsentCount := 0
	for i := 0; i < 2; i++ {
		log := PendingAuditLog{
			ProfileID: "test",
			Details:   fmt.Sprintf("log %d", i),
		}
		result, err := q.EnqueueAuditLog(log)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
		select {
		case unsentCount = <-result:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for logs to be flushed")
		}
	}

	gotFailed, wantUnsent := unsentCount, 0

	if wantUnsent != gotFailed {
		t.Fatalf("want %d unsent, got %d", wantUnsent, gotFailed)
	}
}

// TestStart enqueues 2 logs while the queue is stopped. We then start the queue and expect
// all logs to be flushed.
func TestStart(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	mockStore := NewAuditLogStateStore(&mem.Store{}, t.Logf)

	q := NewAuditLogger(AuditLoggerOpts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Transport:  mockTransport,
		Store:      mockStore,
		ProfileID:  "test",
	})

	t.Cleanup(func() {
		q.Stop()
	})

	log := PendingAuditLog{
		ProfileID: "test",
		Details:   "log",
	}

	// Toss a couple of logs at the stopped queue.  These should get
	// persisted
	for i := 0; i < 2; i++ {
		result, err := q.EnqueueAuditLog(log)
		if err != nil {
			t.Fatalf("enqueue failed %v", err)
		}

		wantPending, gotPending := 1, <-result
		if wantPending != gotPending {
			t.Fatalf("want %d pending, got %d", wantPending, gotPending)
		}
	}

	q.Start(mockTransport)

	// Submit another one after starting
	result, err := q.EnqueueAuditLog(log)
	if err != nil {
		t.Fatalf("enqueue failed %v", err)
	}

	gotPending, wantPending := <-result, 0
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
	mockStore := NewAuditLogStateStore(&mem.Store{}, t.Logf)

	q := NewAuditLoggerStarted(AuditLoggerOpts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Transport:  mockTransport,
		Store:      mockStore,
		ProfileID:  "test",
	})

	t.Cleanup(func() {
		q.Stop()
	})

	log := PendingAuditLog{
		ProfileID: "test",
		Details:   "log",
	}
	result, err := q.EnqueueAuditLog(log)
	if err != nil {
		t.Fatalf("enqueue failed %v", err)
	}

	wantPending, gotPending := 1, <-result
	if wantPending != gotPending {
		t.Fatalf("want %d pending, got %d", wantPending, gotPending)
	}

	q.Stop()
	// This second stop should no-op
	q.Stop()

	wantSent, gotSent := 0, mockTransport.sendCount
	if wantSent != gotSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}

	mockTransport.fail = false
	result = q.Start(mockTransport)

	gotFailed, wantFailed := <-result, 0
	if wantFailed != gotFailed {
		t.Fatalf("want %d failed, got %d", wantFailed, gotFailed)
	}
}

// TestLogStoring tests that audit logs are persisted sorted by timestamp, oldest to newest
func TestLogSorting(t *testing.T) {
	mockStore := NewAuditLogStateStore(&mem.Store{}, t.Logf)

	logs := []PendingAuditLog{
		{ProfileID: "test", Details: "log 3", TimeStamp: time.Now().Add(-time.Hour * 1)},
		{ProfileID: "test", Details: "log 2", TimeStamp: time.Now().Add(-time.Hour * 2)},
		{ProfileID: "test", Details: "log 1", TimeStamp: time.Now().Add(-time.Hour * 3)},
	}

	wantLogs := []PendingAuditLog{
		{ProfileID: "test", Details: "log 1"},
		{ProfileID: "test", Details: "log 2"},
		{ProfileID: "test", Details: "log 3"},
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
	mockStore := NewAuditLogStateStore(&mem.Store{}, t.Logf)

	logs := []PendingAuditLog{
		{ProfileID: "test", Details: longDetails},
		{ProfileID: "test", Details: "log 2"},
		{ProfileID: "test", Details: "log 3"},
	}

	wantLogs := []PendingAuditLog{
		{ProfileID: "test", Details: "log 2"},
		{ProfileID: "test", Details: "log 3"},
	}

	// Cast mockStore to AuditLogPersistentStore
	store := mockStore.(*AuditLogStateStore)

	gotLogs, err := store.limitLogSize(logs, sizeLimit)
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
