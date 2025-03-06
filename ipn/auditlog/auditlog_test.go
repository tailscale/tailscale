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

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

func expectNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func expectError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error not found")
	}
}

// auditLoggerForTest creates an auditLogger for you and cleans it up
// (and ensures no goroutines are leaked) when the test is done.
func auditLoggerForTest(t *testing.T, opts Opts) *Logger {
	t.Helper()
	if opts.Logf == nil {
		t.Fatalf("opts.Logf must be set")
	}
	if opts.Store == nil {
		t.Fatalf("opts.Store must be set")
	}

	a := NewLogger(opts)

	t.Cleanup(func() {
		a.FlushAndStop(5 * time.Second)
	})
	tstest.ResourceCheck(t)
	return a
}

// TestEnqueueAndFlush enqueues n logs and flushes them.
// We expect all logs to be flushed and for no
// logs to remain in the store once FlushAndStop returns.
func TestEnqueueAndFlush(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	a := auditLoggerForTest(t, Opts{
		RetryLimit: 200,
		Logf:       t.Logf,
		Store:      newLogStore(&mem.Store{}),
	})

	a.SetProfileID("test")
	a.Start(mockTransport)

	mockTransport.fail = false
	mockTransport.err = &retriableError

	wantSent := 10

	for i := range wantSent {
		err := a.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log %d", i))
		expectNoError(t, err)
	}

	a.FlushAndStop(5 * time.Second)

	a.mu.Lock()
	defer a.mu.Unlock()
	gotStored, err := a.storedCountLocked()
	expectNoError(t, err)

	wantStored := 0
	if !cmp.Equal(wantStored, gotStored) {
		t.Fatalf("want %d stored, got %d", wantStored, gotStored)
	}

	gotSent := mockTransport.sentCount()
	if !cmp.Equal(wantSent, gotSent) {
		t.Fatalf("want %d stored, got %d", wantSent, gotSent)
	}
}

// TestDeduplicateAndSort tests that the most recent log is kept when deduplicating logs
func TestDeduplicateAndSort(t *testing.T) {
	a := auditLoggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      newLogStore(&mem.Store{}),
	})
	a.SetProfileID("test")

	logs := []*transaction{
		{EventID: "1", Details: "log 1", TimeStamp: time.Now().Add(-time.Minute * 1), Retries: 1},
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.appendToStoreLocked(logs)

	// Update the transaction and re-append it
	logs[0].Retries = 2
	a.appendToStoreLocked(logs)

	fromStore, err := a.store.Load("test")
	expectNoError(t, err)

	// We should see only one transaction
	wantLen, gotLen := len(logs), len(fromStore)
	if !cmp.Equal(wantLen, gotLen) {
		t.Fatalf("want %d retries, got %d", wantLen, gotLen)
	}

	// We should see the latest transaction
	wantRetryCount := 2
	gotRetryCount := fromStore[0].Retries
	if !cmp.Equal(wantRetryCount, gotRetryCount) {
		t.Fatalf("want %d retries, got %d", wantRetryCount, gotRetryCount)
	}
}

func TestChangeProfileId(t *testing.T) {
	a := auditLoggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      newLogStore(&mem.Store{}),
	})
	expectNoError(t, a.SetProfileID("test"))

	// Changing a profile ID must fail
	expectError(t, a.SetProfileID("test"))
}

// TestSendOnRestore pushes a n logs to the persistent store, and ensures they
// are sent as soon as Start is called then checks to ensure the sent logs no
// longer exist in the store.
func TestSendOnRestore(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	a := auditLoggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      newLogStore(&mem.Store{}),
	})
	a.SetProfileID("test")

	wantTotal := 10

	for range wantTotal {
		a.Enqueue(tailcfg.AuditNodeDisconnect, "log")
	}

	a.Start(mockTransport)
	a.FlushAndStop(5 * time.Second)

	a.mu.Lock()
	defer a.mu.Unlock()
	gotStored, err := a.storedCountLocked()
	expectNoError(t, err)

	wantStored := 0
	if !cmp.Equal(wantStored, gotStored) {
		t.Fatalf("want %d stored, got %d", wantStored, gotStored)
	}

	gotSent, wantSent := mockTransport.sentCount(), wantTotal
	if !cmp.Equal(wantSent, gotSent) {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}
}

// TestFailureExhaustion enqueues n logs,  with the transport in a failable state.
// We then set it to a non-failing state, call FlushAndStop and expect all logs to be sent.
func TestFailureExhaustion(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:    t,
		err:  &retriableError,
		fail: true,
	}

	a := auditLoggerForTest(t, Opts{
		RetryLimit: 1,
		Logf:       t.Logf,
		Store:      newLogStore(&mem.Store{}),
	})

	a.SetProfileID("test")
	a.Start(mockTransport)

	for range 10 {
		err := a.Enqueue(tailcfg.AuditNodeDisconnect, "log")
		expectNoError(t, err)
	}

	a.FlushAndStop(5 * time.Second)
	a.mu.Lock()
	defer a.mu.Unlock()
	gotStored, err := a.storedCountLocked()
	expectNoError(t, err)

	wantStored := 0
	if gotStored != wantStored {
		t.Fatalf("want %d stored, got %d", wantStored, gotStored)
	}

	gotSent, wantSent := mockTransport.sentCount(), 0
	if !cmp.Equal(wantSent, gotSent) {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}
}

// TestEnqueueAndFailNoRetry enqueues a set of logs, all of which will fail and are not
// retriable. We then call FlushAndStop and expect all to be unsent.
func TestEnqueueAndFailNoRetry(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:    t,
		fail: true,
		err:  &nonRetriableError,
	}

	a := auditLoggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      newLogStore(&mem.Store{}),
	})

	a.SetProfileID("test")
	a.Start(mockTransport)

	for i := range 10 {
		err := a.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log %d", i))
		expectNoError(t, err)
	}

	a.FlushAndStop(5 * time.Second)
	a.mu.Lock()
	defer a.mu.Unlock()
	gotStored, err := a.storedCountLocked()
	expectNoError(t, err)

	wantStored := 0

	if !cmp.Equal(wantStored, gotStored) {
		t.Fatalf("want %d stored, got %d", wantStored, gotStored)
	}

	gotSent, wantSent := mockTransport.sentCount(), 0
	if !cmp.Equal(wantSent, gotSent) {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}
}

// TestEnqueueAndRetry enqueues a set of logs, all of which will fail and are retriable.
// Mid-test, we set the transport to not-fail and expect the queue to flush properly
// We set the backoff parameters to 0 seconds so retries are immediate.
func TestEnqueueAndRetry(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:    t,
		fail: true,
		err:  &retriableError,
	}

	a := auditLoggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      newLogStore(&mem.Store{}),
	})

	// Set our backoff parameters to 0 seconds to avoid the
	// need for any sleeps
	a.backoffOpts = backoffOpts{
		min:        0,
		max:        0,
		multiplier: 0.0,
	}

	a.SetProfileID("test")
	a.Start(mockTransport)

	for range 10 {
		err := a.Enqueue(tailcfg.AuditNodeDisconnect, "log")
		expectNoError(t, err)
	}

	mockTransport.mu.Lock()
	mockTransport.fail = false
	mockTransport.mu.Unlock()

	a.FlushAndStop(5 * time.Second)
	a.mu.Lock()
	defer a.mu.Unlock()
	gotStored, err := a.storedCountLocked()
	expectNoError(t, err)

	wantStored := 0
	if !cmp.Equal(wantStored, gotStored) {
		t.Fatalf("want %d stored, got %d", wantStored, gotStored)
	}

	gotSent, wantSent := mockTransport.sentCount(), 10
	if !cmp.Equal(wantSent, gotSent) {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}
}

// TestStart enqueues a set of logs while the queue is stopped. We then start the queue and expect
// all logs to be flushed.

func TestStart(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:    t,
		fail: true,
		err:  &retriableError,
	}

	a := auditLoggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      newLogStore(&mem.Store{}),
	})

	err := a.Enqueue(tailcfg.AuditNodeDisconnect, "log")
	expectError(t, err)

	a.FlushAndStop(5 * time.Second)

	a.mu.Lock()
	gotStored, err := a.storedCountLocked()
	expectError(t, err)
	a.mu.Unlock()
	wantStored := 0

	if !cmp.Equal(wantStored, gotStored) {
		t.Fatalf("want %d stored, got %d", wantStored, gotStored)
	}

	// This second stop should no-op
	a.FlushAndStop(5 * time.Second)

	mockTransport.fail = false

	a.SetProfileID("test")
	a.Start(mockTransport)
	// This must no-op
	a.Start(mockTransport)

	err = a.Enqueue(tailcfg.AuditNodeDisconnect, "log")
	expectNoError(t, err)

	a.FlushAndStop(5 * time.Second)
	// This must no-op safely
	a.FlushAndStop(5 * time.Second)

	a.mu.Lock()
	defer a.mu.Unlock()
	gotStored, err = a.storedCountLocked()
	expectNoError(t, err)
	wantStored = 0

	if !cmp.Equal(wantStored, gotStored) {
		t.Fatalf("want %d persisted, got %d", wantStored, gotStored)
	}

	gotSent, wantSent := mockTransport.sentCount(), 1
	if !cmp.Equal(wantSent, gotSent) {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}
}

// TestLogStoring tests that audit logs are persisted sorted by timestamp, oldest to newest
func TestLogSorting(t *testing.T) {
	mockStore := newLogStore(&mem.Store{})

	logs := []*transaction{
		{EventID: "1", Details: "log 3", TimeStamp: time.Now().Add(-time.Minute * 1)},
		{EventID: "1", Details: "log 3", TimeStamp: time.Now().Add(-time.Minute * 2)},
		{EventID: "2", Details: "log 2", TimeStamp: time.Now().Add(-time.Minute * 3)},
		{EventID: "3", Details: "log 1", TimeStamp: time.Now().Add(-time.Minute * 4)},
	}

	wantLogs := []transaction{
		{Details: "log 1"},
		{Details: "log 2"},
		{Details: "log 3"},
	}

	mockStore.Save("test", logs)

	gotLogs, err := mockStore.Load("test")
	expectNoError(t, err)
	gotLogs = deduplicateAndSort(gotLogs)

	for i := range gotLogs {
		if !cmp.Equal(wantLogs[i].Details, gotLogs[i].Details) {
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

func (m *mockAuditLogTransport) sentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sendCount
}

func (m *mockAuditLogTransport) SendAuditLog(ctx context.Context, _ tailcfg.AuditLogRequest) (err error) {
	m.t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(m.delay):
	}

	if m.fail {
		return m.err
	} else {
		m.sendCount += 1
		return nil
	}
}

type mockError struct {
	err error
}

func (e *mockError) Error() string {
	return e.err.Error()
}

var retriableError = mockError{errors.New("retriable error")}
var nonRetriableError = mockError{errors.New("permenent failure error")}

func (e *mockError) Retryable() bool {
	return errors.Is(e, &retriableError)
}
