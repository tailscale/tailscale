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
		t.Fatalf("expected error but got nil")
	}
}

// loggerForTest creates an auditLogger for you and cleans it up
// (and ensures no goroutines are leaked) when the test is done.
func loggerForTest(t *testing.T, opts Opts) *Logger {
	t.Helper()
	tstest.ResourceCheck(t)

	if opts.Logf == nil {
		opts.Logf = t.Logf
	}

	if opts.Store == nil {
		t.Fatalf("opts.Store must be set")
	}

	a := NewLogger(opts)

	t.Cleanup(func() {
		a.FlushAndStop(context.Background())
	})
	return a
}

func TestNonRetryableErrors(t *testing.T) {
	errorTests := []struct {
		desc string
		err  error
		want bool
	}{
		{"DeadlineExceeded", context.DeadlineExceeded, false},
		{"Canceled", context.Canceled, false},
		{"Canceled wrapped", fmt.Errorf("%w: %w", context.Canceled, errors.New("ctx cancelled")), false},
		{"Random error", errors.New("random error"), false},
	}

	for _, tt := range errorTests {
		t.Run(tt.desc, func(t *testing.T) {
			if IsRetryableError(tt.err) != tt.want {
				t.Fatalf("retriable: got %v, want %v", !tt.want, tt.want)
			}
		})
	}
}

// TestEnqueueAndFlush enqueues n logs and flushes them.
// We expect all logs to be flushed and for no
// logs to remain in the store once FlushAndStop returns.
func TestEnqueueAndFlush(t *testing.T) {
	mockTransport := NewMockTransport(nil)
	l := loggerForTest(t, Opts{
		RetryLimit: 200,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	expectNoError(t, l.SetProfileID("test"))
	expectNoError(t, l.Start(mockTransport))

	wantSent := 10

	for i := range wantSent {
		err := l.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log %d", i))
		expectNoError(t, err)
	}

	l.FlushAndStop(context.Background())

	l.mu.Lock()
	defer l.mu.Unlock()
	gotStored, err := l.storedCountLocked()
	expectNoError(t, err)

	if wantStored := 0; gotStored != wantStored {
		t.Fatalf("stored: got %d, want %d", gotStored, wantStored)
	}

	if gotSent := mockTransport.sentCount(); gotSent != wantSent {
		t.Fatalf("sent: got %d, want %d", gotSent, wantSent)
	}
}

// TestEnqueueAndFlushWithFlushCancel calls FlushAndCancel with a cancelled
// context.  We expect nothing to be sent and all logs to be stored.
func TestEnqueueAndFlushWithFlushCancel(t *testing.T) {
	mockTransport := NewMockTransport(&retriableError)
	l := loggerForTest(t, Opts{
		RetryLimit: 200,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	expectNoError(t, l.SetProfileID("test"))
	expectNoError(t, l.Start(mockTransport))

	for i := range 10 {
		err := l.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log %d", i))
		expectNoError(t, err)
	}

	// Cancel the context before calling FlushAndStop - nothing should get sent.
	// This mimics a timeout before flush() has a chance to execute.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	l.FlushAndStop(ctx)

	l.mu.Lock()
	defer l.mu.Unlock()
	gotStored, err := l.storedCountLocked()
	expectNoError(t, err)

	if wantStored := 10; gotStored != wantStored {
		t.Fatalf("stored: got %d, want %d", gotStored, wantStored)
	}

	if gotSent, wantSent := mockTransport.sentCount(), 0; gotSent != wantSent {
		t.Fatalf("sent: got %d, want %d", gotSent, wantSent)
	}
}

// TestDeduplicateAndSort tests that the most recent log is kept when deduplicating logs
func TestDeduplicateAndSort(t *testing.T) {
	l := loggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	expectNoError(t, l.SetProfileID("test"))

	logs := []*transaction{
		{EventID: "1", Details: "log 1", TimeStamp: time.Now().Add(-time.Minute * 1), Retries: 1},
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.appendToStoreLocked(logs)

	// Update the transaction and re-append it
	logs[0].Retries = 2
	l.appendToStoreLocked(logs)

	fromStore, err := l.store.Load("test")
	expectNoError(t, err)

	// We should see only one transaction
	if wantStored, gotStored := len(logs), len(fromStore); gotStored != wantStored {
		t.Fatalf("stored: got %d, want %d", gotStored, wantStored)
	}

	// We should see the latest transaction
	if wantRetryCount, gotRetryCount := 2, fromStore[0].Retries; gotRetryCount != wantRetryCount {
		t.Fatalf("reties: got %d, want %d", gotRetryCount, wantRetryCount)
	}
}

func TestChangeProfileId(t *testing.T) {
	l := loggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})
	expectNoError(t, l.SetProfileID("test"))

	// Changing a profile ID must fail
	expectError(t, l.SetProfileID("test"))
}

// TestSendOnRestore pushes a n logs to the persistent store, and ensures they
// are sent as soon as Start is called then checks to ensure the sent logs no
// longer exist in the store.
func TestSendOnRestore(t *testing.T) {
	mockTransport := NewMockTransport(nil)
	l := loggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})
	l.SetProfileID("test")

	wantTotal := 10

	for range 10 {
		l.Enqueue(tailcfg.AuditNodeDisconnect, "log")
	}

	expectNoError(t, l.Start(mockTransport))

	l.FlushAndStop(context.Background())

	l.mu.Lock()
	defer l.mu.Unlock()
	gotStored, err := l.storedCountLocked()
	expectNoError(t, err)

	if wantStored := 0; gotStored != wantStored {
		t.Fatalf("stored: got %d, want %d", gotStored, wantStored)
	}

	if gotSent, wantSent := mockTransport.sentCount(), wantTotal; gotSent != wantSent {
		t.Fatalf("sent: got %d, want %d", gotSent, wantSent)
	}
}

// TestFailureExhaustion enqueues n logs,  with the transport in a failable state.
// We then set it to a non-failing state, call FlushAndStop and expect all logs to be sent.
func TestFailureExhaustion(t *testing.T) {
	mockTransport := NewMockTransport(&retriableError)

	l := loggerForTest(t, Opts{
		RetryLimit: 1,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	expectNoError(t, l.SetProfileID("test"))
	expectNoError(t, l.Start(mockTransport))

	for range 10 {
		err := l.Enqueue(tailcfg.AuditNodeDisconnect, "log")
		expectNoError(t, err)
	}

	l.FlushAndStop(context.Background())
	l.mu.Lock()
	defer l.mu.Unlock()
	gotStored, err := l.storedCountLocked()
	expectNoError(t, err)

	if wantStored := 0; gotStored != wantStored {
		t.Fatalf("stored: got %d, want %d", gotStored, wantStored)
	}

	if gotSent, wantSent := mockTransport.sentCount(), 0; gotSent != wantSent {
		t.Fatalf("sent: got %d, want %d", gotSent, wantSent)
	}
}

// TestEnqueueAndFailNoRetry enqueues a set of logs, all of which will fail and are not
// retriable. We then call FlushAndStop and expect all to be unsent.
func TestEnqueueAndFailNoRetry(t *testing.T) {
	mockTransport := NewMockTransport(&nonRetriableError)

	l := loggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	expectNoError(t, l.SetProfileID("test"))
	expectNoError(t, l.Start(mockTransport))

	for i := range 10 {
		err := l.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log %d", i))
		expectNoError(t, err)
	}

	l.FlushAndStop(context.Background())
	l.mu.Lock()
	defer l.mu.Unlock()
	gotStored, err := l.storedCountLocked()
	expectNoError(t, err)

	if wantStored := 0; gotStored != wantStored {
		t.Fatalf("stored: got %d, want %d", gotStored, wantStored)
	}

	if gotSent, wantSent := mockTransport.sentCount(), 0; gotSent != wantSent {
		t.Fatalf("sent: got %d, want %d", gotSent, wantSent)
	}
}

// TestEnqueueAndRetry enqueues a set of logs, all of which will fail and are retriable.
// Mid-test, we set the transport to not-fail and expect the queue to flush properly
// We set the backoff parameters to 0 seconds so retries are immediate.
func TestEnqueueAndRetry(t *testing.T) {
	mockTransport := NewMockTransport(&retriableError)

	l := loggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	l.backoffOpts = backoffOpts{
		min:        1 * time.Millisecond,
		max:        4 * time.Millisecond,
		multiplier: 2.0,
	}

	expectNoError(t, l.SetProfileID("test"))
	expectNoError(t, l.Start(mockTransport))

	err := l.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log 1"))
	expectNoError(t, err)

	// This will wait for at least 2 retries
	mockTransport.waitForSendAttemptsToReach(3)
	mockTransport.setErrorCondition(nil)

	l.FlushAndStop(context.Background())
	l.mu.Lock()
	defer l.mu.Unlock()

	gotStored, err := l.storedCountLocked()
	expectNoError(t, err)

	if wantStored := 0; gotStored != wantStored {
		t.Fatalf("stored: got %d, want %d", gotStored, wantStored)
	}

	if gotSent, wantSent := mockTransport.sentCount(), 1; gotSent != wantSent {
		t.Fatalf("sent: got %d, want %d", gotSent, wantSent)
	}
}

// TestEnqueueBeforeSetProfileID tests that logs enqueued before SetProfileId are not sent
func TestEnqueueBeforeSetProfileID(t *testing.T) {
	l := loggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	err := l.Enqueue(tailcfg.AuditNodeDisconnect, "log")
	expectError(t, err)
	l.FlushAndStop(context.Background())

	l.mu.Lock()
	defer l.mu.Unlock()
	gotStored, err := l.storedCountLocked()
	expectError(t, err)

	if wantStored := 0; gotStored != wantStored {
		t.Fatalf("stored: got %d, want %d", gotStored, wantStored)
	}
}

// TestLogStoring tests that audit logs are persisted sorted by timestamp, oldest to newest
func TestLogSorting(t *testing.T) {
	mockStore := NewLogStore(&mem.Store{})

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
		if want, got := wantLogs[i].Details, gotLogs[i].Details; want != got {
			t.Fatalf("Details: got %v, want %v", got, want)
		}
	}
}

// mock implementations for testing

func NewMockTransport(err error) *mockAuditLogTransport {
	return &mockAuditLogTransport{
		err:      err,
		attempts: make(chan int),
	}
}

type mockAuditLogTransport struct {
	attempts chan int // channel to notify of send attempts

	mu          sync.Mutex
	sendAttmpts int   // number of attempts to send logs
	sendCount   int   // number of logs sent by the transport
	err         error // error to return when sending logs
}

func (m *mockAuditLogTransport) waitForSendAttemptsToReach(n int) {
	for attempts := range m.attempts {
		if attempts >= n {
			return
		}
	}
}

func (m *mockAuditLogTransport) setErrorCondition(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func (m *mockAuditLogTransport) sentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sendCount
}

func (m *mockAuditLogTransport) SendAuditLog(ctx context.Context, _ tailcfg.AuditLogRequest) (err error) {
	m.mu.Lock()
	m.sendAttmpts += 1
	defer func() {
		a := m.sendAttmpts
		m.mu.Unlock()
		select {
		case m.attempts <- a:
		default:
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if m.err != nil {
		return m.err
	}
	m.sendCount += 1
	return nil
}

var (
	retriableError    = mockError{errors.New("retriable error")}
	nonRetriableError = mockError{errors.New("permanent failure error")}
)

type mockError struct {
	error
}

func (e mockError) Retryable() bool {
	return e == retriableError
}
