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

	qt "github.com/frankban/quicktest"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

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
	c := qt.New(t)
	mockTransport := newMockTransport(nil)
	al := loggerForTest(t, Opts{
		RetryLimit: 200,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	c.Assert(al.SetProfileID("test"), qt.IsNil)
	c.Assert(al.Start(mockTransport), qt.IsNil)

	wantSent := 10

	for i := range wantSent {
		err := al.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log %d", i))
		c.Assert(err, qt.IsNil)
	}

	al.FlushAndStop(context.Background())

	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
	c.Assert(err, qt.IsNil)

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
	c := qt.New(t)
	mockTransport := newMockTransport(&retriableError)
	al := loggerForTest(t, Opts{
		RetryLimit: 200,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	c.Assert(al.SetProfileID("test"), qt.IsNil)
	c.Assert(al.Start(mockTransport), qt.IsNil)

	for i := range 10 {
		err := al.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log %d", i))
		c.Assert(err, qt.IsNil)
	}

	// Cancel the context before calling FlushAndStop - nothing should get sent.
	// This mimics a timeout before flush() has a chance to execute.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	al.FlushAndStop(ctx)

	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
	c.Assert(err, qt.IsNil)

	if wantStored := 10; gotStored != wantStored {
		t.Fatalf("stored: got %d, want %d", gotStored, wantStored)
	}

	if gotSent, wantSent := mockTransport.sentCount(), 0; gotSent != wantSent {
		t.Fatalf("sent: got %d, want %d", gotSent, wantSent)
	}
}

// TestDeduplicateAndSort tests that the most recent log is kept when deduplicating logs
func TestDeduplicateAndSort(t *testing.T) {
	c := qt.New(t)
	al := loggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	c.Assert(al.SetProfileID("test"), qt.IsNil)

	logs := []*transaction{
		{EventID: "1", Details: "log 1", TimeStamp: time.Now().Add(-time.Minute * 1), Retries: 1},
	}

	al.mu.Lock()
	defer al.mu.Unlock()
	al.appendToStoreLocked(logs)

	// Update the transaction and re-append it
	logs[0].Retries = 2
	al.appendToStoreLocked(logs)

	fromStore, err := al.store.load("test")
	c.Assert(err, qt.IsNil)

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
	c := qt.New(t)
	al := loggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})
	c.Assert(al.SetProfileID("test"), qt.IsNil)

	// Calling SetProfileID with the same profile ID must not fail.
	c.Assert(al.SetProfileID("test"), qt.IsNil)

	// Changing a profile ID must fail.
	c.Assert(al.SetProfileID("test2"), qt.IsNotNil)
}

// TestSendOnRestore pushes a n logs to the persistent store, and ensures they
// are sent as soon as Start is called then checks to ensure the sent logs no
// longer exist in the store.
func TestSendOnRestore(t *testing.T) {
	c := qt.New(t)
	mockTransport := newMockTransport(nil)
	al := loggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})
	al.SetProfileID("test")

	wantTotal := 10

	for range 10 {
		al.Enqueue(tailcfg.AuditNodeDisconnect, "log")
	}

	c.Assert(al.Start(mockTransport), qt.IsNil)

	al.FlushAndStop(context.Background())

	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
	c.Assert(err, qt.IsNil)

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
	c := qt.New(t)
	mockTransport := newMockTransport(&retriableError)

	al := loggerForTest(t, Opts{
		RetryLimit: 1,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	c.Assert(al.SetProfileID("test"), qt.IsNil)
	c.Assert(al.Start(mockTransport), qt.IsNil)

	for range 10 {
		err := al.Enqueue(tailcfg.AuditNodeDisconnect, "log")
		c.Assert(err, qt.IsNil)
	}

	al.FlushAndStop(context.Background())
	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
	c.Assert(err, qt.IsNil)

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
	c := qt.New(t)
	mockTransport := newMockTransport(&nonRetriableError)

	al := loggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	c.Assert(al.SetProfileID("test"), qt.IsNil)
	c.Assert(al.Start(mockTransport), qt.IsNil)

	for i := range 10 {
		err := al.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log %d", i))
		c.Assert(err, qt.IsNil)
	}

	al.FlushAndStop(context.Background())
	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
	c.Assert(err, qt.IsNil)

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
	c := qt.New(t)
	mockTransport := newMockTransport(&retriableError)

	al := loggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	al.backoffOpts = backoffOpts{
		min:        1 * time.Millisecond,
		max:        4 * time.Millisecond,
		multiplier: 2.0,
	}

	c.Assert(al.SetProfileID("test"), qt.IsNil)
	c.Assert(al.Start(mockTransport), qt.IsNil)

	err := al.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log 1"))
	c.Assert(err, qt.IsNil)

	// This will wait for at least 2 retries
	gotRetried, wantRetried := mockTransport.waitForSendAttemptsToReach(3), true
	if gotRetried != wantRetried {
		t.Fatalf("retried: got %v, want %v", gotRetried, wantRetried)
	}

	mockTransport.setErrorCondition(nil)

	al.FlushAndStop(context.Background())
	al.mu.Lock()
	defer al.mu.Unlock()

	gotStored, err := al.storedCountLocked()
	c.Assert(err, qt.IsNil)

	if wantStored := 0; gotStored != wantStored {
		t.Fatalf("stored: got %d, want %d", gotStored, wantStored)
	}

	if gotSent, wantSent := mockTransport.sentCount(), 1; gotSent != wantSent {
		t.Fatalf("sent: got %d, want %d", gotSent, wantSent)
	}
}

// TestEnqueueBeforeSetProfileID tests that logs enqueued before SetProfileId are not sent
func TestEnqueueBeforeSetProfileID(t *testing.T) {
	c := qt.New(t)
	al := loggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStore(&mem.Store{}),
	})

	err := al.Enqueue(tailcfg.AuditNodeDisconnect, "log")
	c.Assert(err, qt.IsNotNil)
	al.FlushAndStop(context.Background())

	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
	c.Assert(err, qt.IsNotNil)

	if wantStored := 0; gotStored != wantStored {
		t.Fatalf("stored: got %d, want %d", gotStored, wantStored)
	}
}

// TestLogStoring tests that audit logs are persisted sorted by timestamp, oldest to newest
func TestLogSorting(t *testing.T) {
	c := qt.New(t)
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

	mockStore.save("test", logs)

	gotLogs, err := mockStore.load("test")
	c.Assert(err, qt.IsNil)
	gotLogs = deduplicateAndSort(gotLogs)

	for i := range gotLogs {
		if want, got := wantLogs[i].Details, gotLogs[i].Details; want != got {
			t.Fatalf("Details: got %v, want %v", got, want)
		}
	}
}

// mock implementations for testing

// newMockTransport returns a mock transport for testing
// If err is no nil, SendAuditLog will return this error if the send is attempted
// before the context is cancelled.
func newMockTransport(err error) *mockAuditLogTransport {
	return &mockAuditLogTransport{
		err:      err,
		attempts: make(chan int, 1),
	}
}

type mockAuditLogTransport struct {
	attempts chan int // channel to notify of send attempts

	mu          sync.Mutex
	sendAttmpts int   // number of attempts to send logs
	sendCount   int   // number of logs sent by the transport
	err         error // error to return when sending logs
}

// waitForSendAttemptsToReach blocks until the number of send attempts reaches n
// This should be use only in tests where the transport is expected to retry sending logs
func (t *mockAuditLogTransport) waitForSendAttemptsToReach(n int) bool {
	for attempts := range t.attempts {
		if attempts >= n {
			return true
		}
	}
	return false
}

func (t *mockAuditLogTransport) setErrorCondition(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.err = err
}

func (t *mockAuditLogTransport) sentCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sendCount
}

func (t *mockAuditLogTransport) SendAuditLog(ctx context.Context, _ tailcfg.AuditLogRequest) (err error) {
	t.mu.Lock()
	t.sendAttmpts += 1
	defer func() {
		a := t.sendAttmpts
		t.mu.Unlock()
		select {
		case t.attempts <- a:
		default:
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if t.err != nil {
		return t.err
	}
	t.sendCount += 1
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
