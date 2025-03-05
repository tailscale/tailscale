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
	"tailscale.com/control/controlclient"
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
func auditLoggerForTest(t *testing.T, opts Opts) *AuditLogger {
	t.Helper()
	if opts.Logf == nil {
		t.Fatalf("opts.Logf must be set")
	}
	if opts.Store == nil {
		t.Fatalf("opts.Store must be set")
	}

	al := NewAuditLogger(opts)

	t.Cleanup(func() {
		al.FlushAndStop(5 * time.Second)
	})
	tstest.ResourceCheck(t)
	return al
}

func TestRetryableErrors(t *testing.T) {
	errors := []struct {
		err  error
		want bool
	}{
		{controlclient.ErrHTTPFailure, false},
		{controlclient.ErrNoNoiseClient, true},
		{fmt.Errorf("%w: %w", controlclient.ErrNoNoiseClient, errors.New("boom")), true},
		{fmt.Errorf("%w: %w", controlclient.ErrHTTPPostFailure, errors.New("boom")), true},
		{controlclient.ErrNoNodeKey, true},
		{context.Canceled, false},
		{fmt.Errorf("%w: %w", context.Canceled, errors.New("boom")), false},
		{controlclient.ErrTxnHTTPFailure(500, []byte("server melted")), false},
	}

	for _, e := range errors {
		if !cmp.Equal(isRetryableError(e.err), e.want) {
			t.Fatalf("error evaluator failed for %v", e.err)
		}
	}
}

// TestEnqueueAndFlush enqueues n logs and flushes them.
// We expect all logs to be flushed and for no
// logs to remain in the store once FlushAndStop returns.
func TestEnqueueAndFlush(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	al := auditLoggerForTest(t, Opts{
		RetryLimit: 200,
		Logf:       t.Logf,
		Store:      NewLogStateStore(&mem.Store{}, t.Logf),
	})

	al.SetProfileID("test")
	al.Start(mockTransport)

	mockTransport.fail = false
	mockTransport.err = &retriableError

	wantSent := 10

	for i := range wantSent {
		err := al.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log %d", i))
		expectNoError(t, err)
	}

	al.FlushAndStop(5 * time.Second)

	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
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
	al := auditLoggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStateStore(&mem.Store{}, t.Logf),
	})
	al.SetProfileID("test")

	logs := []*transaction{
		{EventID: "1", Details: "log 1", TimeStamp: time.Now().Add(-time.Minute * 1), Retries: 1},
	}

	al.mu.Lock()
	defer al.mu.Unlock()
	al.appendToStoreLocked(logs)

	// Update the transaction and re-append it
	logs[0].Retries = 2
	al.appendToStoreLocked(logs)

	fromStore, err := al.store.Load("test")
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
	al := auditLoggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStateStore(&mem.Store{}, t.Logf),
	})
	expectNoError(t, al.SetProfileID("test"))

	// Changing a profile ID must fail
	expectError(t, al.SetProfileID("test"))
}

// TestSendOnRestore pushes a n logs to the persistent store, and ensures they
// are sent as soon as Start is called then checks to ensure the sent logs no
// longer exist in the store.
func TestSendOnRestore(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	al := auditLoggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStateStore(&mem.Store{}, t.Logf),
	})
	al.SetProfileID("test")

	wantTotal := 10

	for range wantTotal {
		al.Enqueue(tailcfg.AuditNodeDisconnect, "log")
	}

	al.Start(mockTransport)
	al.FlushAndStop(5 * time.Second)

	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
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

	al := auditLoggerForTest(t, Opts{
		RetryLimit: 1,
		Logf:       t.Logf,
		Store:      NewLogStateStore(&mem.Store{}, t.Logf),
	})

	al.SetProfileID("test")
	al.Start(mockTransport)

	for range 10 {
		err := al.Enqueue(tailcfg.AuditNodeDisconnect, "log")
		expectNoError(t, err)
	}

	al.FlushAndStop(5 * time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
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

	al := auditLoggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStateStore(&mem.Store{}, t.Logf),
	})

	al.SetProfileID("test")
	al.Start(mockTransport)

	for i := range 10 {
		err := al.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log %d", i))
		expectNoError(t, err)
	}

	al.FlushAndStop(5 * time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
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

	al := auditLoggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStateStore(&mem.Store{}, t.Logf),
	})

	// Set our backoff parameters to 0 seconds to avoid the
	// need for any sleeps
	al.backoffOpts = backoffOpts{
		min:       0,
		max:       0,
		mutiplier: 0.0,
	}

	al.SetProfileID("test")
	al.Start(mockTransport)

	for range 10 {
		err := al.Enqueue(tailcfg.AuditNodeDisconnect, "log")
		expectNoError(t, err)
	}

	mockTransport.mu.Lock()
	mockTransport.fail = false
	mockTransport.mu.Unlock()

	al.FlushAndStop(5 * time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
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

	al := auditLoggerForTest(t, Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      NewLogStateStore(&mem.Store{}, t.Logf),
	})

	err := al.Enqueue(tailcfg.AuditNodeDisconnect, "log")
	expectError(t, err)

	al.FlushAndStop(5 * time.Second)

	al.mu.Lock()
	gotStored, err := al.storedCountLocked()
	expectError(t, err)
	al.mu.Unlock()
	wantStored := 0

	if !cmp.Equal(wantStored, gotStored) {
		t.Fatalf("want %d stored, got %d", wantStored, gotStored)
	}

	// This second stop should no-op
	al.FlushAndStop(5 * time.Second)

	mockTransport.fail = false

	al.SetProfileID("test")
	al.Start(mockTransport)
	// This must no-op
	al.Start(mockTransport)

	err = al.Enqueue(tailcfg.AuditNodeDisconnect, "log")
	expectNoError(t, err)

	al.FlushAndStop(5 * time.Second)
	// This must no-op safely
	al.FlushAndStop(5 * time.Second)

	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err = al.storedCountLocked()
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
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

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
