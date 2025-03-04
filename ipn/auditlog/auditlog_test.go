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
		{controlclient.ErrAuditLogHTTPFailure(500, []byte("server melted")), false},
	}

	for _, e := range errors {
		if isRetryableError(e.err) != e.want {
			t.Fatalf("error evaluator failed for %v", e.err)
		}
	}
}

// TestEnqueueAndFlush enqueues n logs and flushes them.
// We expect all logs to be flushed and for no
// logs to remain in the store.
func TestEnqueueAndFlush(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 200,
		Logf:       t.Logf,
		Store:      mockStore,
	})

	t.Cleanup(func() {
		al.FlushAndStop(5 * time.Second)
	})
	tstest.ResourceCheck(t)

	al.SetProfileID("test")
	al.Start(mockTransport)

	mockTransport.fail = false
	mockTransport.err = &retriableError

	wantSent := 10

	var err error
	for i := range wantSent {
		err = al.Enqueue(tailcfg.AuditNodeDisconnect, fmt.Sprintf("log %d", i))
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	al.FlushAndStop(5 * time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()

	if err != nil {
		t.Fatalf("failed to restore logs: %v", err)
	}

	wantStored := 0
	if gotStored != wantStored {
		t.Fatalf("want %d stored, got %d", wantStored, gotStored)
	}

	gotSent := mockTransport.sendCount
	if gotSent != wantSent {
		t.Fatalf("want %d stored, got %d", wantSent, gotSent)
	}
}

func TestChangeProfileId(t *testing.T) {
	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
	})
	err := al.SetProfileID("test")
	if err != nil {
		t.Fatalf("failed to set profileID: %v", err)
	}

	// Changing a profile ID must fail
	err = al.SetProfileID("test")
	if err == nil {
		t.Fatalf("expected error when setting profileID")
	}
}

// TestSendOnRestore pushes a n logs to the persistent store, and ensures they
// are sent as soon as Start is called then checks to ensure the sent logs no
// longer exist in the store.
func TestSendOnRestore(t *testing.T) {
	mockTransport := &mockAuditLogTransport{t: t}
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	tstest.ResourceCheck(t)
	al.SetProfileID("test")

	wantTotal := 10

	for range wantTotal {
		err := al.Enqueue(tailcfg.AuditNodeDisconnect, "log")
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	al.Start(mockTransport)
	al.FlushAndStop(5 * time.Second)

	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()

	if err != nil {
		t.Fatalf("failed to restore logs: %v", err)
	}

	wantStored := 0
	if gotStored != wantStored {
		t.Fatalf("want %d stored, got %d", wantStored, gotStored)
	}

	gotSent, wantSent := mockTransport.sendCount, wantTotal
	if gotSent != wantSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}
}

// TestFailureExhaustion enqueues n logs,  with the transport in a failable state.
// We then set it to a non-failing state, call FlushAndStop and expect all logs to be sent.
func TestFailureExhaustion(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 10 * time.Millisecond,
		err:   &retriableError,
		fail:  true,
	}
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 1,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	t.Cleanup(func() {
		al.FlushAndStop(5 * time.Second)
	})
	tstest.ResourceCheck(t)

	al.SetProfileID("test")
	al.Start(mockTransport)

	for range 10 {
		err := al.Enqueue(tailcfg.AuditNodeDisconnect, "log")
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	al.FlushAndStop(5 * time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
	if err != nil {
		t.Fatalf("failed to restore logs: %v", err)
	}

	if err != nil {
		t.Fatalf("failed to restore logs: %v", err)
	}
	wantStored := 0
	if gotStored != wantStored {
		t.Fatalf("want %d stored, got %d", gotStored, wantStored)
	}

	gotSent, wantSent := mockTransport.sendCount, 0
	if gotSent != wantSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}
}

// TestEnqueueAndFailNoRetry enqueues a set of logs, all of which will fail and are not
// retriable. We then call FlushAndStop and expect all to be unsent.
func TestEnqueueAndFailNoRetry(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 10 * time.Millisecond,
		fail:  true,
		err:   &nonRetriableError,
	}
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	t.Cleanup(func() {
		al.FlushAndStop(5 * time.Second)
	})
	tstest.ResourceCheck(t)

	al.SetProfileID("test")
	al.Start(mockTransport)

	for i := range 10 {
		log := auditLogTxn{
			Details:   fmt.Sprintf("log %d", i),
			TimeStamp: time.Now(),
			EventID:   fmt.Sprintf("%d", i),
		}
		err := al.enqueue(log)
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	al.FlushAndStop(5 * time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
	if err != nil {
		t.Fatalf("failed to restore logs: %v", err)
	}

	if err != nil {
		t.Fatalf("failed to restore logs: %v", err)
	}
	wantStored := 0

	if gotStored != wantStored {
		t.Fatalf("want %d stored, got %d", gotStored, wantStored)
	}

	gotSent, wantSent := mockTransport.sendCount, 0
	if gotSent != wantSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
	}
}

// TestEnqueueAndRetry enqueues a set of logs, all of which will fail and are retriable.
// Mid-test, we set the transport to not-fail and expect the queue to flush properly
// We set the backoff parameters to 0 seconds so retries are immediate.
func TestEnqueueAndRetry(t *testing.T) {
	mockTransport := &mockAuditLogTransport{
		t:     t,
		delay: 0 * time.Millisecond,
		fail:  true,
		err:   &retriableError,
	}
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})

	// Set our backoff parameters to 0 seconds to avoid the
	// need for any sleeps
	al.backoffOpts = backoffOpts{
		min:       0,
		max:       0,
		mutiplier: 0.0,
	}

	t.Cleanup(func() {
		al.FlushAndStop(5 * time.Second)
	})
	tstest.ResourceCheck(t)

	al.SetProfileID("test")
	al.Start(mockTransport)

	for range 10 {
		err := al.Enqueue(tailcfg.AuditNodeDisconnect, "log")
		if err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	mockTransport.mu.Lock()
	mockTransport.fail = false
	mockTransport.mu.Unlock()

	al.FlushAndStop(5 * time.Second)
	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err := al.storedCountLocked()
	if err != nil {
		t.Fatalf("failed to restore logs: %v", err)
	}

	if err != nil {
		t.Fatalf("failed to restore logs: %v", err)
	}
	wantStored := 0

	if gotStored != wantStored {
		t.Fatalf("want %d stored, got %d", wantStored, gotStored)
	}

	gotSent, wantSent := mockTransport.sendCount, 10
	if gotSent != wantSent {
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
	mockStore := NewLogStateStore(&mem.Store{}, t.Logf)

	al := NewAuditLogger(Opts{
		RetryLimit: 100,
		Logf:       t.Logf,
		Store:      mockStore,
	})
	t.Cleanup(func() {
		al.FlushAndStop(5 * time.Second)
	})
	tstest.ResourceCheck(t)

	err := al.Enqueue(tailcfg.AuditNodeDisconnect, "log")
	if err == nil {
		t.Fatalf("enqueue should have failed")
	}

	al.FlushAndStop(5 * time.Second)

	al.mu.Lock()
	gotStored, err := al.storedCountLocked()
	if err == nil {
		t.Fatalf("expected Enqueue failure")
	}
	al.mu.Unlock()
	wantStored := 0

	if wantStored != gotStored {
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
	if err != nil {
		t.Fatalf("enqueue should not have failed %v", err)
	}

	al.FlushAndStop(5 * time.Second)
	// This must no-op safely
	al.FlushAndStop(5 * time.Second)

	al.mu.Lock()
	defer al.mu.Unlock()
	gotStored, err = al.storedCountLocked()
	if err != nil {
		t.Fatalf("failed to restore logs: %v", err)
	}
	wantStored = 0

	if gotStored != wantStored {
		t.Fatalf("want %d persisted, got %d", gotStored, wantStored)
	}

	gotSent, wantSent := mockTransport.sendCount, 1
	if gotSent != wantSent {
		t.Fatalf("want %d sent, got %d", wantSent, gotSent)
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
