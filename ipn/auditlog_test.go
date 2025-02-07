// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

type MockAuditLogTransport struct {
	mu        sync.Mutex
	sendCount int
	delay     time.Duration
	fail      bool // true if the transport should fail
	retry     bool // if true, retr
}

func (m *MockAuditLogTransport) SendAuditLog(ctx context.Context, auditLog tailcfg.ClientAuditLog) (err error, retriable bool) {
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

func TestEnqueueAndFlushAuditLogs(t *testing.T) {
	mockTransport := &MockAuditLogTransport{}

	q := NewAuditLogger(AuditLoggerOpts{
		RetryCount: 100,
		Logf:       t.Logf,
	})

	wantSent := 2
	wantFailed, gotFailed := 0, 0

	flushed := make(chan int, 1)
	for i := 0; i < wantSent; i++ {
		log := tailcfg.ClientAuditLog{
			Details: fmt.Sprintf("log %d", i),
		}
		if err := q.EnqueueAuditLog(mockTransport, log, time.Second*2, flushed); err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
		select {
		case gotFailed = <-flushed:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for logs to be flushed")
		}
	}

	gotSent := mockTransport.sendCount
	if wantSent != gotSent {
		t.Fatalf("want %d logs to be flushed, got %d", wantSent, gotSent)
	}

	if wantFailed != gotFailed {
		t.Fatalf("want %d logs to be fail. got %d", wantFailed, gotFailed)
	}
}

func TestFailuresFlushLater(t *testing.T) {
	mockTransport := &MockAuditLogTransport{
		delay: 10 * time.Millisecond,
		retry: true,
		fail:  true,
	}

	q := NewAuditLogger(AuditLoggerOpts{
		RetryCount: 100,
		Logf:       t.Logf,
	})

	for i := 0; i < 5; i++ {
		log := tailcfg.ClientAuditLog{
			Details: fmt.Sprintf("log %d", i),
		}
		flushed := make(chan int, 1)
		if err := q.EnqueueAuditLog(mockTransport, log, time.Second*2, flushed); err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
		<-flushed

	}

	mockTransport.mu.Lock()
	mockTransport.fail = false
	mockTransport.mu.Unlock()

	flushed := make(chan int, 1)
	q.Flush(mockTransport, 5*time.Second, flushed)

	gotFailed, wantFailed := 0, 0

	select {
	case gotFailed = <-flushed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for logs to be flushed")
	}

	want, got := 5, mockTransport.sendCount

	if want != got {
		t.Fatalf("want %d logs to be flushed, got %d", want, got)
	}

	if wantFailed != gotFailed {
		t.Fatalf("want %d logs to be fail. got %d", wantFailed, gotFailed)
	}
}

func TestFailureExhaustion(t *testing.T) {
	mockTransport := &MockAuditLogTransport{
		delay: 10 * time.Millisecond,
		retry: true,
		fail:  true,
	}

	q := NewAuditLogger(AuditLoggerOpts{
		RetryCount: 3,
		Logf:       t.Logf,
	})

	for i := 0; i < 3; i++ {
		log := tailcfg.ClientAuditLog{
			Details: fmt.Sprintf("log %d", i),
		}
		if err := q.EnqueueAuditLog(mockTransport, log, time.Second*2, nil); err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
	}

	wantFailed, gotFailed := 0, 0
	for i := 0; i < 3; i++ {
		flushed := make(chan int, 1)
		q.Flush(mockTransport, 5*time.Second, flushed)
		gotFailed = <-flushed
	}

	wantSent, gotSent := 0, mockTransport.sendCount

	if wantSent != gotSent {
		t.Fatalf("want %d logs to be flushed, got %d", wantSent, gotSent)
	}

	if wantFailed != gotFailed {
		t.Fatalf("want %d logs to be flushed, got %d", wantFailed, gotFailed)
	}
}

func TestEqueueAndFail(t *testing.T) {
	mockTransport := &MockAuditLogTransport{
		delay: 10 * time.Millisecond,
		fail:  true,
		retry: false,
	}

	q := NewAuditLogger(AuditLoggerOpts{
		RetryCount: 100,
		Logf:       t.Logf,
	})

	flushed := make(chan int)
	failCount := 0
	for i := 0; i < 2; i++ {
		log := tailcfg.ClientAuditLog{
			Details: fmt.Sprintf("log %d", i),
		}
		if err := q.EnqueueAuditLog(mockTransport, log, time.Second*2, flushed); err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
		select {
		case failCount = <-flushed:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for logs to be flushed")
		}
	}

	gotFailed, wantFailed := failCount, 0

	if wantFailed != gotFailed {
		t.Fatalf("expected %d logs to be flushed, got %d", wantFailed, gotFailed)
	}
}

func TestEqueueAndFailTimout(t *testing.T) {
	mockTransport := &MockAuditLogTransport{
		delay: 2 * time.Second,
		fail:  true,
		retry: false,
	}

	q := NewAuditLogger(AuditLoggerOpts{
		RetryCount: 0,
		Logf:       t.Logf,
	})

	flushed := make(chan int)
	failCount := 0
	for i := 0; i < 2; i++ {
		log := tailcfg.ClientAuditLog{
			Details: fmt.Sprintf("log %d", i),
		}
		if err := q.EnqueueAuditLog(mockTransport, log, time.Millisecond, flushed); err != nil {
			t.Fatalf("failed to enqueue audit log: %v", err)
		}
		select {
		case failCount = <-flushed:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for logs to be flushed")
		}
	}

	gotFailed, wantFailed := failCount, 0

	if wantFailed != gotFailed {
		t.Fatalf("expected %d logs to be flushed, got %d", wantFailed, gotFailed)
	}
}
