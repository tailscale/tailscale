// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

type AuditLogTransport interface {
	SendAuditLog(ctx context.Context, auditLog tailcfg.ClientAuditLog) (err error, retriable bool)
}

type AuditLogger interface {
	// EnqueueAuditLog queues an audit log to be sent to the control plane.
	EnqueueAuditLog(transport AuditLogTransport, log tailcfg.ClientAuditLog, timeout time.Duration, flushed chan int) error

	// Flush synchronously sends all pending audit logs to the control plane
	// Calls to Flush are serialized.  If a flush is already in progress, this
	// will block until the current flush completes and immediately retry any failures.
	// The flushed chan will be sent a value indicating the number of retriable transactions
	// that remain in the queue.
	Flush(transport AuditLogTransport, timeout time.Duration, unsent chan int)

	// Discard discards all pending audit logs, saving them to disk if necessary.
	DiscardAndPersist()

	// RestoreUnflushedLogs restores any unflushed logs from disk on startup.
	RestoreUnflushedLogs(id ProfileID)

	// Destroys any unflushed logs for the given profile ID.
	DestroyUnflushedLogs(id ProfileID)
}

type auditLogger struct {
	logf       logger.Logf
	retryCount int // maximum number of attempts to send an audit log before giving up

	flushMu sync.Mutex

	mu      sync.Mutex
	cancel  context.CancelFunc       // cancel function for the current flush
	pending []tailcfg.ClientAuditLog // pending logs to be sent
}

type AuditLoggerOpts struct {
	RetryCount int
	Logf       logger.Logf
}

func NewAuditLogger(opts AuditLoggerOpts) AuditLogger {
	logger := logger.WithPrefix(opts.Logf, "auditlog: ")
	q := &auditLogger{
		retryCount: opts.RetryCount,
		pending:    []tailcfg.ClientAuditLog{},
		logf:       logger,
	}
	return q
}

func (q *auditLogger) Flush(transport AuditLogTransport, timeout time.Duration, result chan int) {
	// Serialize flushes
	q.flushMu.Lock()
	defer q.flushMu.Unlock()

	q.mu.Lock()
	pending := q.pending
	q.pending = []tailcfg.ClientAuditLog{}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	q.cancel = cancel
	defer cancel()
	q.mu.Unlock()

	if len(pending) == 0 {
		if result != nil {
			result <- 0
		}
		return
	}

	failures := make([]tailcfg.ClientAuditLog, 0, len(pending))
	failed, sent := 0, 0
	for _, log := range pending {
		err, retriable := transport.SendAuditLog(ctx, log)
		if err == nil {
			sent++
			continue
		}
		failed++
		if !retriable {
			q.logf("send failed permanently: %v", err)
			continue
		}

		// We permit a fixed number of retries for each log.
		log.Retries++
		if log.Retries < q.retryCount {
			failures = append(failures, log)
			q.logf("send failed, retrying (%d/%d): %v", log.Retries, q.retryCount, err)
		} else {
			q.logf("send failed permanently after %d retries: %v", log.Retries, err)
		}
	}

	q.logf("%d flushed, %d failures", sent, failed)

	q.mu.Lock()
	defer q.mu.Unlock()

	q.pending = append(failures, q.pending...)
	q.persistUnflushedLogsLocked()

	if result != nil {
		result <- len(failures)
	}
}

func (q *auditLogger) DestroyUnflushedLogs(id ProfileID) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pending = []tailcfg.ClientAuditLog{}

	// (barstar) TODO: Destroy any persisted logs for the given profile ID.
}

func (q *auditLogger) RestoreUnflushedLogs(id ProfileID) {
	// (barstar) TODO: Out of scope for now, but we should restore
	// any unflushed logs from disk on startup.
}

func (q *auditLogger) persistUnflushedLogsLocked() {
	// (barstar) TODO: Out of scope for now, but we should persist
	// any unflushed logs so that on events like a crash, system restart,
	// we can restore them.
}

func (q *auditLogger) DiscardAndPersist() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) != 0 {
		q.cancel()
		q.persistUnflushedLogsLocked()
		q.logf("discarding %d unflushed logs", len(q.pending))
		q.pending = []tailcfg.ClientAuditLog{}
	}
}

func (q *auditLogger) EnqueueAuditLog(transport AuditLogTransport, log tailcfg.ClientAuditLog, timeout time.Duration, result chan int) error {
	// Some suitably random event identifier
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return err
	}
	eventID := fmt.Sprintf("%d", time.Now().Unix()) + hex.EncodeToString(bytes)
	log.EventID = eventID

	q.mu.Lock()
	q.pending = append(q.pending, log)
	q.mu.Unlock()

	go func() {
		q.Flush(transport, timeout, result)
	}()
	return nil
}
