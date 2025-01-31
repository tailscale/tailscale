// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

type auditLogSender func(ctx context.Context, auditLog tailcfg.ClientAuditLog) (err error, retriable bool)

// queuedAuditLogger manages a queue of audit logs to be sent to the control server.
// It handles periodic retries for unsent logs.
type queuedAuditLogger struct {
	// Unguarded fields.  These should never be mutated.
	retryCount int           // maximum number of retries
	retryDelay time.Duration // delay between retries
	sendFunc   auditLogSender
	logf       logger.Logf
	ctx        context.Context // ctx managed by the queue's owner

	mu         sync.Mutex
	pending    []tailcfg.ClientAuditLog // pending logs to be sent
	flush      chan struct{}            // signals queue drain
	stop       chan struct{}            // signals worker stop
	retryTimer *time.Timer              // set upon failures to trigger sending unflushed logs
}

type queuedAuditLoggerOpts struct {
	Ctx        context.Context
	RetryCount int
	RetryDelay time.Duration
	SendFunc   auditLogSender
	Logf       logger.Logf
}

func newQueuedAuditLogger(opts queuedAuditLoggerOpts) *queuedAuditLogger {
	q := &queuedAuditLogger{
		ctx:        opts.Ctx,
		retryDelay: opts.RetryDelay,
		retryCount: opts.RetryCount,
		sendFunc:   opts.SendFunc,
		pending:    []tailcfg.ClientAuditLog{},
		flush:      make(chan struct{}, 1),
		stop:       make(chan struct{}),
		logf:       opts.Logf,
	}
	return q
}

// cancelPending cancels all pending audit logs.
func (q *queuedAuditLogger) cancelPending() {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.retryTimer != nil {
		q.retryTimer.Stop()
		q.retryTimer = nil
	}

	if len(q.pending) != 0 {
		q.logf("cancelling %d pending audit logs", len(q.pending))
	}
	q.pending = []tailcfg.ClientAuditLog{}
}

// stopAndFlush stops the audit log queue.  We give a maximum of 3 seconds
// to flush the queue before returning.
func (q *queuedAuditLogger) stopAndFlush() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q.flushQueue(ctx, true)

	q.stop <- struct{}{}
}

// start starts the audit log queue and immeidately attempts to send
// any pending logs.
func (q *queuedAuditLogger) start() {
	q.mu.Lock()
	defer func() {
		flush := q.flush
		q.mu.Unlock()
		flush <- struct{}{}
	}()

	q.stop = make(chan struct{})
	q.flush = make(chan struct{}, 1)
	go auditLogWorker(q)
}

func auditLogWorker(q *queuedAuditLogger) {
	for {
		select {
		case <-q.stop:
			return
		case <-q.flush:
			q.flushQueue(q.ctx, false)
		}
	}
}

// enqueue adds an audit log to the queue and immediately
// attempts to flush the queue.
func (q *queuedAuditLogger) enqueue(auditLog tailcfg.ClientAuditLog) {
	q.mu.Lock()
	q.pending = append(q.pending, auditLog)
	d := q.flush
	q.mu.Unlock()

	d <- struct{}{}
}

func (q *queuedAuditLogger) flushQueue(ctx context.Context, finalize bool) {
	q.logf("flushing audit log queue")
	q.mu.Lock()
	pending := q.pending
	q.pending = []tailcfg.ClientAuditLog{}
	q.mu.Unlock()

	if len(pending) == 0 {
		q.logf("audit log flush complete - queue is empty")
		return
	}

	failures := make([]tailcfg.ClientAuditLog, 0, len(pending))
	for _, log := range pending {
		err, retriable := q.sendFunc(ctx, log)
		if err == nil {
			continue
		}

		if !retriable {
			q.logf("audit log send failed permanently: %v", err)
			continue
		}

		log.Retries++
		if log.Retries < q.retryCount {
			failures = append(failures, log)
		} else {
			q.logf("audit log send failed permanently after %d retries: %v", log.Retries, err)
		}
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	q.pending = append(failures, q.pending...)
	q.persistUnflushedLogs()

	if len(q.pending) > 0 {
		if finalize {
			q.logf("audit log queue finalized with %d pending logs", len(q.pending))
		} else {
			if nil != q.retryTimer {
				q.retryTimer.Stop()
			}

			d := q.flush
			q.retryTimer = time.AfterFunc(q.retryDelay, func() {
				d <- struct{}{}
			})
		}
	}
}

func (q *queuedAuditLogger) persistUnflushedLogs() {
	// (barstar) TODO: Out of scope for now, but we should persist
	// any unflushed logs and restore them on startup.
}

func (c *Direct) sendAuditLog(ctx context.Context, auditLog tailcfg.ClientAuditLog) (err error, retriable bool) {
	nc, err := c.getNoiseClient()
	if err != nil {
		return err, true
	}

	req := &tailcfg.AuditLogRequest{
		NodeKey: auditLog.NodeKey,
		Action:  auditLog.Action,
		Details: auditLog.Details,
	}

	if c.panicOnUse {
		panic("tainted client")
	}

	res, err := nc.post(ctx, "/machine/audit-log", auditLog.NodeKey, req)
	if err != nil {
		return err, true
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(res.Body)
		// Are any errors from the control plane retriable?  We will assume not for now.
		return fmt.Errorf("HTTP error from control plane: %v, %s", res.Status, msg), false
	}
	return nil, true
}
