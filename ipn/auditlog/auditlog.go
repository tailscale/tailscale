// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// package auditlog provides a mechanism for logging client events to the control plane.
package auditlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/version"
)

const (
	// defaultTimeout is the default timeout for a flush operation.
	defaultTimeout = time.Second * 2
)

// PendingAuditLog represents an audit log that has not yet been sent to the control plane.
// Users of the audit logger should create an instance of this struct and pass it to the
// EnqueueAuditLog method.  The EventID, ProfileID, and Retries fields are managed by the logger
// and should not be set by the user.
type PendingAuditLog struct {
	// EventID is the unique identifier for the event being logged.
	EventID string `json:",omitempty"`
	// ProfileID is the fixed, unique user ipn.ProfileID to whom the audit log is associated.
	// This is used for validating that the audit log is being sent by the correct user.
	ProfileID string `json:",omitempty"`
	// Retries is the number of times we've attempted to submit this log.
	Retries int `json:",omitempty"`

	// Action is the action to be logged. It must correspond to a known action in the control plane.
	Action tailcfg.ClientAuditAction `json:",omitempty"`
	// Details is an opaque string, specific to the action being logged. Empty strings may not
	// be valid depending on the action being logged.
	Details string `json:",omitempty"`
	// Timestamp is the time at which the audit log was generated on the node.
	TimeStamp time.Time `json:",omitzero"`
}

func (p *PendingAuditLog) Equals(other PendingAuditLog) bool {
	return p.EventID == other.EventID
}

// AuditLogTransport provides a means for a client to send audit logs.
// to a consumer (typically the control plane).
type AuditLogTransport interface {
	// SendAuditLog sends an audit log to the control plane.
	// If err is non-nil, the log was not sent successfully.
	// If retriable is true, the log may be retried.
	SendAuditLog(ctx context.Context, auditLog tailcfg.AuditLogRequest) (err error, retriable bool)
}

type AuditLogPersistentStore interface {
	// Persist saves the given data to a persistent store.  Persist may disard logs if
	// the store has a size limit.  Persist will overwrite existing data for the given key.
	Persist(key string, data []PendingAuditLog) error

	// Restore retrieves the data from a persistent store. This must return
	// an empty slice if no data exists for the given key.
	Restore(key string) ([]PendingAuditLog, error)
}

// AuditLoggerOpts contains the configuration options for an AuditLogger.
type AuditLoggerOpts struct {
	// RetryLimin is maximum number of attempts the logger will make to send a log before giving up.
	RetryLimit int
	// Store is the persistent store used to save logs to disk.
	Store AuditLogPersistentStore
	// Transport is the initial transport used to send logs to the control plane.
	Transport AuditLogTransport
	// ProfileID is the profile ID for the user associated with this logger.
	ProfileID ipn.ProfileID

	Logf logger.Logf
}

type AuditLoggerState string

const (
	// The state of a logger on constuction and after Stop() is called.  A logger in the stopped state
	// cannot actively flush logs.
	stopped AuditLoggerState = "stopped"
	// The state of a logger after Start() is called.  A logger in the started state must have a running
	// flush worker.
	started AuditLoggerState = "started"
)

type AuditLogger struct {
	logf       logger.Logf
	retryLimit int
	timeout    time.Duration
	profileID  ipn.ProfileID
	store      AuditLogPersistentStore

	// mu protects the fields below.
	mu           sync.Mutex
	transport    AuditLogTransport  // transport used to send logs
	pending      []PendingAuditLog  // pending logs to be sent
	state        AuditLoggerState   // state of the logger
	flusher      chan flushOp       // channel used to signal a flush operation
	flushCancel  context.CancelFunc // cancel function for the current flush operation's context
	flushCtx     context.Context    // context for the current flush
	workerCancel context.CancelFunc // cancel function for the flush worker's context
}

type flushOp struct {
	timeout   time.Duration
	result    chan<- int
	transport AuditLogTransport
}

func NewAuditLogger(opts AuditLoggerOpts) *AuditLogger {
	logger := logger.WithPrefix(opts.Logf, "auditlog: ")
	q := &AuditLogger{
		retryLimit: opts.RetryLimit,
		pending:    []PendingAuditLog{},
		logf:       logger,
		timeout:    defaultTimeout,
		transport:  opts.Transport,
		store:      opts.Store,
		profileID:  opts.ProfileID,
		state:      stopped,
		flusher:    make(chan flushOp),
	}
	q.logf("created for profileID: %v", q.profileID)
	return q
}

func NewAuditLoggerStarted(opts AuditLoggerOpts) *AuditLogger {
	q := NewAuditLogger(opts)
	q.Start(opts.Transport)
	return q
}

// ProfileID returns the profile ID for the user associated with this logger. Multiple AuditLogger
// instances may not simultaneously exist for the same profile ID.
func (q *AuditLogger) ProfileID() ipn.ProfileID {
	return q.profileID
}

// Stop synchronously cancels any incomplete flush operations, stops the audit logger,
// and persists any pending logs to the store. You may continue to send logs to the logger in
// the Stopped state, and they will be persisted to the store.
//
// Calling Flush and waiting on the result before calling stop is is required if you
// want to ensure that an upload is attempted before stopping the logger.
func (q *AuditLogger) Stop() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.state = stopped

	if q.workerCancel != nil {
		q.workerCancel()
	}

	if q.flushCancel != nil {
		q.flushCancel()
	}

	if q.flushCtx != nil {
		select {
		case <-q.flushCtx.Done():
		}
		q.flushCtx = nil
	}

	err := q.persistLogsLocked(q.pending)
	if err != nil {
		// Continue gracefully.
		q.logf("failed to persist logs: %w", err)
	}
	q.pending = []PendingAuditLog{}

	q.logf("stopped for profileID: %v", q.profileID)
}

// Start starts the audit logger, resets the transport to the given value,
// restores any persisted logs and immediately flushes the queue. Returns
// a read-only channel with a buffer size of one indicating the number
// of retriable transactions that remain in the queue.
//
// If the queue is already in the started state, this will reset the transport and
// immediately flush the queue. It is safe to call at-will.  This is non-blocking.
func (q *AuditLogger) Start(t AuditLogTransport) <-chan int {
	q.logf("starting for profileID: %v", q.profileID)
	q.mu.Lock()

	q.transport = t
	to := q.timeout

	var ctx context.Context
	startWorker := false

	if q.state == stopped {
		err := q.restoreLogsLocked()
		if err != nil {
			// Continue gracefully.
			q.logf("failed to restore pending logs: %w", err)
		}
		ctx, q.workerCancel = context.WithCancel(context.Background())
		startWorker = true
	}
	q.state = started
	q.mu.Unlock()

	if startWorker {
		go q.flushWorker(ctx)
	}
	q.logf("started for profileID: %v", q.profileID)

	return q.Flush(to, t)
}

// EnqueueAuditLog queues an audit log to be sent to the control plane.
//
// Returns a receive-only channel that will be sent a single value indicating the number of
// retriable transactions that remain in the queue once flushed.
func (q *AuditLogger) EnqueueAuditLog(log PendingAuditLog) (<-chan int, error) {
	// generate a unique eventID for the log. This is used to de-duplicate logs
	// persisted to the store.
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	eventID := fmt.Sprintf("%d", time.Now().Unix()) + hex.EncodeToString(bytes)

	log.EventID = eventID
	return q.enqueueAuditLog(log, true)
}

// Flush asynchronously sends all pending audit logs to the control plane.
// Calls to Flush are serialized. This returns a 1-buffered channel that will
// a value indicating the number of retriable transactions that remain in the queue
// after the flush operation completes.
//
// The flush operation will be cancelled after the given timeout.
// If t is nil, the transport provided to the logger will be used.
func (q *AuditLogger) Flush(timeout time.Duration, t AuditLogTransport) <-chan int {
	c := make(chan int, 1)

	q.mu.Lock()
	// Important to early exit since a stopped logger will not have a flush worker.
	if q.state == stopped {
		c <- len(q.pending)
		q.mu.Unlock()
		return c
	}

	if q.flushCancel != nil {
		q.flushCancel()
	}
	f := q.flusher
	if t == nil {
		t = q.transport
	}
	q.mu.Unlock()
	f <- flushOp{timeout, c, t}
	return c
}

func (q *AuditLogger) flushWorker(ctx context.Context) {
	for {
		select {
		case op := <-q.flusher:
			q.flush(op.timeout, op.transport, op.result)
		case <-ctx.Done():
			return
		}
	}
}

// flush sends all pending logs to the control plane.
//
// mu must not be held.
// timeout is the maximum time we will permit for the flush operation to complete.
// result sent a single value indicating the number of retriable transactions that
// remain in the queue once flushed.
func (q *AuditLogger) flush(timeout time.Duration, t AuditLogTransport, result chan<- int) {
	q.mu.Lock()
	// Early exit if we're stopped or have no logs to flush.
	if q.state == stopped || len(q.pending) == 0 {
		q.persistLogsLocked(q.pending)
		if result != nil {
			result <- len(q.pending)
		}
		q.mu.Unlock()
		return
	}

	// Extract the pending logs
	pending := q.pending
	// Logs actively being flushed are no longer pending.  Retriable failed transactions
	// will be requeued.
	q.pending = []PendingAuditLog{}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	q.flushCancel = cancel
	q.flushCtx = ctx
	defer cancel()
	q.mu.Unlock()

	requeued := q.sendToTransport(pending, t, ctx)

	// (barnstar) TODO: If requeued is non-zero here, we may want to consider scheduling a future retry.
	// However, LocalBackend calls Start() on a reasonably frequent basis as it is triggered
	// via (controlclient).setPaused(false),  so adding a retry mechanism here if of little practical benefit.

	if result != nil {
		result <- requeued
	}
}

// flushLogsLocked sends all pending logs to the control plane.  Returns the number of logs that
// were requeued.  Persists all pending logs to the store before returning.
// q.mu must be not be held.
func (q *AuditLogger) sendToTransport(pending []PendingAuditLog, t AuditLogTransport, ctx context.Context) (requeued int) {
	failed, sent, requeued := 0, 0, 0

	for _, log := range pending {
		var err error
		var retriable = true

		if t != nil {
			req := tailcfg.AuditLogRequest{
				Action:    tailcfg.ClientAuditAction(log.Action),
				Details:   log.Details,
				Timestamp: log.TimeStamp,
			}

			err, retriable = t.SendAuditLog(ctx, req)
			if err == nil {
				sent++
				continue
			}
			log.Retries++
		}

		failed++
		if !retriable {
			q.logf("failed permanently: %w", err)
			continue
		}

		// We permit a maximum number of retries for each log. All retriable
		// errors should be transient and we should be able to send the log eventually, but
		// we don't want logs to be persisted indefinitely.
		if log.Retries < q.retryLimit {
			// enqueue the log for retry, but do not request an immediate flush
			q.enqueueAuditLog(log, false)
			requeued++
			q.logf("failed, requeued (%d/%d): %w", log.Retries, q.retryLimit, err)
		} else {
			q.logf("failed permanently after %d retries: %w", log.Retries, err)
		}
	}

	// Write down anything that didn't make it to the control plane
	// q.mu.Lock()
	// q.persistLogsLocked(q.pending)
	// q.mu.Unlock()

	return requeued
}

func (q *AuditLogger) restoreLogsLocked() error {
	key := string(q.profileID)

	logs, err := q.store.Restore(key)
	if err != nil {
		// An error on restoration is not fatal.
		logs = []PendingAuditLog{}
		q.logf("failed to restore logs: %w", err)
	}
	// Logs are back in the queue, remove them from the persistent store
	err = q.store.Persist(key, nil)
	if err != nil {
		q.logf("failed to restore logs: %w", err)
		return err
	}

	q.logf("restored %d pending logs for profileId %v", len(logs), q.ProfileID())
	q.pending = append(q.pending, logs...)
	return nil
}

// persistLogsLocked persists logs to the store that are
// not already present in the store.
//
// q.mu must be held.
func (q *AuditLogger) persistLogsLocked(p []PendingAuditLog) error {
	if len(p) == 0 {
		return nil
	}

	key := string(q.profileID)
	logs, _ := q.store.Restore(key)

	// Create a map of existing event IDs for de-duplication
	existingEventIDs := make(map[string]struct{})
	for _, log := range logs {
		existingEventIDs[log.EventID] = struct{}{}
	}

	for _, pendingLog := range p {
		if _, exists := existingEventIDs[pendingLog.EventID]; !exists {
			logs = append(logs, pendingLog)
		}
	}

	return q.store.Persist(key, logs)
}

func (q *AuditLogger) enqueueAuditLog(log PendingAuditLog, flush bool) (<-chan int, error) {
	q.mu.Lock()
	if log.ProfileID != string(q.profileID) {
		return nil, fmt.Errorf("invalid profile ID: %v", log.ProfileID)
	}

	result := make(chan int, 1)

	if q.state == stopped {
		q.logf("stopped. persisting audit log: %v", log)
		q.persistLogsLocked([]PendingAuditLog{log})
		result <- 1
		q.mu.Unlock()
		return result, nil
	}

	q.logf("enqueueing audit log: %v", log)
	q.pending = append(q.pending, log)
	timeout := q.timeout
	transport := q.transport
	q.mu.Unlock()
	if !flush {
		return nil, nil
	}

	return q.Flush(timeout, transport), nil

}

var _ AuditLogPersistentStore = (*AuditLogStateStore)(nil)

// AuditLogStateStore is a concrete implementation of AuditLogPersistentStore
// using ipn.StateStore as the underlying storage.
type AuditLogStateStore struct {
	mu    sync.Mutex
	store ipn.StateStore
	logf  logger.Logf
}

func NewAuditLogStateStore(store ipn.StateStore, logf logger.Logf) AuditLogPersistentStore {
	return &AuditLogStateStore{
		store: store,
		logf:  logf,
	}
}

// Persist saves the given logs to an ipn.StateStore. This overwrites
// any existing entries for the given key.
func (a *AuditLogStateStore) Persist(key string, logs []PendingAuditLog) error {
	// Sort logs by timestamp - oldest to newest
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].TimeStamp.Before(logs[j].TimeStamp)
	})

	// AppStore variants have a hard limit of 4Kb with their default StateStore implementation
	if runtime.GOOS == "ios" || (runtime.GOOS == "darwin" && version.IsMacAppStore()) || version.IsAppleTV() {
		trimmedLogs, err := a.limitLogSize(logs, 4096)
		if err != nil {
			return err
		}
		logs = trimmedLogs
	}

	data, err := json.Marshal(logs)
	if err != nil {
		return err
	}

	k := ipn.StateKey(key)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.store.WriteState(k, data)

	return nil
}

// limitLogSize removes the first entry in the given list repeatedly until
// the total size of the serialized logs is less than or equal to the given max size.
func (a *AuditLogStateStore) limitLogSize(logs []PendingAuditLog, max int) ([]PendingAuditLog, error) {
	if len(logs) == 0 {
		return logs, nil
	}

	// macOS and iOS have a hard limit of 4Kb with their default StateStore implementation
	data, err := json.Marshal(logs)
	if err != nil {
		return nil, err
	}

	for len(data) > max && len(logs) > 0 {
		logs = logs[1:]
		data, err = json.Marshal(logs)
		if err != nil {
			return nil, err
		}
	}
	return logs, nil
}

// Restore retrieves the logs from an ipn.StateStore.
func (a *AuditLogStateStore) Restore(key string) ([]PendingAuditLog, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	k := ipn.StateKey(key)
	data, err := a.store.ReadState(k)

	switch {
	case errors.Is(err, ipn.ErrStateNotExist):
		return []PendingAuditLog{}, nil
	case err != nil:
		return nil, err
	}

	var logs []PendingAuditLog
	if err := json.Unmarshal(data, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}
