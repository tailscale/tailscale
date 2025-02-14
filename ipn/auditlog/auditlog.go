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
	// defaultTimeout is the default timeout for a flush operation.  This also represents the
	// minimum interval between flush operations that we'll trigger via Start
	defaultTimeout = time.Second * 5
)

// PendingAuditLog represents an audit log that has not yet been sent to the control plane.
// Users of the audit logger should create an instance of this struct and pass it to the
// Enqueue method.  The EventID, ProfileID, and Retries fields are managed by the logger
// and should not be set by the user.
type PendingAuditLog struct {
	// EventID is the unique identifier for the event being logged.
	EventID string `json:",omitempty"`
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

// Transport provides a means for a client to send audit logs.
// to a consumer (typically the control plane).
type Transport interface {
	// SendAuditLog sends an audit log to the control plane.
	// If err is non-nil, the log was not sent successfully.
	// If retriable is true, the log may be retried.
	SendAuditLog(ctx context.Context, auditLog tailcfg.AuditLogRequest) (err error, retriable bool)
}

// PersistentStore provides a means for an audit logger to persist logs to disk or memory.
type PersistentStore interface {
	// Persist saves the given data to a persistent store.  Persist may disard logs if
	// the store has a fixed size limit.  Persist will overwrite existing data for the given key.
	Persist(key string, data []PendingAuditLog) error

	// Restore retrieves the data from a persistent store. This must return
	// an empty slice if no data exists for the given key.
	Restore(key string) ([]PendingAuditLog, error)
}

// Opts contains the configuration options for an AuditLogger.
type Opts struct {
	// RetryLimit is maximum number of attempts the logger will make to send a log before giving up.
	RetryLimit int
	// Store is the persistent store used to save logs to disk.
	Store PersistentStore

	Logf logger.Logf
}

type State string

const (
	// stopped is the initial state of the logger and the state after Stop() is called.  A logger in the stopped state
	// cannot flush logs but may accept new logs to be enqueued.
	stopped State = "stopped"
	// started is the state of a logger after Start() is called.  A logger in the started state must have a running
	// flush worker.
	started State = "started"
)

type AuditLogger struct {
	logf       logger.Logf
	retryLimit int
	timeout    time.Duration
	logId      string
	store      PersistentStore

	// mu protects the fields below.
	mu           sync.Mutex
	transport    Transport          // transport used to send logs
	pending      []PendingAuditLog  // pending logs to be sent
	state        State              // state of the logger
	flusher      chan flushOp       // channel used to signal a flush operation
	flushCancel  context.CancelFunc // cancel function for the current flush operation's context
	flushCtx     context.Context    // context for the current flush
	workerCancel context.CancelFunc // cancel function for the flush worker's context

	lastFlush time.Time
}

type retryOp struct {
	delay time.Duration
}

type flushOp struct {
	timeout   time.Duration
	result    chan<- FlushResult
	transport Transport
}

type FlushResult int

func NewAuditLogger(opts Opts) *AuditLogger {
	logger := logger.WithPrefix(opts.Logf, "auditlog: ")
	q := &AuditLogger{
		retryLimit: opts.RetryLimit,
		pending:    []PendingAuditLog{},
		logf:       logger,
		timeout:    defaultTimeout,
		store:      opts.Store,
		state:      stopped,
		flusher:    make(chan flushOp),
	}
	q.logf("created")
	return q
}

func (q *AuditLogger) FlushAndStop(timeout time.Duration) {
	c := q.Flush(timeout, nil)
	<-c
	q.stop()
}

// SetTransport starts the audit logger, resets the transport to the given value,
// restores any persisted logs and immediately flushes the queue if it
// was in the stopped state. Returns a read-only channel with a buffer
// size of one indicating the number of retriable transactions that remain in the queue.
//
// # If this is called in the Started state
//
// If the queue is already in the started state, this will reset the transport and
// immediately flush the queue. This is non-blocking and safe to call at-will.
func (q *AuditLogger) SetTransport(t Transport, logId string) <-chan FlushResult {
	q.mu.Lock()

	q.transport = t
	q.logId = logId
	to := q.timeout
	len := len(q.pending)
	last := q.lastFlush

	if q.state == started {
		q.mu.Unlock()
		return q.retryIfNeeded(t, to, len, last)
	}

	var ctx context.Context

	err := q.restoreLocked()
	if err != nil {
		// Continue gracefully.
		q.logf("failed to restore pending logs: %w", err)
	}
	ctx, q.workerCancel = context.WithCancel(context.Background())
	q.logf("started for logID: %v", q.logId)

	q.state = started
	q.mu.Unlock()

	go q.flushWorker(ctx)
	return q.Flush(to, t)
}

func (q *AuditLogger) retryIfNeeded(t Transport, interval time.Duration, pending int, lastAttempt time.Time) <-chan FlushResult {
	if time.Since(lastAttempt) < interval || pending == 0 {
		c := make(chan FlushResult, 1)
		c <- FlushResult(pending)
		return c
	} else {
		return q.Flush(q.timeout, t)
	}
}

// Enqueue queues an audit log to be sent to the control plane.
//
// Returns a receive-only channel that will be sent a single value indicating the number of
// retriable transactions that remain in the queue once flushed.
func (q *AuditLogger) Enqueue(log PendingAuditLog) (<-chan FlushResult, error) {
	// generate a unique eventID for the log. This is used to de-duplicate logs
	// persisted to the store.
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	eventID := fmt.Sprintf("%d", time.Now().Unix()) + hex.EncodeToString(bytes)

	log.EventID = eventID
	return q.enqueue(log, true)
}

// Flush asynchronously sends all pending audit logs to the control plane.
// This will cancel any flush operations that are in-flight and start a new flush operation.
// Calls to Flush are serialized. This returns a 1-buffered channel that will
// a value indicating the number of retriable transactions that remain in the queue
// after the flush operation completes.
//
// The flush operation will be cancelled after the given timeout.
// If t is nil, the loggers current transport (if any) will be used.
func (q *AuditLogger) Flush(timeout time.Duration, t Transport) <-chan FlushResult {
	c := make(chan FlushResult, 1)

	q.mu.Lock()

	// Important to early exit since a stopped logger will not have a flush worker.
	if q.state == stopped {
		c <- FlushResult(len(q.pending))
		q.mu.Unlock()
		return c
	}

	if q.flushCancel != nil {
		q.flushCancel()
	}
	if q.flushCtx != nil {
		<-q.flushCtx.Done()
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
// timeout is the maximum time we will permit for the flush operation to complete.
// result should be a 1-buffered chan that will always be sent a single value indicating
// the number of retriable transactions that remain in the queue once the flush completes.
//
// q.mu must not be held.
func (q *AuditLogger) flush(timeout time.Duration, t Transport, result chan<- FlushResult) {
	q.mu.Lock()
	// Early exit if we're stopped or have no logs to flush.
	if q.state == stopped || len(q.pending) == 0 || t == nil {
		q.persistLocked(q.pending)
		if result != nil {
			result <- FlushResult(len(q.pending))
		}
		q.mu.Unlock()
		return
	}

	pending := q.pending
	// Logs actively being flushed are no longer pending.  Retriable failed transactions
	// will be requeued.
	q.pending = []PendingAuditLog{}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	q.flushCancel = cancel
	q.flushCtx = ctx
	q.lastFlush = time.Now()
	defer cancel()
	q.mu.Unlock()

	requeued := q.sendToTransport(pending, t, ctx)

	if result != nil {
		result <- FlushResult(requeued)
	}
}

// flushLogsLocked sends all pending logs to the control plane.  Returns the number of logs that
// were requeued.  Persists all pending logs to the store before returning.
//
// This may require multiple round trips to the control plane and can be a long running transaction.
// q.mu must be not be held.
func (q *AuditLogger) sendToTransport(pending []PendingAuditLog, t Transport, ctx context.Context) (requeued int) {
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
			// enqueue the log for retry, but do not request an immediate flush.
			q.enqueue(log, false)
			requeued++
		} else {
			q.logf("failed permanently after %d retries: %w", log.Retries, err)
		}
	}
	q.logf("requeued %d, sent %d, failed %d", requeued, sent, failed)
	return requeued
}

// stop synchronously cancels any incomplete flush operations, stops the audit logger,
// and persists any pending logs to the store. You may continue to send logs to the logger in
// the Stopped state, and they will be persisted to the store.
//
// Calling Flush and waiting on the result before calling stop is is required if you
// want to ensure that a flush is attempted before stopping the logger.
func (q *AuditLogger) stop() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.state == stopped {
		return
	}

	q.state = stopped
	q.transport = nil

	if q.workerCancel != nil {
		q.workerCancel()
	}

	if q.flushCancel != nil {
		q.flushCancel()
	}

	if q.flushCtx != nil {
		<-q.flushCtx.Done()
		q.flushCtx = nil
	}

	err := q.persistLocked(q.pending)
	if err != nil {
		// Continue gracefully.
		q.logf("failed to persist logs: %w", err)
	}
	c := len(q.pending)
	q.pending = []PendingAuditLog{}
	q.logf("stopped for profileID: %v persisted: %d", q.logId, c)
}

// restoreLocked restores logs from the persistent store and
// appends them to q.pending.
//
// q.mu must be held.
func (q *AuditLogger) restoreLocked() error {
	if q.logId == "" {
		return errors.New("no logId set")
	}

	key := string(q.logId)

	logs, err := q.store.Restore(key)
	if err != nil {
		// An error on restoration is not fatal.
		logs = []PendingAuditLog{}
		q.logf("failed to restore logs: %w", err)
	}
	// Logs are back in the queue, remove them from the persistent store.
	err = q.store.Persist(key, nil)
	if err != nil {
		q.logf("failed to restore logs: %w", err)
		return err
	}

	q.logf("restored %d pending logs for profileId %v", len(logs), q.logId)
	q.pending = deduplicateAndSort(append(q.pending, logs...))
	return nil
}

// persistLocked persists logs to the store that are
// not already present in the store.
//
// q.mu must be held.
func (q *AuditLogger) persistLocked(p []PendingAuditLog) error {
	if len(p) == 0 {
		return nil
	}

	if q.logId == "" {
		return errors.New("no logId set")
	}

	key := string(q.logId)
	persisted, _ := q.store.Restore(key)
	logs := append(persisted, p...)
	logs = deduplicateAndSort(logs)

	return q.store.Persist(key, logs)
}

func deduplicateAndSort(logs []PendingAuditLog) []PendingAuditLog {
	seen := make(map[string]struct{})
	deduped := []PendingAuditLog{}
	for _, log := range logs {
		if _, ok := seen[log.EventID]; !ok {
			deduped = append(deduped, log)
			seen[log.EventID] = struct{}{}
		}
	}
	// Sort logs by timestamp - oldest to newest
	sort.Slice(deduped, func(i, j int) bool {
		return logs[i].TimeStamp.Before(logs[j].TimeStamp)
	})
	return deduped
}

func (q *AuditLogger) enqueue(log PendingAuditLog, flush bool) (<-chan FlushResult, error) {
	q.mu.Lock()

	result := make(chan FlushResult, 1)

	if q.state == stopped {
		q.pending = append(q.pending, log)
		q.persistLocked([]PendingAuditLog{log})
		result <- FlushResult(len(q.pending))
		q.mu.Unlock()
		return result, nil
	}

	q.pending = append(q.pending, log)
	timeout := q.timeout
	transport := q.transport
	q.mu.Unlock()
	if !flush {
		return nil, nil
	}

	return q.Flush(timeout, transport), nil

}

var _ PersistentStore = (*StateStore)(nil)

// StateStore is a concrete implementation of PersistentStore
// using ipn.StateStore as the underlying storage.
type StateStore struct {
	mu    sync.Mutex
	store ipn.StateStore
	logf  logger.Logf
}

func NewStateStore(store ipn.StateStore, logf logger.Logf) PersistentStore {
	return &StateStore{
		store: store,
		logf:  logf,
	}
}

// Persist saves the given logs to an ipn.StateStore. This overwrites
// any existing entries for the given key.
func (a *StateStore) Persist(key string, logs []PendingAuditLog) error {
	// Sort logs by timestamp - oldest to newest
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].TimeStamp.Before(logs[j].TimeStamp)
	})

	// AppStore variants have a hard limit of 4Kb with their default StateStore implementation.
	// (barnstar) TODO: Plumb in a more generic file-based store without the size limitations using
	// shared storage similar to macsys.
	if runtime.GOOS == "ios" || (runtime.GOOS == "darwin" && version.IsMacAppStore()) || version.IsAppleTV() {
		trimmedLogs, err := a.truncateLogs(logs, 4096)
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

// truncateLogs removes the first entry in the given slice of logs repeatedly until
// the total size of the serialized logs is less than or equal to the given max size.
func (a *StateStore) truncateLogs(logs []PendingAuditLog, maxBytes int) ([]PendingAuditLog, error) {
	if len(logs) == 0 {
		return logs, nil
	}

	data, err := json.Marshal(logs)
	if err != nil {
		return nil, err
	}

	for len(data) > maxBytes && len(logs) > 0 {
		logs = logs[1:]
		data, err = json.Marshal(logs)
		if err != nil {
			return nil, err
		}
	}
	return logs, nil
}

// Restore retrieves the logs from an ipn.StateStore.
func (a *StateStore) Restore(key string) ([]PendingAuditLog, error) {
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
