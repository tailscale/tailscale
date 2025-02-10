// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// package auditlog provides a reliable mechanism for logging client events to the control plane.
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
	defaultTimeout = time.Second * 5
)

// AuditLogTxn represents an audit log that has not yet been sent to the control plane.
// Users of the audit logger should create an instance of this struct and pass it to the
// Enqueue method. The EventID, ProfileID, and Retries fields are managed by the logger
// and should not be set by the user.
type AuditLogTxn struct {
	// EventID is the unique identifier for the event being logged.  This is generated automatically
	// by auditlog.Enqueue and should not be set by the user.
	EventID string `json:",omitempty"`
	// Retries is the number of times the logger has attempted to send this log.  This is set and
	// updated automatically by the logger and should not be set by the user.
	Retries int `json:",omitempty"`

	// Action is the action to be logged. It must correspond to a known action in the control plane.
	Action tailcfg.ClientAuditAction `json:",omitempty"`
	// Details is an opaque string specific to the action being logged. Empty strings may not
	// be valid depending on the action being logged.
	Details string `json:",omitempty"`
	// TimeStamp is the time at which the audit log was generated on the node.
	TimeStamp time.Time `json:",omitzero"`
}

func (p *AuditLogTxn) Equals(other AuditLogTxn) bool {
	// Transactions are equal if their EventIDs match.
	return p.EventID == other.EventID
}

// Transport provides a means for a client to send audit logs to a consumer (typically the control plane).
type Transport interface {
	// SendAuditLog sends an audit log to the control plane.
	// If err is non-nil, the log was not sent successfully.
	// If retriable is true, the log may be retried.
	SendAuditLog(ctx context.Context, auditLog tailcfg.AuditLogRequest) (err error, retriable bool)
}

// PersistentStore provides a means for an audit logger to persist logs to disk or memory.
type PersistentStore interface {
	// Persist saves the given data to a persistent store. Persist may discard logs if
	// the store has a fixed size limit. Persist will overwrite existing data for the given key.
	Persist(key string, logs []AuditLogTxn) error

	// Restore retrieves the data from a persistent store. This must return
	// an empty slice if no data exists for the given key.
	Restore(key string) ([]AuditLogTxn, error)
}

// Opts contains the configuration options for an AuditLogger.
type Opts struct {
	// RetryLimit is the maximum number of attempts the logger will make to send a log before giving up.
	RetryLimit int
	// Store is the persistent store used to save logs to disk.
	Store PersistentStore
	// Logf is the logger used to log messages from the audit logger.
	Logf logger.Logf
}

type State string

const (
	// stopped is the initial state of the logger and the state after FlushAndStop() is called. A logger in the stopped state
	// cannot flush logs but may accept new logs to be enqueued.
	stopped State = "stopped"
	// started is the state of a logger after SetTransport() is called. A logger in the started state must have a running
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
	pending      []AuditLogTxn      // pending logs to be sent
	state        State              // state of the logger
	flusher      chan flushOp       // channel used to signal a flush operation
	flushCancel  context.CancelFunc // cancel function for the current flush operation's context
	flushCtx     context.Context    // context for the current flush
	workerCancel context.CancelFunc // cancel function for the flush worker's context

	retryBackoff time.Duration      // backoff time for retrying failed transactions
	retryCancel  context.CancelFunc // cancel function for the current retry operation's context
}

type flushOp struct {
	timeout   time.Duration      // non-zero.  the http timeout for each individual transaction
	result    chan<- FlushResult // or nil
	transport Transport          // non-nil
}

type FlushResult int

func NewAuditLogger(opts Opts) *AuditLogger {
	logger := logger.WithPrefix(opts.Logf, "auditlog: ")
	q := &AuditLogger{
		retryLimit:   opts.RetryLimit,
		pending:      []AuditLogTxn{},
		logf:         logger,
		timeout:      defaultTimeout,
		store:        opts.Store,
		state:        stopped,
		flusher:      make(chan flushOp),
		retryBackoff: time.Millisecond * 500,
	}
	q.logf("created")
	return q
}

// FlushAndStop synchronously flushes all pending logs and stops the audit logger.
// This will block until the flush operation completes or the timeout is reached.
// If the logger is already stopped, this will return immediately.
// If the logger is in the started state, this will stop the logger and flush any pending logs and
// leave the logger in the stopped state.
func (al *AuditLogger) FlushAndStop(timeout time.Duration) {
	c := al.Flush(timeout, nil)
	<-c
	al.stop()
}

// SetTransport starts the audit logger, resets the transport to the given value,
// restores any persisted logs and immediately flushes the queue if it
// was in the stopped state. Returns a read-only channel with a buffer
// size of one that will be sent a value indicating the number of retriable transactions
// that remain in the queue.  This will be sent immediately if the logger is in the started state.
func (al *AuditLogger) SetTransport(t Transport, logId string) <-chan FlushResult {
	al.mu.Lock()

	al.transport = t
	al.logId = fmt.Sprintf("audit-logs-%s", logId)
	to := al.timeout
	len := len(al.pending)

	// early exit if the logger is already started.  Just return the pending count.
	if al.state == started {
		c := make(chan FlushResult, 1)
		c <- FlushResult(len)
		al.mu.Unlock()
		return c
	}

	err := al.restoreLocked()
	if err != nil {
		// Continue gracefully.
		al.logf("failed to restore pending logs: %w", err)
	}

	var ctx context.Context
	ctx, al.workerCancel = context.WithCancel(context.Background())
	al.logf("started for logID: %v", al.logId)

	al.state = started
	al.mu.Unlock()

	go al.flushWorker(ctx)
	return al.Flush(to, t)
}

// Enqueue queues an audit log to be sent to the control plane.
//
// Returns a receive-only channel that will be sent a single value indicating the number of
// retriable transactions that remain in the queue once flushed.
func (al *AuditLogger) Enqueue(txn AuditLogTxn) (<-chan FlushResult, error) {
	// On apple platforms, we support audit logging on standalone macsys only.  The other platforms
	// utilize the keyhchain as their persistent store and will require a separate file-based implementation.
	if runtime.GOOS == "ios" || (runtime.GOOS == "darwin" && version.IsMacAppStore()) {
		return nil, errors.New("audit logging is not supported on this platform")
	}

	// generate a unique eventID for the log. This is used to de-duplicate logs
	// persisted to the store.
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	eventID := fmt.Sprintf("%d", time.Now().Unix()) + hex.EncodeToString(bytes)

	txn.EventID = eventID
	return al.enqueue(txn, true)
}

// Flush asynchronously sends all pending audit logs to the control plane.
// This will cancel any flush operations that are in-flight and start a new flush operation.
// Calls to Flush are serialized. This returns a 1-buffered channel that will
// a value indicating the number of retriable transactions that remain in the queue
// after the flush operation completes.
//
// The flush operation will be cancelled after the given timeout.
// If t is nil, the loggers current transport (if any) will be used.
func (al *AuditLogger) Flush(timeout time.Duration, t Transport) <-chan FlushResult {
	c := make(chan FlushResult, 1)

	al.mu.Lock()

	// Important to early exit since a stopped logger will not have a flush worker.
	if al.state == stopped || len(al.pending) == 0 {
		c <- FlushResult(len(al.pending))
		al.mu.Unlock()
		return c
	}

	if al.flushCancel != nil {
		al.flushCancel()
	}
	if al.flushCtx != nil {
		<-al.flushCtx.Done()
	}

	f := al.flusher
	if t == nil {
		t = al.transport
	}
	al.mu.Unlock()

	f <- flushOp{timeout, c, t}
	return c
}

func (al *AuditLogger) flushWorker(ctx context.Context) {
	for {
		select {
		case op := <-al.flusher:
			al.flush(op.timeout, op.transport, op.result)
		case <-ctx.Done():
			return
		}
	}
}

func (al *AuditLogger) retryWorker(ctx context.Context, interval time.Duration) {
	select {
	case <-time.After(interval):
		al.logf("retrying failed transactions (waited %v s)", interval.Seconds())
		al.Flush(defaultTimeout, nil)
	case <-ctx.Done():
		al.logf("retry cancelled")
	}
}

// flush sends all pending logs to the control plane.
//
// timeout is the maximum time we will permit for the flush operation to complete.
// result should be a 1-buffered chan that will always be sent a single value indicating
// the number of retriable transactions that remain in the queue once the flush completes.
//
// al.mu must not be held.
func (al *AuditLogger) flush(timeout time.Duration, t Transport, result chan<- FlushResult) {
	al.mu.Lock()
	// We're about to flush, so any retry operation should be cancelled.
	if al.retryCancel != nil {
		al.retryCancel()
	}

	// Early exit if we're stopped or have no logs to flush.
	if al.state == stopped || len(al.pending) == 0 || t == nil {
		if result != nil {
			result <- FlushResult(len(al.pending))
		}
		al.mu.Unlock()
		return
	}

	pending := al.pending
	// Logs actively being flushed are no longer pending. Retriable failed transactions
	// will be requeued.  These remain persisted until they are successfully sent, to
	// there is not loss of data on a crash, etc.
	al.pending = []AuditLogTxn{}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	al.flushCancel = cancel
	al.flushCtx = ctx
	defer cancel()
	al.mu.Unlock()

	requeued := al.sendToTransport(pending, t, ctx)

	al.retryIfNeeded(requeued)

	if result != nil {
		result <- FlushResult(requeued)
	}
}

func (al *AuditLogger) retryIfNeeded(requeued int) {
	al.mu.Lock()
	defer al.mu.Unlock()
	// Nothing to retry, just reset the backoff timer.
	if requeued == 0 {
		al.retryBackoff = time.Millisecond * 500
		return
	}

	var ctx context.Context
	ctx, al.retryCancel = context.WithCancel(context.Background())
	//.5s, 1s, 2s, 4s, 8s, 10s, 10s, 10s....
	al.retryBackoff = min(al.retryBackoff*2, time.Second*10)
	al.logf("will retry %d failed transactions in %v seconds", requeued, al.retryBackoff.Seconds())
	go al.retryWorker(ctx, al.retryBackoff)
}

// sendToTransport sends all pending logs to the control plane. Returns the number of logs that
// were requeued. Persists all pending logs to the store before returning.
//
// This may require multiple round trips to the control plane and can be a long running transaction.
// al.mu must be not be held.
func (al *AuditLogger) sendToTransport(pending []AuditLogTxn, t Transport, ctx context.Context) (requeued int) {
	failed, successful, requeued := 0, 0, 0

	// removeable is a set of eventIDs that have been successfully sent to the control plane.
	// These transactions can be removed from the persisted store.
	removeable := map[string]bool{}

	for _, txn := range pending {
		var err error
		var retriable = true

		req := tailcfg.AuditLogRequest{
			Action:    tailcfg.ClientAuditAction(txn.Action),
			Details:   txn.Details,
			Timestamp: txn.TimeStamp,
		}

		err, retriable = t.SendAuditLog(ctx, req)
		if err == nil {
			successful++
			removeable[txn.EventID] = true
			continue
		}

		txn.Retries++
		failed++
		if !retriable {
			removeable[txn.EventID] = true
			al.logf("failed permanently: %w", err)
			continue
		}

		// We permit a maximum number of retries for each log. All retriable
		// errors should be transient and we should be able to send the log eventually, but
		// we don't want logs to be persisted indefinitely.
		if txn.Retries < al.retryLimit {
			// enqueue the log for retry, but do not request an immediate flush.
			al.enqueue(txn, false)
			requeued++
		} else {
			al.logf("failed permanently after %d retries: %w", txn.Retries, err)
			removeable[txn.EventID] = true
		}
	}

	al.setSent(removeable)

	al.logf("requeued %d, sent %d, failed %d", requeued, successful, failed)
	return requeued
}

// stop synchronously cancels any incomplete flush operations, stops the audit logger,
// and persists any pending logs to the store. You may continue to send logs to the logger in
// the Stopped state, and they will be persisted to the store.
//
// Calling Flush and waiting on the result before calling stop is is required if you
// want to ensure that a flush is attempted before stopping the logger.
func (al *AuditLogger) stop() {
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.state == stopped {
		return
	}

	al.state = stopped
	al.transport = nil

	if al.retryCancel != nil {
		al.retryCancel()
	}

	if al.workerCancel != nil {
		al.workerCancel()
	}

	if al.flushCancel != nil {
		al.flushCancel()
	}

	if al.flushCtx != nil {
		<-al.flushCtx.Done()
		al.flushCtx = nil
	}

	err := al.appendToPersistedLocked(al.pending)
	if err != nil {
		// Continue gracefully.
		al.logf("failed to persist logs: %w", err)
	}
	c := al.persistedCountLocked()
	al.pending = []AuditLogTxn{}
	al.logf("stopped for profileID: %v persisted: %d", al.logId, c)
}

// restoreLocked restores logs from the persistent store and
// appends them to q.pending.
//
// al.mu must be held.
func (al *AuditLogger) restoreLocked() error {
	if al.logId == "" {
		return errors.New("no logId set")
	}

	key := string(al.logId)

	txns, err := al.store.Restore(key)
	if err != nil {
		// An error on restoration is not fatal.
		txns = []AuditLogTxn{}
		al.logf("failed to restore logs: %w", err)
	}
	al.pending = append(al.pending, txns...)
	al.pending = deduplicateAndSort(append(al.pending, txns...))

	al.logf("restored %d pending logs for profileId %v", len(txns), al.logId)
	return nil
}

// appendToPersistedLocked persists logs to the store that are
// not already present in the store.
//
// al.mu must be held.
func (al *AuditLogger) appendToPersistedLocked(txns []AuditLogTxn) error {
	if len(txns) == 0 {
		return nil
	}

	if al.logId == "" {
		return errors.New("no logId set")
	}

	key := string(al.logId)
	persisted, _ := al.store.Restore(key)
	txnsOut := append(persisted, txns...)
	txnsOut = deduplicateAndSort(txnsOut)

	return al.store.Persist(key, txnsOut)
}

// persistedCountLocked returns the number of logs persisted to the store.
// This is best effort only and may return 0 for incorrectly configured
// al.logId.
//
// al.mu must be held
func (al *AuditLogger) persistedCountLocked() int {
	key := string(al.logId)
	persisted, _ := al.store.Restore(key)
	return len(persisted)
}

func (al *AuditLogger) setSent(ids map[string]bool) {
	al.mu.Lock()
	defer al.mu.Unlock()

	key := string(al.logId)
	persisted, _ := al.store.Restore(key)
	unsent := []AuditLogTxn{}
	for _, txn := range persisted {
		if _, ok := ids[txn.EventID]; !ok {
			unsent = append(unsent, txn)
		}
	}
	al.store.Persist(key, unsent)
}

func deduplicateAndSort(txns []AuditLogTxn) []AuditLogTxn {
	seen := make(map[string]struct{})
	deduped := []AuditLogTxn{}
	for _, txn := range txns {
		if _, ok := seen[txn.EventID]; !ok {
			deduped = append(deduped, txn)
			seen[txn.EventID] = struct{}{}
		}
	}
	// Sort logs by timestamp - oldest to newest. This will put the oldest logs at
	// the front of the queue.
	sort.Slice(deduped, func(i, j int) bool {
		return txns[i].TimeStamp.Before(txns[j].TimeStamp)
	})
	return deduped
}

func (al *AuditLogger) enqueue(txn AuditLogTxn, flush bool) (<-chan FlushResult, error) {
	al.mu.Lock()

	result := make(chan FlushResult, 1)
	al.pending = append(al.pending, txn)
	al.appendToPersistedLocked([]AuditLogTxn{txn})

	if al.state == stopped {
		result <- FlushResult(len(al.pending))
		al.mu.Unlock()
		return result, nil
	}

	timeout := al.timeout
	transport := al.transport
	al.mu.Unlock()
	if !flush {
		return nil, nil
	}

	return al.Flush(timeout, transport), nil

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
func (s *StateStore) Persist(key string, txns []AuditLogTxn) error {
	// Sort logs by timestamp - oldest to newest
	sort.Slice(txns, func(i, j int) bool {
		return txns[i].TimeStamp.Before(txns[j].TimeStamp)
	})

	data, err := json.Marshal(txns)
	if err != nil {
		return err
	}

	k := ipn.StateKey(key)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.store.WriteState(k, data)

	return nil
}

// Restore retrieves the logs from an ipn.StateStore.
func (s *StateStore) Restore(key string) ([]AuditLogTxn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := ipn.StateKey(key)
	data, err := s.store.ReadState(k)

	switch {
	case errors.Is(err, ipn.ErrStateNotExist):
		return []AuditLogTxn{}, nil
	case err != nil:
		return nil, err
	}

	var txns []AuditLogTxn
	if err := json.Unmarshal(data, &txns); err != nil {
		return nil, err
	}
	return txns, nil
}
