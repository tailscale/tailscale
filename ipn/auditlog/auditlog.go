// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package auditlog provides a reliable mechanism for logging client events to the control plane.
package auditlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sort"
	"sync"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
	"tailscale.com/version"
)

const (
	// defaultTimeout is the default timeout for a flush operation.
	defaultTimeout = time.Second * 5
)

// auditLogTxn represents an audit log that has not yet been sent to the control plane.
type auditLogTxn struct {
	// EventID is the unique identifier for the event being logged.
	EventID string `json:",omitempty"`
	// Retries is the number of times the logger has attempted to send this log.
	Retries int `json:",omitempty"`

	// Action is the action to be logged. It must correspond to a known action in the control plane.
	Action tailcfg.ClientAuditAction `json:",omitempty"`
	// Details is an opaque string specific to the action being logged. Empty strings may not
	// be valid depending on the action being logged.
	Details string `json:",omitempty"`
	// TimeStamp is the time at which the audit log was generated on the node.
	TimeStamp time.Time `json:",omitzero"`
}

// Transport provides a means for a client to send audit logs to a consumer (typically the control plane).
type Transport interface {
	// SendAuditLog sends an audit log to a consumer.
	// If err is non-nil, the log was not sent successfully.  Errors should be evaluated by the caller
	// to determine if the request should be retried.
	SendAuditLog(ctx context.Context, auditLog tailcfg.AuditLogRequest) (err error)
}

// [controlclient.Auto] must implement the [Transport] interface.
var _ Transport = (*controlclient.Auto)(nil)

// LogStore provides a means for an [AuditLogger] to persist logs to disk or memory.
type LogStore interface {
	// Save saves the given data to a persistent store. Save may discard logs if
	// the store has a fixed size limit. Save will overwrite existing data for the given key.
	Save(key ipn.ProfileID, logs []auditLogTxn) error

	// Load retrieves the data from a persistent store. This must return
	// an empty slice if no data exists for the given key.
	Load(key ipn.ProfileID) ([]auditLogTxn, error)
}

// Opts contains the configuration options for an [AuditLogger].
type Opts struct {
	// RetryLimit is the maximum number of attempts the logger will make to send a log before giving up.
	RetryLimit int
	// Store is the persistent store used to save logs to disk.
	Store LogStore
	// Logf is the logger used to log messages from the audit logger.
	Logf logger.Logf
}

type State string

// AuditLogger provides a reliable queue-based mechanism for submitting audit logs to the control plane - or
// another suitable consumer. Logs are persisted to disk and retried until they are successfully sent.
//
// Each individual profile/controlclient tuple should constuct and managed a unique [AuditLogger] instance.
type AuditLogger struct {
	logf           logger.Logf
	retryLimit     int
	timeout        time.Duration
	logID          ipn.ProfileID
	store          LogStore
	errorEvaluator func(error) bool // errorEvaluator determines whether an error returned from a [Transport] is retr

	// mu protects the fields below.
	mu              sync.Mutex
	transport       Transport          // transport used to send logs
	flusher         chan flushOp       // channel used to signal a flush operation
	flushWorkerDone chan struct{}      // signal to to stop the flush worker
	flusherStopped  chan struct{}      // signal to indicate the flush worker has stopped.  nil when the worker is not running.
	flushCancel     context.CancelFunc // cancel function for the current flush operation's context
	flushCtx        context.Context    // context for the current flush

	retryBackoff time.Duration // geometric backoff time for retry operations
}

type flushOp struct {
	timeout   time.Duration // non-zero.  the http timeout for each individual transaction
	transport Transport     // non-nil
	isRetry   bool          // force flush even if stopped
}

// NewAuditLogger creates a new AuditLogger with the given options.
func NewAuditLogger(opts Opts) *AuditLogger {
	logger := logger.WithPrefix(opts.Logf, "auditlog: ")
	q := &AuditLogger{
		retryLimit:     opts.RetryLimit,
		logf:           logger,
		timeout:        defaultTimeout,
		store:          opts.Store,
		flusher:        make(chan flushOp),
		retryBackoff:   backoffForever,
		errorEvaluator: errorEvaluator,
	}
	q.logf("created")
	return q
}

// errorEvaluator determines whether an error returned from a [Transport] is
// retriable.  This is the default implementation used by the [AuditLogger].
func errorEvaluator(err error) bool {
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, controlclient.ErrNoNodeKey) ||
		errors.Is(err, controlclient.ErrHTTPPostFailure) ||
		errors.Is(err, controlclient.ErrNoNoiseClient) {
		return true
	}

	// We're treating all HTTP errors as non-retriable here, but this could be made more sophisticated.
	// Notably, HTTP 500's are often retriable.
	// (barnstar) TODO: make this more sophisticated. See: https://github.com/tailscale/corp/issues/26811
	if errors.Is(err, controlclient.ErrHTTPFailure) {
		return false
	}

	return false
}

// FlushAndStop synchronously flushes all pending logs and stops the audit logger.
// This will block until the flush operation completes or the timeout is reached.
// If the logger is already stopped, this will return immediately.
// If the logger is in the started state, this will stop the logger and flush any pending logs and
// leave the logger in the stopped state.
func (al *AuditLogger) FlushAndStop(timeout time.Duration) {
	al.scheduleFlush(timeout, nil)
	al.stop()
}

// SetTransport starts the audit logger, resets the transport to the given value,
// restores any persisted logs and immediately flushes the queue if it
// was in the stopped state. Returns a read-only channel with a buffer
// size of one that will be sent a value indicating the number of retriable transactions
// that remain in the queue.  This will be sent immediately if the logger is in the started state.
func (al *AuditLogger) SetTransport(t Transport, logID ipn.ProfileID) {
	al.mu.Lock()
	al.transport = t
	al.logID = logID

	if al.flusherStopped != nil {
		al.mu.Unlock()
		return
	}

	timeout := al.timeout

	al.logf("started for logID: %v", al.logID)

	al.flushWorkerDone = make(chan struct{})
	al.flusherStopped = make(chan struct{})

	al.mu.Unlock()

	go al.flushWorker()
	al.scheduleFlush(timeout, t)
}

// Enqueue queues an audit log to be sent to the control plane (or another suitable consumer/transport).
//
// Returns a receive-only channel that will be sent a single value indicating the number of
// retriable transactions that remain in the queue once flushed.
func (al *AuditLogger) Enqueue(action tailcfg.ClientAuditAction, details string) error {
	// On apple platforms, we support audit logging on standalone macsys only.  The other platforms
	// utilize the keychain as their persistent store and will require a separate file-based implementation.
	if runtime.GOOS == "ios" || (runtime.GOOS == "darwin" && version.IsMacAppStore()) {
		return errors.New("audit logging is not supported on this platform")
	}

	txn := auditLogTxn{
		Action:    action,
		Details:   details,
		TimeStamp: time.Now(),
	}

	// generate a unique eventID for the log. This is used to de-duplicate logs
	// persisted to the store.
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return err
	}
	eventID := fmt.Sprintf("%d", time.Now().Unix()) + hex.EncodeToString(bytes)

	txn.EventID = eventID
	return al.enqueue(txn, true)
}

// scheduleFlush queues a flush operation for the flush worker.

// The flush operation will be cancelled after the given timeout.
// If t is nil, the loggers current transport (if any) will be used.
func (al *AuditLogger) scheduleFlush(timeout time.Duration, t Transport) {
	al.mu.Lock()
	if al.flusherStopped == nil {
		al.mu.Unlock()
		return
	}

	f := al.flusher
	if t == nil {
		t = al.transport
	}
	al.mu.Unlock()

	f <- flushOp{timeout, t, false}
}

func (al *AuditLogger) flushWorker() {
	for {
		select {
		case <-al.flushWorkerDone:
			defer close(al.flusherStopped)
			return
		case op := <-al.flusher:
			al.flush(op)
		case <-func() <-chan time.Time {
			al.mu.Lock()
			defer al.mu.Unlock()
			return time.After(al.retryBackoff)
		}():
			al.mu.Lock()
			al.logf("retrying after %v", al.retryBackoff)
			op := flushOp{timeout: al.timeout, transport: al.transport, isRetry: true}
			al.mu.Unlock()
			al.flush(op)
		}
	}

}

// flush sends all pending logs to the control plane.
//
// timeout is the maximum time we will permit for the flush operation to complete.
// result should be a 1-buffered chan that will always be sent a single value indicating
// the number of retriable transactions that remain in the queue once the flush completes.
//
// al.mu must not be held.
func (al *AuditLogger) flush(op flushOp) {
	al.mu.Lock()

	if al.flushCancel != nil {
		al.flushCancel()
	}

	// Early exit if we're stopped or have no logs to flush.
	if (al.flusherStopped == nil) || op.transport == nil || al.logID == "" {
		al.mu.Unlock()
		return
	}

	pending, err := al.store.Load(al.logID)
	if err != nil {
		al.logf("[unexpected] failed to restore pending logs: %w", err)
		al.mu.Unlock()
		return
	}

	if len(pending) == 0 {
		al.mu.Unlock()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), op.timeout)
	al.flushCancel = cancel
	al.flushCtx = ctx
	defer cancel()
	al.mu.Unlock()

	requeued := al.sendToTransport(pending, op.transport, ctx)

	al.retryIfNeeded(requeued, op.isRetry)
}

const (
	//.5, 1, 2, 4, 8, 10, 10 ,10, 10s....
	backoffMultiplier = 2
	maxBackoff        = 10 * time.Second
	minBackoff        = time.Millisecond * 500
	backoffForever    = time.Duration(math.MaxInt64)
)

func (al *AuditLogger) retryIfNeeded(requeued int, isRetry bool) {
	al.mu.Lock()
	defer al.mu.Unlock()
	// Nothing to retry, just reset the backoff timer.
	if requeued == 0 {
		al.retryBackoff = backoffForever
		return
	}

	// We're at forever or this flush was not a retry attempt, so set our
	// retry backoff to the minimum.
	if al.retryBackoff > maxBackoff || !isRetry {
		al.retryBackoff = minBackoff
	} else {
		al.retryBackoff = min(al.retryBackoff*backoffMultiplier, maxBackoff)
	}
}

// sendToTransport sends all pending logs to the control plane. Returns the number of logs that
// were requeued. Persists all pending logs to the store before returning.
//
// This may require multiple round trips to the control plane and can be a long running transaction.
// al.mu must be not be held.
func (al *AuditLogger) sendToTransport(pending []auditLogTxn, t Transport, ctx context.Context) (requeued int) {
	failed, successful, requeued := 0, 0, 0

	// removeable is a set of eventIDs that have been successfully sent to the control plane.
	// These transactions can be removed from the persisted store.
	removeable := set.Set[string]{}

	for _, txn := range pending {
		var err error

		req := tailcfg.AuditLogRequest{
			Action:    tailcfg.ClientAuditAction(txn.Action),
			Details:   txn.Details,
			Timestamp: txn.TimeStamp,
		}

		err = t.SendAuditLog(ctx, req)
		if err == nil {
			successful++
			removeable.Add(txn.EventID)
			continue
		}

		txn.Retries++
		failed++
		if !al.errorEvaluator(err) {
			removeable.Add(txn.EventID)
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
			removeable.Add(txn.EventID)
		}
	}

	al.setSent(removeable)
	return requeued
}

// stop synchronously waits for the current flushCtx to complete operations,
// stops the audit logger, stops the worker and persists any pending logs to the store.
//
// New transactions will be persisted to the store until the logger is started again.
func (al *AuditLogger) stop() {
	al.mu.Lock()

	if al.flusherStopped == nil {
		al.mu.Unlock()
		return
	}

	if al.flushCtx != nil {
		<-al.flushCtx.Done()
		al.flushCtx = nil
	}

	close(al.flushWorkerDone)
	stopped := al.flusherStopped
	al.mu.Unlock()

	<-stopped

	al.mu.Lock()
	defer al.mu.Unlock()
	al.flushWorkerDone = nil
	al.flusherStopped = nil
	al.transport = nil

	al.retryBackoff = backoffForever

	c := al.storedCountLocked()
	al.logf("stopped for profileID: %v persisted: %d", al.logID, c)
}

// appendToStoreLocked persists logs to the store.  This will deduplicate
// logs so it is safe to call this with the same logs multiple time, to
// requeue failed transactions for example.
//
// al.mu must be held.
func (al *AuditLogger) appendToStoreLocked(txns []auditLogTxn) error {
	if len(txns) == 0 {
		return nil
	}

	if al.logID == "" {
		return errors.New("no logId set")
	}

	persisted, err := al.store.Load(al.logID)
	if err != nil {
		al.logf("[unexpected] append failed to restore logs: %w", err)
	}

	txnsOut := append(persisted, txns...)
	txnsOut = deduplicateAndSort(txnsOut)

	return al.store.Save(al.logID, txnsOut)
}

// storedCountLocked returns the number of logs persisted to the store.
// This is best effort only and may return 0 for incorrectly configured
// al.logId.
//
// al.mu must be held
func (al *AuditLogger) storedCountLocked() int {
	persisted, _ := al.store.Load(al.logID)
	return len(persisted)
}

// setSent removes logs from the store that have been successfully sent to the control plane.
// al.mu must not be held.
func (al *AuditLogger) setSent(ids set.Set[string]) {
	al.mu.Lock()
	defer al.mu.Unlock()

	persisted, err := al.store.Load(al.logID)
	if err != nil {
		al.logf("[unexpected] setSent failed to restore logs: %w", err)
	}
	var unsent []auditLogTxn
	for _, txn := range persisted {
		if !ids.Contains(txn.EventID) {
			unsent = append(unsent, txn)
		}
	}
	al.store.Save(al.logID, unsent)
}

func deduplicateAndSort(txns []auditLogTxn) []auditLogTxn {
	seen := set.Set[string]{}
	deduped := make([]auditLogTxn, 0, len(txns))
	for _, txn := range txns {
		if !seen.Contains(txn.EventID) {
			deduped = append(deduped, txn)
			seen.Add(txn.EventID)
		}
	}
	// Sort logs by timestamp - oldest to newest. This will put the oldest logs at
	// the front of the queue.
	sort.Slice(deduped, func(i, j int) bool {
		return deduped[i].TimeStamp.Before(deduped[j].TimeStamp)
	})
	return deduped
}

func (al *AuditLogger) enqueue(txn auditLogTxn, flush bool) error {
	al.mu.Lock()

	err := al.appendToStoreLocked([]auditLogTxn{txn})

	// If our flushWorker is stopped or there's no transport, exit early.
	if !flush || al.flusherStopped == nil || al.transport == nil {
		al.mu.Unlock()
		return err
	}

	// ...otherwise, schedule a flush operation.
	timeout := al.timeout
	transport := al.transport
	al.mu.Unlock()
	al.scheduleFlush(timeout, transport)

	return err
}

var _ LogStore = (*LogStateStore)(nil)

// LogStateStore is a concrete implementation of LogStore
// using ipn.LogStateStore as the underlying storage.
type LogStateStore struct {
	store ipn.StateStore
	logf  logger.Logf
}

func NewLogStateStore(store ipn.StateStore, logf logger.Logf) LogStore {
	return &LogStateStore{
		store: store,
		logf:  logf,
	}
}

// generateKey generates a human-readable key for the given profileID.
func (s *LogStateStore) generateKey(key ipn.ProfileID) string {
	return "auditlog-logs-" + string(key)
}

// Save saves the given logs to an ipn.StateStore. This overwrites
// any existing entries for the given key.
func (s *LogStateStore) Save(key ipn.ProfileID, txns []auditLogTxn) error {
	data, err := json.Marshal(txns)
	if err != nil {
		return err
	}

	k := ipn.StateKey(s.generateKey(key))

	s.store.WriteState(k, data)

	return nil
}

// Load retrieves the logs from an ipn.StateStore.
func (s *LogStateStore) Load(key ipn.ProfileID) ([]auditLogTxn, error) {

	k := ipn.StateKey(s.generateKey(key))
	data, err := s.store.ReadState(k)

	switch {
	case errors.Is(err, ipn.ErrStateNotExist):
		return []auditLogTxn{}, nil
	case err != nil:
		return nil, err
	}

	var txns []auditLogTxn
	if err := json.Unmarshal(data, &txns); err != nil {
		return nil, err
	}
	return txns, nil
}
