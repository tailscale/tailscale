// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package auditlog provides a mechanism for logging audit events.
package auditlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/rands"
	"tailscale.com/util/set"
)

// transaction represents an audit log that has not yet been sent to the control plane.
type transaction struct {
	// EventID is the unique identifier for the event being logged.
	// This is used on the client side only and is not sent to control.
	EventID string `json:",omitempty"`
	// Retries is the number of times the logger has attempted to send this log.
	// This is used on the client side only and is not sent to control.
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
	// SendAuditLog sends an audit log to a consumer of audit logs.
	// Errors should be checked with [IsRetryableError] for retryability.
	SendAuditLog(context.Context, tailcfg.AuditLogRequest) error
}

// LogStore provides a means for a [Logger] to persist logs to disk or memory.
type LogStore interface {
	// Save saves the given data to a persistent store. Save will overwrite existing data
	// for the given key.
	save(key ipn.ProfileID, txns []*transaction) error

	// Load retrieves the data from a persistent store.  Returns a nil slice and
	// no error if no data exists for the given key.
	load(key ipn.ProfileID) ([]*transaction, error)
}

// Opts contains the configuration options for a [Logger].
type Opts struct {
	// RetryLimit is the maximum number of attempts the logger will make to send a log before giving up.
	RetryLimit int
	// Store is the persistent store used to save logs to disk. Must be non-nil.
	Store LogStore
	// Logf is the logger used to log messages from the audit logger. Must be non-nil.
	Logf logger.Logf
}

// IsRetryableError returns true if the given error is retryable
// See [controlclient.apiResponseError].  Potentially retryable errors implement the Retryable() method.
func IsRetryableError(err error) bool {
	var retryable interface{ Retryable() bool }
	return errors.As(err, &retryable) && retryable.Retryable()
}

type backoffOpts struct {
	min, max   time.Duration
	multiplier float64
}

// .5, 1, 2, 4, 8, 10, 10, 10, 10, 10...
var defaultBackoffOpts = backoffOpts{
	min:        time.Millisecond * 500,
	max:        10 * time.Second,
	multiplier: 2,
}

// Logger provides a queue-based mechanism for submitting audit logs to the control plane - or
// another suitable consumer. Logs are stored to disk and retried until they are successfully sent,
// or until they permanently fail.
//
// Each individual profile/controlclient tuple should construct and manage a unique [Logger] instance.
type Logger struct {
	logf        logger.Logf
	retryLimit  int                // the maximum number of attempts to send a log before giving up.
	flusher     chan struct{}      // channel used to signal a flush operation.
	done        chan struct{}      // closed when the flush worker exits.
	ctx         context.Context    // canceled when the logger is stopped.
	ctxCancel   context.CancelFunc // cancels ctx.
	backoffOpts                    // backoff settings for retry operations.

	// mu protects the fields below.
	mu        sync.Mutex
	store     LogStore      // persistent storage for unsent logs.
	profileID ipn.ProfileID // empty if [Logger.SetProfileID] has not been called.
	transport Transport     // nil until [Logger.Start] is called.
}

// NewLogger creates a new [Logger] with the given options.
func NewLogger(opts Opts) *Logger {
	ctx, cancel := context.WithCancel(context.Background())

	al := &Logger{
		retryLimit:  opts.RetryLimit,
		logf:        opts.Logf,
		store:       opts.Store,
		flusher:     make(chan struct{}, 1),
		done:        make(chan struct{}),
		ctx:         ctx,
		ctxCancel:   cancel,
		backoffOpts: defaultBackoffOpts,
	}
	al.logf("created")
	return al
}

// FlushAndStop synchronously flushes all pending logs and stops the audit logger.
// This will block until a final flush operation completes or context is done.
// If the logger is already stopped, this will return immediately.  All unsent
// logs will be persisted to the store.
func (al *Logger) FlushAndStop(ctx context.Context) {
	al.stop()
	al.flush(ctx)
}

// SetProfileID sets the profileID for the logger. This must be called before any logs can be enqueued.
// The profileID of a logger cannot be changed once set.
func (al *Logger) SetProfileID(profileID ipn.ProfileID) error {
	al.mu.Lock()
	defer al.mu.Unlock()
	// It's not an error to call SetProfileID more than once
	// with the same [ipn.ProfileID].
	if al.profileID != "" && al.profileID != profileID {
		return errors.New("profileID cannot be changed once set")
	}

	al.profileID = profileID
	return nil
}

// Start starts the audit logger with the given transport.
// It returns an error if the logger is already started.
func (al *Logger) Start(t Transport) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.transport != nil {
		return errors.New("already started")
	}

	al.transport = t
	pending, err := al.storedCountLocked()
	if err != nil {
		al.logf("[unexpected] failed to restore logs: %v", err)
	}
	go al.flushWorker()
	if pending > 0 {
		al.flushAsync()
	}
	return nil
}

// ErrAuditLogStorageFailure is returned when the logger fails to persist logs to the store.
var ErrAuditLogStorageFailure = errors.New("audit log storage failure")

// Enqueue queues an audit log to be sent to the control plane (or another suitable consumer/transport).
// This will return an error if the underlying store fails to save the log or we fail to generate a unique
// eventID for the log.
func (al *Logger) Enqueue(action tailcfg.ClientAuditAction, details string) error {
	txn := &transaction{
		Action:    action,
		Details:   details,
		TimeStamp: time.Now(),
	}
	// Generate a suitably random eventID for the transaction.
	txn.EventID = fmt.Sprint(txn.TimeStamp, rands.HexString(16))
	return al.enqueue(txn)
}

// flushAsync requests an asynchronous flush.
// It is a no-op if a flush is already pending.
func (al *Logger) flushAsync() {
	select {
	case al.flusher <- struct{}{}:
	default:
	}
}

func (al *Logger) flushWorker() {
	defer close(al.done)

	var retryDelay time.Duration
	retry := time.NewTimer(0)
	retry.Stop()

	for {
		select {
		case <-al.ctx.Done():
			return
		case <-al.flusher:
			err := al.flush(al.ctx)
			switch {
			case errors.Is(err, context.Canceled):
				// The logger was stopped, no need to retry.
				return
			case err != nil:
				retryDelay = max(al.backoffOpts.min, min(retryDelay*time.Duration(al.backoffOpts.multiplier), al.backoffOpts.max))
				al.logf("retrying after %v, %v", retryDelay, err)
				retry.Reset(retryDelay)
			default:
				retryDelay = 0
				retry.Stop()
			}
		case <-retry.C:
			al.flushAsync()
		}
	}
}

// flush attempts to send all pending logs to the control plane.
// l.mu must not be held.
func (al *Logger) flush(ctx context.Context) error {
	al.mu.Lock()
	pending, err := al.store.load(al.profileID)
	t := al.transport
	al.mu.Unlock()

	if err != nil {
		// This will catch nil profileIDs
		return fmt.Errorf("failed to restore pending logs: %w", err)
	}
	if len(pending) == 0 {
		return nil
	}
	if t == nil {
		return errors.New("no transport")
	}

	complete, unsent := al.sendToTransport(ctx, pending, t)
	al.markTransactionsDone(complete)

	al.mu.Lock()
	defer al.mu.Unlock()
	if err = al.appendToStoreLocked(unsent); err != nil {
		al.logf("[unexpected] failed to persist logs: %v", err)
	}

	if len(unsent) != 0 {
		return fmt.Errorf("failed to send %d logs", len(unsent))
	}

	if len(complete) != 0 {
		al.logf("complete %d audit log transactions", len(complete))
	}
	return nil
}

// sendToTransport sends all pending logs to the control plane. Returns a pair of slices
// containing the logs that were successfully sent (or failed permanently) and those that were not.
//
// This may require multiple round trips to the control plane and can be a long running transaction.
func (al *Logger) sendToTransport(ctx context.Context, pending []*transaction, t Transport) (complete []*transaction, unsent []*transaction) {
	for i, txn := range pending {
		req := tailcfg.AuditLogRequest{
			Action:    tailcfg.ClientAuditAction(txn.Action),
			Details:   txn.Details,
			Timestamp: txn.TimeStamp,
		}

		if err := t.SendAuditLog(ctx, req); err != nil {
			switch {
			case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
				// The contex is done.  All further attempts will fail.
				unsent = append(unsent, pending[i:]...)
				return complete, unsent
			case IsRetryableError(err) && txn.Retries+1 < al.retryLimit:
				// We permit a maximum number of retries for each log. All retriable
				// errors should be transient and we should be able to send the log eventually, but
				// we don't want logs to be persisted indefinitely.
				txn.Retries++
				unsent = append(unsent, txn)
			default:
				complete = append(complete, txn)
				al.logf("failed permanently: %v", err)
			}
		} else {
			// No error - we're done.
			complete = append(complete, txn)
		}
	}

	return complete, unsent
}

func (al *Logger) stop() {
	al.mu.Lock()
	t := al.transport
	al.mu.Unlock()

	if t == nil {
		// No transport means no worker goroutine and done will not be
		// closed if we cancel the context.
		return
	}

	al.ctxCancel()
	<-al.done
	al.logf("stopped for profileID: %v", al.profileID)
}

// appendToStoreLocked persists logs to the store.  This will deduplicate
// logs so it is safe to call this with the same logs multiple time, to
// requeue failed transactions for example.
//
// l.mu must be held.
func (al *Logger) appendToStoreLocked(txns []*transaction) error {
	if len(txns) == 0 {
		return nil
	}

	if al.profileID == "" {
		return errors.New("no logId set")
	}

	persisted, err := al.store.load(al.profileID)
	if err != nil {
		al.logf("[unexpected] append failed to restore logs: %v", err)
	}

	// The order is important here.  We want the latest transactions first, which will
	// ensure when we dedup, the new transactions are seen and the older transactions
	// are discarded.
	txnsOut := append(txns, persisted...)
	txnsOut = deduplicateAndSort(txnsOut)

	return al.store.save(al.profileID, txnsOut)
}

// storedCountLocked returns the number of logs persisted to the store.
// al.mu must be held.
func (al *Logger) storedCountLocked() (int, error) {
	persisted, err := al.store.load(al.profileID)
	return len(persisted), err
}

// markTransactionsDone removes logs from the store that are complete (sent or failed permanently).
// al.mu must not be held.
func (al *Logger) markTransactionsDone(sent []*transaction) {
	al.mu.Lock()
	defer al.mu.Unlock()

	ids := set.Set[string]{}
	for _, txn := range sent {
		ids.Add(txn.EventID)
	}

	persisted, err := al.store.load(al.profileID)
	if err != nil {
		al.logf("[unexpected] markTransactionsDone failed to restore logs: %v", err)
	}
	var unsent []*transaction
	for _, txn := range persisted {
		if !ids.Contains(txn.EventID) {
			unsent = append(unsent, txn)
		}
	}
	al.store.save(al.profileID, unsent)
}

// deduplicateAndSort removes duplicate logs from the given slice and sorts them by timestamp.
// The first log entry in the slice will be retained, subsequent logs with the same EventID will be discarded.
func deduplicateAndSort(txns []*transaction) []*transaction {
	seen := set.Set[string]{}
	deduped := make([]*transaction, 0, len(txns))
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

func (al *Logger) enqueue(txn *transaction) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if err := al.appendToStoreLocked([]*transaction{txn}); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditLogStorageFailure, err)
	}

	// If a.transport is nil if the logger is stopped.
	if al.transport != nil {
		al.flushAsync()
	}

	return nil
}

var _ LogStore = (*logStateStore)(nil)

// logStateStore is a concrete implementation of [LogStore]
// using [ipn.StateStore] as the underlying storage.
type logStateStore struct {
	store ipn.StateStore
}

// NewLogStore creates a new LogStateStore with the given [ipn.StateStore].
func NewLogStore(store ipn.StateStore) LogStore {
	return &logStateStore{
		store: store,
	}
}

func (s *logStateStore) generateKey(key ipn.ProfileID) string {
	return "auditlog-" + string(key)
}

// Save saves the given logs to an [ipn.StateStore]. This overwrites
// any existing entries for the given key.
func (s *logStateStore) save(key ipn.ProfileID, txns []*transaction) error {
	if key == "" {
		return errors.New("empty key")
	}

	data, err := json.Marshal(txns)
	if err != nil {
		return err
	}
	k := ipn.StateKey(s.generateKey(key))
	return s.store.WriteState(k, data)
}

// Load retrieves the logs from an [ipn.StateStore].
func (s *logStateStore) load(key ipn.ProfileID) ([]*transaction, error) {
	if key == "" {
		return nil, errors.New("empty key")
	}

	k := ipn.StateKey(s.generateKey(key))
	data, err := s.store.ReadState(k)

	switch {
	case errors.Is(err, ipn.ErrStateNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	}

	var txns []*transaction
	err = json.Unmarshal(data, &txns)
	return txns, err
}
