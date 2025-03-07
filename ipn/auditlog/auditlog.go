// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package auditlog provides a mechanism for logging audit events.
package auditlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
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
	SendAuditLog(ctx context.Context, auditLog tailcfg.AuditLogRequest) error
}

// [controlclient.Auto] must implement the [Transport] interface.
var _ Transport = (*controlclient.Auto)(nil)

// LogStore provides a means for an [Logger] to persist logs to disk or memory.
type LogStore interface {
	// Save saves the given data to a persistent store. Save will overwrite existing data
	// for the given key.
	Save(key ipn.ProfileID, logs []*transaction) error

	// Load retrieves the data from a persistent store.  Returns a nil slice and
	// no error if no data exists for the given key.
	Load(key ipn.ProfileID) ([]*transaction, error)
}

// Opts contains the configuration options for an [Logger].
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
	logf           logger.Logf
	retryLimit     int                // the maximum number of attempts to send a log before giving up.
	flusher        chan struct{}      // channel used to signal a flush operation.
	done           chan struct{}      // closed when the flush worker exits.
	ctx            context.Context    // canceled when the logger is stopped.
	ctxCancel      context.CancelFunc // cancels ctx.
	retryAttempted chan struct{}      // signaled on each retry attempt. Used for testing.
	backoffOpts                       // backoff settings for retry operations.

	// mu protects the fields below.
	mu        sync.Mutex
	store     LogStore      // persistent storage for unsent logs.
	profileID ipn.ProfileID // empty if [Logger.SetProfileID] has not been called.
	transport Transport     // nil until [Logger.Start] is called.
}

// NewLogger creates a new [Logger] with the given options.
func NewLogger(opts Opts) *Logger {
	ctx, cancel := context.WithCancel(context.Background())

	l := &Logger{
		retryLimit:     opts.RetryLimit,
		logf:           logger.WithPrefix(opts.Logf, "auditlog: "),
		store:          opts.Store,
		flusher:        make(chan struct{}, 1),
		done:           make(chan struct{}),
		retryAttempted: make(chan struct{}),
		ctx:            ctx,
		ctxCancel:      cancel,
		backoffOpts:    defaultBackoffOpts,
	}
	l.logf("created")
	return l
}

// FlushAndStop synchronously flushes all pending logs and stops the audit logger.
// This will block until a final flush operation completes or the timeout is reached.
// If the logger is already stopped, this will return immediately.
func (l *Logger) FlushAndStop(ctx context.Context) {
	l.stop()
	l.flush(ctx)
}

// SetProfileID sets the profileID for the logger. This must be called before any logs can be enqueued.
// The profileID of a logger cannot be changed once set.
func (l *Logger) SetProfileID(profileID ipn.ProfileID) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.profileID != "" {
		return errors.New("profileID already set")
	}

	l.profileID = profileID
	return nil
}

// Start starts the audit logger with the given transport.
// Returns an error if the logger is already started.
func (a *Logger) Start(t Transport) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.transport != nil {
		return errors.New("already started")
	}

	a.transport = t
	pending, err := a.storedCountLocked()
	if err != nil {
		a.logf("[unexpected] failed to restore logs: %v", err)
	}
	go a.flushWorker()
	if pending > 0 {
		a.flushAsync()
	}
	return nil
}

// ErrAuditLogStorageFailure is returned when the logger fails to persist logs to the store.
var ErrAuditLogStorageFailure = errors.New("audit log storage failure")

// Enqueue queues an audit log to be sent to the control plane (or another suitable consumer/transport).
// This will return an error if the underlying store fails to save the log or we fail to generate a unique
// eventID for the log.
func (l *Logger) Enqueue(action tailcfg.ClientAuditAction, details string) error {
	txn := &transaction{
		Action:    action,
		Details:   details,
		TimeStamp: time.Now(),
	}

	// generate a unique eventID for the log. This is used to de-duplicate logs
	// persisted to the store.
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditLogStorageFailure, err)
	}
	txn.EventID = fmt.Sprint(txn.TimeStamp, hex.EncodeToString(bytes))
	return l.enqueue(txn)
}

// flushAsync requests an asynchronous flush.
// It is a no-op if a flush is already pending.
func (l *Logger) flushAsync() {
	select {
	case l.flusher <- struct{}{}:
	default:
	}
}

func (l *Logger) flushWorker() {
	defer close(l.done)

	var retryDelay time.Duration
	retry := time.NewTimer(0)
	retry.Stop()

	for {
		select {
		case <-l.ctx.Done():
			return
		case <-l.flusher:
			err := l.flush(l.ctx)
			switch {
			case errors.Is(err, context.Canceled):
				// The logger was stopped, no need to retry.
				return
			case err != nil:
				retryDelay = max(l.backoffOpts.min, min(retryDelay*time.Duration(l.backoffOpts.multiplier), l.backoffOpts.max))
				l.logf("retrying after %v, %v", retryDelay, err)
				retry.Reset(retryDelay)
			default:
				retryDelay = 0
				retry.Stop()
			}
		case <-retry.C:
			l.flushAsync()
			l.retryAttempted <- struct{}{}
		}
	}
}

// flush attempts to send all pending logs to the control plane.
// a.mu must not be held.
func (l *Logger) flush(ctx context.Context) error {
	l.mu.Lock()
	pending, err := l.store.Load(l.profileID)
	t := l.transport
	l.mu.Unlock()

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

	complete, unsent := l.sendToTransport(ctx, pending, t)
	l.markTransactionsDone(complete)

	l.mu.Lock()
	defer l.mu.Unlock()
	if err = l.appendToStoreLocked(unsent); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditLogStorageFailure, err)
	}

	if len(unsent) != 0 {
		return fmt.Errorf("failed to send %d logs", len(unsent))
	}

	if len(complete) != 0 {
		l.logf("complete %d audit log transactions", len(complete))
	}
	return nil
}

// sendToTransport sends all pending logs to the control plane. Returns a pair of slices
// containing the logs that were successfully sent (or failed permanently) and those that were not.
//
// This may require multiple round trips to the control plane and can be a long running transaction.
func (l *Logger) sendToTransport(ctx context.Context, pending []*transaction, t Transport) (complete []*transaction, unsent []*transaction) {
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
			case IsRetryableError(err) && txn.Retries+1 < l.retryLimit:
				// We permit a maximum number of retries for each log. All retriable
				// errors should be transient and we should be able to send the log eventually, but
				// we don't want logs to be persisted indefinitely.
				txn.Retries++
				unsent = append(unsent, txn)
			default:
				complete = append(complete, txn)
				l.logf("failed permanently: %v", err)
			}
		} else {
			// No error - we're done.
			complete = append(complete, txn)
		}
	}

	return complete, unsent
}

func (l *Logger) stop() {
	l.mu.Lock()
	t := l.transport
	l.mu.Unlock()

	if t == nil {
		// No transport means no worker goroutine and done will not be
		// closed if we cancel the context.
		return
	}

	l.ctxCancel()
	<-l.done
	l.logf("stopped for profileID: %v", l.profileID)
}

// appendToStoreLocked persists logs to the store.  This will deduplicate
// logs so it is safe to call this with the same logs multiple time, to
// requeue failed transactions for example.
//
// a.mu must be held.
func (l *Logger) appendToStoreLocked(txns []*transaction) error {
	if len(txns) == 0 {
		return nil
	}

	if l.profileID == "" {
		return errors.New("no logId set")
	}

	persisted, err := l.store.Load(l.profileID)
	if err != nil {
		l.logf("[unexpected] append failed to restore logs: %v", err)
	}

	// The order is important here.  We want the latest transactions first, which will
	// ensure when we dedup, the new transactions are seen and the older transactions
	// are discarded.
	txnsOut := append(txns, persisted...)
	txnsOut = deduplicateAndSort(txnsOut)

	return l.store.Save(l.profileID, txnsOut)
}

// storedCountLocked returns the number of logs persisted to the store.
// a.mu must be held.
func (l *Logger) storedCountLocked() (int, error) {
	persisted, err := l.store.Load(l.profileID)
	return len(persisted), err
}

// markTransactionsDone removes logs from the store that are complete (sent or failed permanently).
// a.mu must not be held.
func (l *Logger) markTransactionsDone(sent []*transaction) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ids := set.Set[string]{}
	for _, txn := range sent {
		ids.Add(txn.EventID)
	}

	persisted, err := l.store.Load(l.profileID)
	if err != nil {
		l.logf("[unexpected] markTransactionsDone failed to restore logs: %v", err)
	}
	var unsent []*transaction
	for _, txn := range persisted {
		if !ids.Contains(txn.EventID) {
			unsent = append(unsent, txn)
		}
	}
	l.store.Save(l.profileID, unsent)
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

func (l *Logger) enqueue(txn *transaction) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.appendToStoreLocked([]*transaction{txn}); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditLogStorageFailure, err)
	}

	// If a.transport is nil if the logger is stopped.
	if l.transport != nil {
		l.flushAsync()
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
func (s *logStateStore) Save(key ipn.ProfileID, txns []*transaction) error {
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
func (s *logStateStore) Load(key ipn.ProfileID) ([]*transaction, error) {
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
