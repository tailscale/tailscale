// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package auditlog sends auditlog events to the control plane.
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
	// Send sends an audit log to a consumer.
	// If err is non-nil, the log was not sent successfully.  Errors should be evaluated by the caller
	// to determine if the request should be retried.
	SendAuditLog(ctx context.Context, auditLog tailcfg.AuditLogRequest) error
}

// [controlclient.Auto] must implement the [Transport] interface.
var _ Transport = (*controlclient.Auto)(nil)

// LogStore provides a means for an [AuditLogger] to persist logs to disk or memory.
type LogStore interface {
	// Save saves the given data to a persistent store. Save will overwrite existing data
	// for the given key.
	Save(key ipn.ProfileID, logs []*transaction) error

	// Load retrieves the data from a persistent store. This must return
	// an empty slice if no data exists for the given key.
	Load(key ipn.ProfileID) ([]*transaction, error)
}

// Opts contains the configuration options for an [AuditLogger].
type Opts struct {
	// RetryLimit is the maximum number of attempts the logger will make to send a log before giving up.
	RetryLimit int
	// Store is the persistent store used to save logs to disk. non-nil
	Store LogStore
	// Logf is the logger used to log messages from the audit logger. non-nil
	Logf logger.Logf
}

type maybeRetryable interface {
	Retryable() bool
}

func isRetryableError(err error) bool {
	var ae maybeRetryable
	if errors.As(err, &ae) {
		return ae.Retryable()
	}
	return false
}

type backoffOpts struct {
	min, max  time.Duration
	mutiplier float64
}

// .5, 1, 2, 4, 8, 10, 10, 10, 10, 10...
var defaultBackoffOpts = backoffOpts{
	min:       time.Millisecond * 500,
	max:       10 * time.Second,
	mutiplier: 2,
}

// AuditLogger provides a queue-based mechanism for submitting audit logs to the control plane - or
// another suitable consumer. Logs are store to disk and retried until they are successfully sent,
// or until they permanently fail.
//
// Each individual profile/controlclient tuple should constuct and manage a unique [AuditLogger] instance.
type AuditLogger struct {
	logf        logger.Logf
	retryLimit  int                // the maximum number of attempts to send a log before giving up.
	flusher     chan struct{}      // channel used to signal a flush operation
	done        chan struct{}      // close to stop the worker goroutine.
	ctx         context.Context    // canceled when the logger is stopped
	ctxCancel   context.CancelFunc // cancels ctx
	backoffOpts                    // backoff settings for retry operations

	// mu protects the fields below.
	mu        sync.Mutex
	store     LogStore      // persistent storage for unsent logs
	profileID ipn.ProfileID // the profileID for the logger. Empty if SetProfileID has not been called.
	transport Transport     // nil until SetTransport is called.
}

// NewAuditLogger creates a new [AuditLogger] with the given options.
func NewAuditLogger(opts Opts) *AuditLogger {
	ctx, cancel := context.WithCancel(context.Background())

	q := &AuditLogger{
		retryLimit:  opts.RetryLimit,
		logf:        logger.WithPrefix(opts.Logf, "auditlog: "),
		store:       opts.Store,
		flusher:     make(chan struct{}, 1),
		done:        make(chan struct{}),
		ctx:         ctx,
		ctxCancel:   cancel,
		backoffOpts: defaultBackoffOpts,
	}
	q.logf("created")
	return q
}

// FlushAndStop synchronously flushes all pending logs and stops the audit logger.
// This will block until a final flush operation completes or the timeout is reached.
// If the logger is already stopped, this will return immediately.
func (al *AuditLogger) FlushAndStop(timeout time.Duration) {
	al.stop()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	al.flush(ctx)
}

// SetProfileID sets the profileID for the logger. This must be called before any logs can be enqueued.
// The profileID of a logger cannot be changed once set.
func (al *AuditLogger) SetProfileID(profileID ipn.ProfileID) error {
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.profileID != "" {
		return errors.New("profileID already set")
	}

	al.profileID = profileID
	return nil
}

// Start starts the audit logger with the given transport.
// If the logger is already started (it has a transport), this will return an error and no-op.
// If the logger is stopped, this will start the logger and begin processing logs.
func (al *AuditLogger) Start(t Transport) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.transport != nil {
		return errors.New("already started")
	}

	al.transport = t
	pending, err := al.storedCountLocked()

	go al.flushWorker(al.ctx, al.done)

	if err != nil {
		al.logf("[unexpected] failed to restore logs: %v", err)
	}

	if pending > 0 {
		al.flushAsync()
	}
	return nil
}

// Enqueue queues an audit log to be sent to the control plane (or another suitable consumer/transport).
func (al *AuditLogger) Enqueue(action tailcfg.ClientAuditAction, details string) error {
	txn := &transaction{
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
	txn.EventID = fmt.Sprint(txn.TimeStamp, hex.EncodeToString(bytes))
	return al.enqueue(txn)
}

// flushAsync requests an asynchronous flush.
// It is a no-op if a flush is already pending.
func (al *AuditLogger) flushAsync() {
	select {
	case al.flusher <- struct{}{}:
	default:
	}
}

func (al *AuditLogger) flushWorker(ctx context.Context, done chan struct{}) {
	defer close(done)

	var retryDelay time.Duration
	retry := time.NewTimer(0)
	retry.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-al.flusher:
			err := al.flush(ctx)
			switch {
			case errors.Is(err, context.Canceled):
				// The logger was stopped, no need to retry.
				return
			case err != nil:
				retryDelay = max(al.backoffOpts.min, min(retryDelay*time.Duration(al.backoffOpts.mutiplier), al.backoffOpts.max))
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

// flush attemps to send all pending logs to the control plane.
// al.mu must not be held.
func (al *AuditLogger) flush(ctx context.Context) error {
	al.mu.Lock()
	pending, err := al.store.Load(al.profileID)
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
// al.mu must be not be held.
func (al *AuditLogger) sendToTransport(ctx context.Context, pending []*transaction, t Transport) (complete []*transaction, unsent []*transaction) {
	for i, txn := range pending {
		req := tailcfg.AuditLogRequest{
			Action:    tailcfg.ClientAuditAction(txn.Action),
			Details:   txn.Details,
			Timestamp: txn.TimeStamp,
		}

		err := t.SendAuditLog(ctx, req)
		if err == nil {
			complete = append(complete, txn)
			continue
		}

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			// Context cancellations are, by definition, retriable errors.
			unsent = append(unsent, pending[i:]...)
			return complete, unsent
		}

		txn.Retries++
		if !isRetryableError(err) {
			complete = append(complete, txn)
			al.logf("failed permanently: %v", err)
			continue
		}

		// We permit a maximum number of retries for each log. All retriable
		// errors should be transient and we should be able to send the log eventually, but
		// we don't want logs to be persisted indefinitely.
		if txn.Retries < al.retryLimit {
			unsent = append(unsent, txn)
		} else {
			al.logf("failed permanently after %d retries: %v", txn.Retries, err)
			complete = append(complete, txn)
		}
	}

	return complete, unsent
}

func (al *AuditLogger) stop() {
	al.mu.Lock()
	t := al.transport
	al.mu.Unlock()

	if t == nil {
		// No transport means no worker goroutine.
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
// al.mu must be held.
func (al *AuditLogger) appendToStoreLocked(txns []*transaction) error {
	if len(txns) == 0 {
		return nil
	}

	if al.profileID == "" {
		return errors.New("no logId set")
	}

	persisted, err := al.store.Load(al.profileID)
	if err != nil {
		al.logf("[unexpected] append failed to restore logs: %v", err)
	}

	// The order is important here.  We want the latest transactions first, which will
	// ensure when we dedup, the new transactions are seen and the older transactions
	// are discarded.
	txnsOut := append(txns, persisted...)
	txnsOut = deduplicateAndSort(txnsOut)

	return al.store.Save(al.profileID, txnsOut)
}

// storedCountLocked returns the number of logs persisted to the store.
// al.mu must be held
func (al *AuditLogger) storedCountLocked() (int, error) {
	persisted, err := al.store.Load(al.profileID)
	return len(persisted), err
}

// markTransactionsDone removes logs from the store that are complete (sent or failed permanently).
// al.mu must not be held.
func (al *AuditLogger) markTransactionsDone(sent []*transaction) {
	al.mu.Lock()
	defer al.mu.Unlock()

	ids := set.Set[string]{}
	for _, txn := range sent {
		ids.Add(txn.EventID)
	}

	persisted, err := al.store.Load(al.profileID)
	if err != nil {
		al.logf("[unexpected] setSent failed to restore logs: %w", err)
	}
	var unsent []*transaction
	for _, txn := range persisted {
		if !ids.Contains(txn.EventID) {
			unsent = append(unsent, txn)
		}
	}
	al.store.Save(al.profileID, unsent)
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

func (al *AuditLogger) enqueue(txn *transaction) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	err := al.appendToStoreLocked([]*transaction{txn})
	if err != nil {
		return err
	}

	// If al.transport is nil if the logger is stopped.
	if al.transport == nil {
		return errors.New("logger not started")
	}

	al.flushAsync()
	return nil
}

var _ LogStore = (*LogStateStore)(nil)

// LogStateStore is a concrete implementation of [LogStore]
// using [ipn.StateStore] as the underlying storage.
type LogStateStore struct {
	store ipn.StateStore
	logf  logger.Logf
}

// NewLogStateStore creates a new LogStateStore with the given [ipn.StateStore].
func NewLogStateStore(store ipn.StateStore, logf logger.Logf) LogStore {
	return &LogStateStore{
		store: store,
		logf:  logf,
	}
}

func (s *LogStateStore) generateKey(key ipn.ProfileID) string {
	return "auditlog-" + string(key)
}

// Save saves the given logs to an [ipn.StateStore]. This overwrites
// any existing entries for the given key.
func (s *LogStateStore) Save(key ipn.ProfileID, txns []*transaction) error {
	if key == "" {
		return errors.New("empty key")
	}

	data, err := json.Marshal(txns)
	if err != nil {
		return err
	}

	k := ipn.StateKey(s.generateKey(key))

	s.store.WriteState(k, data)

	return nil
}

// Load retrieves the logs from an [ipn.StateStore].
func (s *LogStateStore) Load(key ipn.ProfileID) ([]*transaction, error) {
	if key == "" {
		return nil, errors.New("empty key")
	}

	k := ipn.StateKey(s.generateKey(key))
	data, err := s.store.ReadState(k)

	switch {
	case errors.Is(err, ipn.ErrStateNotExist):
		return []*transaction{}, nil
	case err != nil:
		return nil, err
	}

	var txns []*transaction
	if err := json.Unmarshal(data, &txns); err != nil {
		return nil, err
	}
	return txns, nil
}
