// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package auditlog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/lazy"
	"tailscale.com/types/logger"
)

// featureName is the name of the feature implemented by this package.
// It is also the [extension] name and the log prefix.
const featureName = "auditlog"

func init() {
	feature.Register(featureName)
	ipnext.RegisterExtension(featureName, newExtension)
}

// extension is an [ipnext.Extension] managing audit logging
// on platforms that import this package.
// As of 2025-03-27, that's only Windows and macOS.
type extension struct {
	logf logger.Logf

	// store is the log store shared by all loggers.
	// It is created when the first logger is started.
	store lazy.SyncValue[LogStore]

	// mu protects all following fields.
	mu syncs.Mutex
	// logger is the current audit logger, or nil if it is not set up,
	// such as before the first control client is created, or after
	// a profile change and before the new control client is created.
	//
	// It queues, persists, and sends audit logs to the control client.
	logger *Logger
}

// newExtension is an [ipnext.NewExtensionFn] that creates a new audit log extension.
// It is registered with [ipnext.RegisterExtension] if the package is imported.
func newExtension(logf logger.Logf, _ ipnext.SafeBackend) (ipnext.Extension, error) {
	return &extension{logf: logger.WithPrefix(logf, featureName+": ")}, nil
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string {
	return featureName
}

// Init implements [ipnext.Extension] by registering callbacks and providers
// for the duration of the extension's lifetime.
func (e *extension) Init(h ipnext.Host) error {
	h.Hooks().NewControlClient.Add(e.controlClientChanged)
	h.Hooks().ProfileStateChange.Add(e.profileChanged)
	h.Hooks().AuditLoggers.Add(e.getCurrentLogger)
	return nil
}

// [controlclient.Auto] implements [Transport].
var _ Transport = (*controlclient.Auto)(nil)

// startNewLogger creates and starts a new logger for the specified profile
// using the specified [controlclient.Client] as the transport.
// The profileID may be "" if the profile has not been persisted yet.
func (e *extension) startNewLogger(cc controlclient.Client, profileID ipn.ProfileID) (*Logger, error) {
	transport, ok := cc.(Transport)
	if !ok {
		return nil, fmt.Errorf("%T cannot be used as transport", cc)
	}

	// Create a new log store if this is the first logger.
	// Otherwise, get the existing log store.
	store, err := e.store.GetErr(func() (LogStore, error) {
		return newDefaultLogStore(e.logf)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create audit log store: %w", err)
	}

	logger := NewLogger(Opts{
		Logf:       e.logf,
		RetryLimit: 32,
		Store:      store,
	})
	if err := logger.SetProfileID(profileID); err != nil {
		return nil, fmt.Errorf("set profile failed: %w", err)
	}
	if err := logger.Start(transport); err != nil {
		return nil, fmt.Errorf("start failed: %w", err)
	}
	return logger, nil
}

func (e *extension) controlClientChanged(cc controlclient.Client, profile ipn.LoginProfileView) (cleanup func()) {
	logger, err := e.startNewLogger(cc, profile.ID())
	e.mu.Lock()
	e.logger = logger // nil on error
	e.mu.Unlock()
	if err != nil {
		// If we fail to create or start the logger, log the error
		// and return a nil cleanup function. There's nothing more
		// we can do here.
		//
		// But [extension.getCurrentLogger] returns [noCurrentLogger]
		// when the logger is nil. Since [noCurrentLogger] always
		// fails with [errNoLogger], operations that must be audited
		// but cannot will fail on platforms where the audit logger
		// is enabled (i.e., the auditlog package is imported).
		e.logf("[unexpected] %v", err)
		return nil
	}
	return func() {
		// Stop the logger when the control client shuts down.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		logger.FlushAndStop(ctx)
	}
}

func (e *extension) profileChanged(profile ipn.LoginProfileView, _ ipn.PrefsView, sameNode bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case e.logger == nil:
		// No-op if we don't have an audit logger.
	case sameNode:
		// The profile info has changed, but it represents the same node.
		// This includes the case where the login has just been completed
		// and the profile's [ipn.ProfileID] has been set for the first time.
		if err := e.logger.SetProfileID(profile.ID()); err != nil {
			e.logf("[unexpected] failed to set profile ID: %v", err)
		}
	default:
		// The profile info has changed, and it represents a different node.
		// We won't have an audit logger for the new profile until the new
		// control client is created.
		//
		// We don't expect any auditable actions to be attempted in this state.
		// But if they are, they will fail with [errNoLogger].
		e.logger = nil
	}
}

// errNoLogger is an error returned by [noCurrentLogger]. It indicates that
// the logger was unavailable when [ipnlocal.LocalBackend] requested it,
// such as when an auditable action was attempted before [LocalBackend.Start]
// was called for the first time or immediately after a profile change
// and before the new control client was created.
//
// This error is unexpected and should not occur in normal operation.
var errNoLogger = errors.New("[unexpected] no audit logger")

// noCurrentLogger is an [ipnauth.AuditLogFunc] returned by [extension.getCurrentLogger]
// when the logger is not available. It fails with [errNoLogger] on every call.
func noCurrentLogger(_ tailcfg.ClientAuditAction, _ string) error {
	return errNoLogger
}

// getCurrentLogger is an [ipnext.AuditLogProvider] registered with [ipnext.Host].
// It is called when [ipnlocal.LocalBackend] or an extension needs to audit an action.
//
// It returns a function that enqueues the audit log for the current profile,
// or [noCurrentLogger] if the logger is unavailable.
func (e *extension) getCurrentLogger() ipnauth.AuditLogFunc {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.logger == nil {
		return noCurrentLogger
	}
	return e.logger.Enqueue
}

// Shutdown implements [ipnlocal.Extension].
func (e *extension) Shutdown() error {
	return nil
}
