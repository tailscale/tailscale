// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lapitest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/lazy"
	"tailscale.com/types/logger"
)

// Option is any optional configuration that can be passed to [NewServer] or [NewBackend].
type Option interface {
	apply(*options) error
}

// options is the merged result of all applied [Option]s.
type options struct {
	tb      testing.TB
	ctx     lazy.SyncValue[context.Context]
	logf    lazy.SyncValue[logger.Logf]
	sys     lazy.SyncValue[*tsd.System]
	newCC   lazy.SyncValue[NewControlFn]
	backend lazy.SyncValue[*ipnlocal.LocalBackend]
}

// newOptions returns a new [options] struct with the specified [Option]s applied.
func newOptions(tb testing.TB, opts ...Option) (*options, error) {
	options := &options{tb: tb}
	for _, opt := range opts {
		if err := opt.apply(options); err != nil {
			return nil, fmt.Errorf("lapitest: %w", err)
		}
	}
	return options, nil
}

// TB returns the owning [*testing.T] or [*testing.B].
func (o *options) TB() testing.TB {
	return o.tb
}

// Context returns the base context to be used by the server.
func (o *options) Context() context.Context {
	return o.ctx.Get(context.Background)
}

// Logf returns the [logger.Logf] to be used for logging.
func (o *options) Logf() logger.Logf {
	return o.logf.Get(func() logger.Logf { return logger.Discard })
}

// Sys returns the [tsd.System] that contains subsystems to be used
// when creating a new [ipnlocal.LocalBackend].
func (o *options) Sys() *tsd.System {
	return o.sys.Get(func() *tsd.System { return tsd.NewSystem() })
}

// Backend returns the [ipnlocal.LocalBackend] to be used by the server.
// If a backend is provided via [WithBackend], it is used as-is.
// Otherwise, a new backend is created with the the [options] in o.
func (o *options) Backend() *ipnlocal.LocalBackend {
	return o.backend.Get(func() *ipnlocal.LocalBackend { return newBackend(o) })
}

// MakeControlClient returns a new [controlclient.Client] to be used by newly
// created [ipnlocal.LocalBackend]s. It is only used if no backend is provided
// via [WithBackend].
func (o *options) MakeControlClient(opts controlclient.Options) (controlclient.Client, error) {
	newCC := o.newCC.Get(func() NewControlFn { return NewUnreachableControlClient })
	return newCC(o.tb, opts)
}

type loggingOption struct{ enableLogging bool }

// WithLogging returns an [Option] that enables or disables logging.
func WithLogging(enableLogging bool) Option {
	return loggingOption{enableLogging: enableLogging}
}

func (o loggingOption) apply(opts *options) error {
	var logf logger.Logf
	if o.enableLogging {
		logf = tstest.WhileTestRunningLogger(opts.tb)
	} else {
		logf = logger.Discard
	}
	if !opts.logf.Set(logf) {
		return errors.New("logging already configured")
	}
	return nil
}

type contextOption struct{ ctx context.Context }

// WithContext returns an [Option] that sets the base context to be used by the [Server].
func WithContext(ctx context.Context) Option {
	return contextOption{ctx: ctx}
}

func (o contextOption) apply(opts *options) error {
	if !opts.ctx.Set(o.ctx) {
		return errors.New("context already configured")
	}
	return nil
}

type sysOption struct{ sys *tsd.System }

// WithSys returns an [Option] that sets the [tsd.System] to be used
// when creating a new [ipnlocal.LocalBackend].
func WithSys(sys *tsd.System) Option {
	return sysOption{sys: sys}
}

func (o sysOption) apply(opts *options) error {
	if !opts.sys.Set(o.sys) {
		return errors.New("tsd.System already configured")
	}
	return nil
}

type backendOption struct{ backend *ipnlocal.LocalBackend }

// WithBackend returns an [Option] that configures the server to use the specified
// [ipnlocal.LocalBackend] instead of creating a new one.
// It is mutually exclusive with [WithControlClient].
func WithBackend(backend *ipnlocal.LocalBackend) Option {
	return backendOption{backend: backend}
}

func (o backendOption) apply(opts *options) error {
	if _, ok := opts.backend.Peek(); ok {
		return errors.New("backend cannot be set when control client is already set")
	}
	if !opts.backend.Set(o.backend) {
		return errors.New("backend already set")
	}
	return nil
}

// NewControlFn is any function that creates a new [controlclient.Client]
// with the specified options.
type NewControlFn func(tb testing.TB, opts controlclient.Options) (controlclient.Client, error)

// WithControlClient returns an option that specifies a function to be used
// by the [ipnlocal.LocalBackend] when creating a new [controlclient.Client].
// It is mutually exclusive with [WithBackend] and is only used if no backend
// has been provided.
func WithControlClient(newControl NewControlFn) Option {
	return newControl
}

func (fn NewControlFn) apply(opts *options) error {
	if _, ok := opts.backend.Peek(); ok {
		return errors.New("control client cannot be set when backend is already set")
	}
	if !opts.newCC.Set(fn) {
		return errors.New("control client already set")
	}
	return nil
}
