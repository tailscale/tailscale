// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailssh

import (
	"sync"
	"time"
)

// sshContext is the context.Context implementation we use for SSH
// that adds a CloseWithError method. Otherwise it's just a normalish
// Context.
type sshContext struct {
	mu     sync.Mutex
	closed bool
	done   chan struct{}
	err    error
}

func newSSHContext() *sshContext {
	return &sshContext{done: make(chan struct{})}
}

func (ctx *sshContext) CloseWithError(err error) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.closed {
		return
	}
	ctx.closed = true
	ctx.err = err
	close(ctx.done)
}

func (ctx *sshContext) Err() error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.err
}

func (ctx *sshContext) Done() <-chan struct{}                   { return ctx.done }
func (ctx *sshContext) Deadline() (deadline time.Time, ok bool) { return }
func (ctx *sshContext) Value(any) any                           { return nil }

// userVisibleError is a wrapper around an error that implements
// SSHTerminationError, so msg is written to their session.
type userVisibleError struct {
	msg string
	error
}

func (ue userVisibleError) SSHTerminationMessage() string { return ue.msg }

// SSHTerminationError is implemented by errors that terminate an SSH
// session and should be written to user's sessions.
type SSHTerminationError interface {
	error
	SSHTerminationMessage() string
}
