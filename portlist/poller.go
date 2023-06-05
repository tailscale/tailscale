// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file contains the code related to the Poller type and its methods.
// The hot loop to keep efficient is Poller.Run.

package portlist

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"golang.org/x/exp/slices"
	"tailscale.com/envknob"
)

var (
	pollInterval         = 5 * time.Second // default; changed by some OS-specific init funcs
	debugDisablePortlist = envknob.RegisterBool("TS_DEBUG_DISABLE_PORTLIST")
)

// PollInterval is the recommended OS-specific interval
// to wait between *Poller.Poll method calls.
func PollInterval() time.Duration {
	return pollInterval
}

// Poller scans the systems for listening ports periodically and sends
// the results to C.
type Poller struct {
	// IncludeLocalhost controls whether services bound to localhost are included.
	//
	// This field should only be changed before calling Run.
	IncludeLocalhost bool

	c chan List // unbuffered

	// os, if non-nil, is an OS-specific implementation of the portlist getting
	// code. When non-nil, it's responsible for getting the complete list of
	// cached ports complete with the process name. That is, when set,
	// addProcesses is not used.
	// A nil values means we don't have code for getting the list on the current
	// operating system.
	os       osImpl
	initOnce sync.Once // guards init of os
	initErr  error

	// closeCtx is the context that's canceled on Close.
	closeCtx       context.Context
	closeCtxCancel context.CancelFunc

	runDone chan struct{} // closed when Run completes

	// scatch is memory for Poller.getList to reuse between calls.
	scratch []Port

	prev List // most recent data, not aliasing scratch
}

// osImpl is the OS-specific implementation of getting the open listening ports.
type osImpl interface {
	Close() error

	// AppendListeningPorts appends to base (which must have length 0 but
	// optional capacity) the list of listening ports. The Port struct should be
	// populated as completely as possible. Another pass will not add anything
	// to it.
	//
	// The appended ports should be in a sorted (or at least stable) order so
	// the caller can cheaply detect when there are no changes.
	AppendListeningPorts(base []Port) ([]Port, error)
}

// newOSImpl, if non-nil, constructs a new osImpl.
var newOSImpl func(includeLocalhost bool) osImpl

var (
	errUnimplemented = errors.New("portlist poller not implemented on " + runtime.GOOS)
	errDisabled      = errors.New("portlist disabled by envknob")
)

// NewPoller returns a new portlist Poller. It returns an error
// if the portlist couldn't be obtained.
func NewPoller() (*Poller, error) {
	p := &Poller{
		c:       make(chan List),
		runDone: make(chan struct{}),
	}
	p.initOnce.Do(p.init)
	if p.initErr != nil {
		return nil, p.initErr
	}
	p.closeCtx, p.closeCtxCancel = context.WithCancel(context.Background())
	// Do one initial poll synchronously so we can return an error
	// early.
	if pl, err := p.getList(); err != nil {
		return nil, err
	} else {
		p.setPrev(pl)
	}
	return p, nil
}

func (p *Poller) setPrev(pl List) {
	// Make a copy, as the pass in pl slice aliases pl.scratch and we don't want
	// that to except to the caller.
	p.prev = slices.Clone(pl)
}

// init initializes the Poller by ensuring it has an underlying
// OS implementation and is not turned off by envknob.
func (p *Poller) init() {
	if debugDisablePortlist() {
		p.initErr = errDisabled
		return
	}
	if newOSImpl == nil {
		p.initErr = errUnimplemented
		return
	}
	p.os = newOSImpl(p.IncludeLocalhost)
}

// Updates return the channel that receives port list updates.
//
// The channel is closed when the Poller is closed.
func (p *Poller) Updates() <-chan List { return p.c }

// Close closes the Poller.
func (p *Poller) Close() error {
	if p.initErr != nil {
		return p.initErr
	}
	if p.os == nil {
		return nil
	}
	if p.closeCtxCancel != nil {
		p.closeCtxCancel()
		<-p.runDone
	}
	return p.os.Close()
}

// send sends pl to p.c and returns whether it was successfully sent.
func (p *Poller) send(ctx context.Context, pl List) (sent bool, err error) {
	select {
	case p.c <- pl:
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	case <-p.closeCtx.Done():
		return false, nil
	}
}

// Poll returns the list of listening ports, if changed from
// a previous call as indicated by the changed result.
func (p *Poller) Poll() (ports []Port, changed bool, err error) {
	p.initOnce.Do(p.init)
	if p.initErr != nil {
		return nil, false, fmt.Errorf("error initializing poller: %w", p.initErr)
	}
	pl, err := p.getList()
	if err != nil {
		return nil, false, err
	}
	if pl.equal(p.prev) {
		return nil, false, nil
	}
	p.setPrev(pl)
	return p.prev, true, nil
}

// Run runs the Poller periodically until either the context
// is done, or the Close is called.
//
// Run may only be called once.
func (p *Poller) Run(ctx context.Context) error {
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	return p.runWithTickChan(ctx, tick.C)
}

func (p *Poller) runWithTickChan(ctx context.Context, tickChan <-chan time.Time) error {
	defer close(p.runDone)
	defer close(p.c)

	// Send out the pre-generated initial value.
	if sent, err := p.send(ctx, p.prev); !sent {
		return err
	}

	for {
		select {
		case <-tickChan:
			pl, err := p.getList()
			if err != nil {
				return err
			}
			if pl.equal(p.prev) {
				continue
			}
			p.setPrev(pl)
			if sent, err := p.send(ctx, p.prev); !sent {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-p.closeCtx.Done():
			return nil
		}
	}
}

func (p *Poller) getList() (List, error) {
	// TODO(marwan): this method does not
	// need to do any init logic. Update tests
	// once async API is removed.
	p.initOnce.Do(p.init)
	if p.initErr == errDisabled {
		return nil, nil
	}
	var err error
	p.scratch, err = p.os.AppendListeningPorts(p.scratch[:0])
	return p.scratch, err
}
