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

var pollInterval = 5 * time.Second // default; changed by some OS-specific init funcs

var debugDisablePortlist = envknob.RegisterBool("TS_DEBUG_DISABLE_PORTLIST")

// Poller scans the systems for listening ports periodically and sends
// the results to C.
type Poller struct {
	// IncludeLocalhost controls whether services bound to localhost are included.
	//
	// This field should only be changed before calling Run.
	IncludeLocalhost bool

	// Interval sets the polling interval for probing the underlying
	// os for port updates.
	Interval time.Duration

	c chan Update // unbuffered

	initOnce sync.Once // guards init of private fields
	initErr  error

	// os, if non-nil, is an OS-specific implementation of the portlist getting
	// code. When non-nil, it's responsible for getting the complete list of
	// cached ports complete with the process name. That is, when set,
	// addProcesses is not used.
	// A nil values means we don't have code for getting the list on the current
	// operating system.
	os osImpl

	// closeCtx is the context that's canceled on Close.
	closeCtx       context.Context
	closeCtxCancel context.CancelFunc

	runDone chan struct{} // closed when Run completes

	// scatch is memory for Poller.getList to reuse between calls.
	scratch []Port

	prev List // most recent data, not aliasing scratch
}

// Update is a container for a portlist update event.
// When Poller polls the underlying OS for an update,
// it either returns a new list of open ports,
// or an error that happened in the process.
//
// Note that it is up to the caller to act upon the error,
// such as closing the Poller. Otherwise, the Poller will continue
// to try and get a list for every interval.
type Update struct {
	List  List
	Error error
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

var errUnimplemented = errors.New("portlist poller not implemented on " + runtime.GOOS)

func (p *Poller) setPrev(pl List) {
	// Make a copy, as the pass in pl slice aliases pl.scratch and we don't want
	// that to except to the caller.
	p.prev = slices.Clone(pl)
}

// init makes sure the Poller is enabled
// and the undelrying OS implementation is working properly.
//
// An error returned from init is non-fatal and means
// that it's been administratively disabled or the underlying
// OS is not implemented.
func (p *Poller) init() error {
	if debugDisablePortlist() {
		return errors.New("portlist disabled by envknob")
	}
	if newOSImpl == nil {
		return errUnimplemented
	}
	p.os = newOSImpl(p.IncludeLocalhost)

	// Do one initial poll synchronously so we can return an error
	// early.
	if pl, err := p.getList(); err != nil {
		return err
	} else {
		p.setPrev(pl)
	}

	if p.Interval == 0 {
		p.Interval = pollInterval
	}

	p.closeCtx, p.closeCtxCancel = context.WithCancel(context.Background())
	p.c = make(chan Update)
	p.runDone = make(chan struct{})

	return nil
}

// Close closes the Poller.
// Run will return with a nil error.
func (p *Poller) Close() error {
	if p.os == nil {
		return nil
	}
	p.closeCtxCancel()
	<-p.runDone // if caller of Close never called Run, this can hang.
	if p.os != nil {
		p.os.Close()
	}
	return nil
}

// send sends pl to p.c and returns whether it was successfully sent.
func (p *Poller) send(ctx context.Context, pl List, plErr error) (sent bool) {
	select {
	case p.c <- Update{pl, plErr}:
		return true
	case <-ctx.Done():
		return false
	case <-p.closeCtx.Done():
		return false
	}
}

// Run runs the Poller periodically until either the context
// is done, or the Close is called.
//
// Run may only be called once.
func (p *Poller) Run(ctx context.Context) (chan Update, error) {
	p.initOnce.Do(func() {
		p.initErr = p.init()
	})
	if p.initErr != nil {
		return nil, fmt.Errorf("error initializing poller: %w", p.initErr)
	}
	tick := time.NewTicker(p.Interval)
	go func() {
		defer tick.Stop()
		p.runWithTickChan(ctx, tick.C)
	}()
	return p.c, nil
}

func (p *Poller) runWithTickChan(ctx context.Context, tickChan <-chan time.Time) {
	defer close(p.runDone)
	defer close(p.c)

	// Send out the pre-generated initial value.
	if sent := p.send(ctx, p.prev, nil); !sent {
		return
	}

	for {
		select {
		case <-tickChan:
			pl, err := p.getList()
			if err != nil {
				if !p.send(ctx, nil, err) {
					return
				}
				continue
			}
			if pl.equal(p.prev) {
				continue
			}
			p.setPrev(pl)
			if !p.send(ctx, p.prev, nil) {
				return
			}
		case <-ctx.Done():
			return
		case <-p.closeCtx.Done():
			return
		}
	}
}

func (p *Poller) getList() (List, error) {
	var err error
	p.scratch, err = p.os.AppendListeningPorts(p.scratch[:0])
	return p.scratch, err
}
