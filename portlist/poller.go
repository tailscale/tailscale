// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file contains the code related to the Poller type and its methods.
// The hot loop to keep efficient is Poller.Run.

package portlist

import (
	"context"
	"errors"
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

	c chan Update // unbuffered

	// os, if non-nil, is an OS-specific implementation of the portlist getting
	// code. When non-nil, it's responsible for getting the complete list of
	// cached ports complete with the process name. That is, when set,
	// addProcesses is not used.
	// A nil values means we don't have code for getting the list on the current
	// operating system.
	os     osImpl
	osOnce sync.Once // guards init of os

	// closeCtx is the context that's canceled on Close.
	closeCtx       context.Context
	closeCtxCancel context.CancelFunc

	runDone chan struct{} // closed when Run completes

	// scatch is memory for Poller.getList to reuse between calls.
	scratch []Port

	prev List // most recent data, not aliasing scratch
}

// Update is sent by Poller to indicate
// an update has been made to the machine's
// open ports. Receiver of this struct must
// check the Err() method before calling List().
type Update struct {
	list List
	err  error
}

func (u *Update) Err() error {
	return u.err
}

func (u *Update) List() List {
	return u.list
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

func (p *Poller) initOSField() {
	if newOSImpl != nil {
		p.os = newOSImpl(p.IncludeLocalhost)
	}
}

// Updates return the channel that receives port list updates.
//
// The channel is closed when the Poller is closed.
func (p *Poller) Updates() <-chan Update { return p.c }

// Close closes the Poller.
// Run will return with a nil error.
func (p *Poller) Close() error {
	// Skip if uninitialized.
	if p.os == nil {
		return nil
	}
	p.closeCtxCancel()
	<-p.runDone
	if p.os != nil {
		p.os.Close()
	}
	return nil
}

// send sends pl to p.c and returns whether it was successfully sent.
func (p *Poller) send(ctx context.Context, pl List, listErr error) (sent bool) {
	select {
	case p.c <- Update{list: pl, err: listErr}:
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
	if debugDisablePortlist() {
		return nil, errors.New("portlist disabled by envknob")
	}
	if p.os != nil {
		return nil, errors.New("method called more than once")
	}
	p.initOSField()
	if p.os == nil {
		return nil, errUnimplemented
	}

	p.c = make(chan Update)
	p.runDone = make(chan struct{})
	p.closeCtx, p.closeCtxCancel = context.WithCancel(context.Background())

	// Do one initial poll synchronously so we can return an error
	// early.
	if pl, err := p.getList(); err != nil {
		return nil, err
	} else {
		p.setPrev(pl)
	}

	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	go p.runWithTickChan(ctx, tick.C)
	return p.c, nil
}

func (p *Poller) runWithTickChan(ctx context.Context, tickChan <-chan time.Time) {
	defer close(p.runDone)
	defer close(p.c)

	// Send out the pre-generated initial value.
	if sent := p.send(ctx, p.prev, nil); !sent {
		return
	}

	// Order of events:
	// 1. If the context is done, exit
	// 2. If the user called p.Close(), exit.
	// 3. If we received a tick, then get the list
	// 3B. If that error'd, send an error to the user.
	// 3C. If the context or p.Close where called in the meantime, exit.
	// 3D. If getList succeeded, skip if there are no updates.
	// 3E. If there are indeed updates, send them, or exit if 1/2 are true.
	// We check 1 & 2 in 3 places: top of the for-loop,
	// whenever we send (which is two places: sending an error, or sending a list).
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.closeCtx.Done():
			return
		case <-tickChan:
			pl, err := p.getList()
			if err != nil {
				sent := p.send(ctx, nil, err)
				if !sent {
					return
				}
				continue
			}
			if pl.equal(p.prev) {
				continue
			}
			p.setPrev(pl)
			if sent := p.send(ctx, p.prev, nil); !sent {
				return
			}
		}
	}
}

func (p *Poller) getList() (List, error) {
	var err error
	p.scratch, err = p.os.AppendListeningPorts(p.scratch[:0])
	return p.scratch, err
}
