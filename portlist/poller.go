// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains the code related to the Poller type and its methods.
// The hot loop to keep efficient is Poller.Run.

package portlist

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/version"
)

var debugDisablePortlist = envknob.RegisterBool("TS_DEBUG_DISABLE_PORTLIST")

// Poller scans the systems for listening ports periodically and sends
// the results to C.
type Poller struct {
	c chan List // unbuffered

	// os, if non-nil, is an OS-specific implementation of the portlist getting
	// code. When non-nil, it's responsible for getting the complete list of
	// cached ports complete with the process name. That is, when set,
	// addProcesses is not used.
	//
	// This is part of a multi-step migration (starting 2022-10-22) to move to
	// using osImpl for all of Linux, macOS (unsandboxed), and Windows. But
	// during the transition period, we support this being nil.
	// TODO(bradfitz): finish that migration.
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
var newOSImpl func() osImpl

// NewPoller returns a new portlist Poller. It returns an error
// if the portlist couldn't be obtained.
func NewPoller() (*Poller, error) {
	if version.OS() == "iOS" {
		return nil, errors.New("not available on iOS")
	}
	if debugDisablePortlist() {
		return nil, errors.New("portlist disabled by envknob")
	}
	p := &Poller{
		c:       make(chan List),
		runDone: make(chan struct{}),
	}
	p.closeCtx, p.closeCtxCancel = context.WithCancel(context.Background())
	p.osOnce.Do(p.initOSField)

	// Do one initial poll synchronously so we can return an error
	// early.
	var err error
	p.prev, err = p.getList()
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Poller) initOSField() {
	if newOSImpl != nil {
		p.os = newOSImpl()
	}
}

// Updates return the channel that receives port list updates.
//
// The channel is closed when the Poller is closed.
func (p *Poller) Updates() <-chan List { return p.c }

// Close closes the Poller.
// Run will return with a nil error.
func (p *Poller) Close() error {
	p.closeCtxCancel()
	<-p.runDone
	if p.os != nil {
		p.os.Close()
	}
	return nil
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

// Run runs the Poller periodically until either the context
// is done, or the Close is called.
//
// Run may only be called once.
func (p *Poller) Run(ctx context.Context) error {
	defer close(p.runDone)
	defer close(p.c)

	tick := time.NewTicker(pollInterval)
	defer tick.Stop()

	// Send out the pre-generated initial value.
	if sent, err := p.send(ctx, p.prev); !sent {
		return err
	}

	for {
		select {
		case <-tick.C:
			pl, err := p.getList()
			if err != nil {
				return err
			}
			if pl.equal(p.prev) {
				continue
			}
			// New value. Make a copy, as pl might alias pl.scratch
			// and prev must not.
			p.prev = append([]Port(nil), pl...)
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
	if debugDisablePortlist() {
		return nil, nil
	}
	p.osOnce.Do(p.initOSField)
	var err error
	if p.os != nil {
		p.scratch, err = p.os.AppendListeningPorts(p.scratch[:0])
		return p.scratch, err
	}

	// Old path for OSes that don't have osImpl yet.
	// TODO(bradfitz): delete these when macOS and Windows are converted.
	p.scratch, err = appendListeningPorts(p.scratch[:0])
	if err != nil {
		return nil, fmt.Errorf("listPorts: %s", err)
	}
	pl := sortAndDedup(p.scratch)
	if pl.equal(p.prev) {
		// Nothing changed, skip inode lookup
		return p.prev, nil
	}
	pl, err = addProcesses(pl)
	if err != nil {
		return nil, fmt.Errorf("addProcesses: %s", err)
	}
	return pl, nil
}
