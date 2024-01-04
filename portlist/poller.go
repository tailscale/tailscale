// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file contains the code related to the Poller type and its methods.
// The hot loop to keep efficient is Poller.Run.

package portlist

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"time"

	"tailscale.com/envknob"
)

var (
	newOSImpl            func(includeLocalhost bool) osImpl // if non-nil, constructs a new osImpl.
	pollInterval         = 5 * time.Second                  // default; changed by some OS-specific init funcs
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

	// os, if non-nil, is an OS-specific implementation of the portlist getting
	// code. When non-nil, it's responsible for getting the complete list of
	// cached ports complete with the process name. That is, when set,
	// addProcesses is not used.
	// A nil values means we don't have code for getting the list on the current
	// operating system.
	os       osImpl
	initOnce sync.Once // guards init of os
	initErr  error

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

func (p *Poller) setPrev(pl List) {
	// Make a copy, as the pass in pl slice aliases pl.scratch and we don't want
	// that to except to the caller.
	p.prev = slices.Clone(pl)
}

// init initializes the Poller by ensuring it has an underlying
// OS implementation and is not turned off by envknob.
func (p *Poller) init() {
	switch {
	case debugDisablePortlist():
		p.initErr = errors.New("portlist disabled by envknob")
	case newOSImpl == nil:
		p.initErr = errors.New("portlist poller not implemented on " + runtime.GOOS)
	default:
		p.os = newOSImpl(p.IncludeLocalhost)
	}
}

// Close closes the Poller.
func (p *Poller) Close() error {
	if p.initErr != nil {
		return p.initErr
	}
	if p.os == nil {
		return nil
	}
	return p.os.Close()
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

func (p *Poller) getList() (List, error) {
	var err error
	p.scratch, err = p.os.AppendListeningPorts(p.scratch[:0])
	return p.scratch, err
}
